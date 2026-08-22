package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"perimeter/ent/job"
	"perimeter/internal/notifier"
	"perimeter/internal/storage"
	"perimeter/scanner/csp"
	"perimeter/scanner/ports"
	"perimeter/scanner/ssl"
)

type ScannerConfig struct {
	PortScanInterval   time.Duration
	SSLScanInterval    time.Duration
	CSPScanInterval    time.Duration
	ResolutionInterval time.Duration
	SSLEmail           string
	WorkerCount        int
	UseDBQueue         bool
	JobTimeout         time.Duration
}

type Manager struct {
	storage    *storage.EntStorage
	config     ScannerConfig
	queue      Queue
	dispatcher *notifier.Dispatcher

	// inFlight is only used with InMemoryQueue
	inFlight   map[string]struct{}
	inFlightMu sync.Mutex
}

func NewManager(s *storage.EntStorage, cfg ScannerConfig, dispatcher *notifier.Dispatcher) *Manager {
	if cfg.ResolutionInterval == 0 {
		cfg.ResolutionInterval = 1 * time.Minute
	}
	if cfg.WorkerCount < 0 {
		cfg.WorkerCount = 0
	}
	if cfg.JobTimeout == 0 {
		cfg.JobTimeout = 10 * time.Minute
	}

	var q Queue
	if cfg.UseDBQueue {
		q = NewDBQueue(s, cfg.JobTimeout, 2*time.Second)
	} else {
		q = NewInMemoryQueue(1000)
	}

	return &Manager{
		storage:    s,
		config:     cfg,
		queue:      q,
		dispatcher: dispatcher,
		inFlight:   make(map[string]struct{}),
	}
}

func (m *Manager) Start() {
	// Start Producers
	go m.runResolutionProducer()
	go m.runIPScanProducer()
	go m.runSSLScanProducer()
	go m.runCSPScanProducer()

	// Stale job recovery (only for DB queue)
	if m.config.UseDBQueue {
		go m.runStaleJobRecovery()
	}

	// Start Workers
	log.Printf("Starting %d workers", m.config.WorkerCount)
	for i := range m.config.WorkerCount {
		go m.runWorker(i)
	}
}

func (m *Manager) canEnqueue(ctx context.Context, jobType string, key string) bool {
	if m.config.UseDBQueue {
		var jt job.Type
		switch jobType {
		case string(JobTypeResolution):
			jt = job.TypeResolve
		case string(JobTypePortScan):
			jt = job.TypePortScan
		case string(JobTypeSSLScan):
			jt = job.TypeSslScan
		case string(JobTypeCSPScan):
			jt = job.TypeCspScan
		}

		// Determine which payload key to check
		payloadKey := "input"
		if jobType == string(JobTypePortScan) {
			payloadKey = "address"
		}

		exists, err := m.storage.HasPendingJob(ctx, jt, payloadKey, key)
		if err != nil {
			log.Printf("Producer: Error checking pending job: %v", err)
			return false
		}
		return !exists
	}

	// In-memory queue: use inFlight map
	m.inFlightMu.Lock()
	defer m.inFlightMu.Unlock()
	if _, ok := m.inFlight[jobType+":"+key]; ok {
		return false
	}
	m.inFlight[jobType+":"+key] = struct{}{}
	return true
}

func (m *Manager) removeInFlight(key string) {
	if m.config.UseDBQueue {
		return // DB queue handles this via job status
	}
	m.inFlightMu.Lock()
	defer m.inFlightMu.Unlock()
	delete(m.inFlight, key)
}

func (m *Manager) completeJob(ctx context.Context, j Job) {
	if m.config.UseDBQueue && j.ID > 0 {
		if err := m.storage.CompleteJob(ctx, j.ID, nil); err != nil {
			log.Printf("Worker: failed to mark job %d complete: %v", j.ID, err)
		}
	}
}

func (m *Manager) failJob(ctx context.Context, j Job, errMsg string) {
	if m.config.UseDBQueue && j.ID > 0 {
		if err := m.storage.FailJob(ctx, j.ID, errMsg); err != nil {
			log.Printf("Worker: failed to mark job %d failed: %v", j.ID, err)
		}
	}
}

func (m *Manager) runStaleJobRecovery() {
	for {
		time.Sleep(30 * time.Second)
		ctx := context.Background()
		n, err := m.storage.RecoverStaleJobs(ctx)
		if err != nil {
			log.Printf("Stale recovery: error: %v", err)
		} else if n > 0 {
			log.Printf("Stale recovery: reset %d jobs", n)
		}
	}
}

func (m *Manager) runWorker(id int) {
	log.Printf("Worker %d started", id)
	ctx := context.Background()

	portScanner := ports.NewSimpleScanner(100, 50, 3, 1, 1000)

	var sslScanner *ssl.SSLLabsScanner
	if m.config.SSLEmail != "" {
		sslScanner = ssl.NewSSLLabsScanner(m.config.SSLEmail)
	}

	cspEvaluator := csp.NewEvaluator()
	clientHttp := http.Client{Timeout: 5 * time.Second}

	for {
		j, err := m.queue.Dequeue(ctx)
		if err != nil {
			log.Printf("Worker %d: Queue error: %v", id, err)
			return
		}

		key := string(j.Type) + ":" + j.Input
		if j.Type == JobTypePortScan {
			key = string(j.Type) + ":" + j.Address
		}

		switch j.Type {
		case JobTypeResolution:
			m.processResolution(ctx, j)
		case JobTypePortScan:
			m.processPortScan(ctx, j, portScanner)
		case JobTypeSSLScan:
			if sslScanner != nil {
				m.processSSLScan(ctx, j, sslScanner)
			}
		case JobTypeCSPScan:
			m.processCSPScan(ctx, j, clientHttp, cspEvaluator)
		}

		m.removeInFlight(key)
	}
}

// --- Producers ---

func (m *Manager) runResolutionProducer() {
	log.Println("Starting Resolution Producer")
	ctx := context.Background()
	for {
		targets, err := m.storage.GetUnresolvedTargets(ctx, 10, m.config.ResolutionInterval)
		if err != nil {
			log.Printf("Producer: Error fetching targets: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		if len(targets) == 0 {
			time.Sleep(10 * time.Second)
			continue
		}

		now := time.Now()
		for _, t := range targets {
			// Fibonacci backoff (capped 1h) keyed off the last attempt time.
			if now.Sub(t.UpdateTime) < resolveBackoff(t.ResolveAttempts, m.config.ResolutionInterval) {
				continue
			}
			if m.canEnqueue(ctx, string(JobTypeResolution), t.Input) {
				if err := m.queue.Enqueue(ctx, Job{Type: JobTypeResolution, Input: t.Input}); err != nil {
					log.Printf("Producer: failed to enqueue resolution for %s: %v", t.Input, err)
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
}

func (m *Manager) runIPScanProducer() {
	log.Println("Starting IP Port Scan Producer")
	ctx := context.Background()
	for {
		ipEntity, err := m.storage.GetOldestOutdatedIP(ctx, m.config.PortScanInterval)
		if err != nil {
			log.Printf("Producer: Error fetching IP: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}
		if ipEntity == nil {
			time.Sleep(10 * time.Second)
			continue
		}

		if !m.canEnqueue(ctx, string(JobTypePortScan), ipEntity.Address) {
			time.Sleep(1 * time.Second)
		} else if err := m.queue.Enqueue(ctx, Job{Type: JobTypePortScan, Address: ipEntity.Address}); err != nil {
			log.Printf("Producer: failed to enqueue port scan for %s: %v", ipEntity.Address, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (m *Manager) runSSLScanProducer() {
	if m.config.SSLEmail == "" {
		return
	}
	log.Println("Starting SSL Scan Producer")
	ctx := context.Background()
	for {
		t, err := m.storage.GetOldestOutdatedTarget(ctx, storage.ScanTypeSSL, m.config.SSLScanInterval)
		if err != nil {
			log.Printf("Producer: Error fetching SSL target: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}
		if t == nil {
			time.Sleep(10 * time.Second)
			continue
		}

		if !m.canEnqueue(ctx, string(JobTypeSSLScan), t.Input) {
			time.Sleep(1 * time.Second)
		} else if err := m.queue.Enqueue(ctx, Job{Type: JobTypeSSLScan, Input: t.Input}); err != nil {
			log.Printf("Producer: failed to enqueue SSL scan for %s: %v", t.Input, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (m *Manager) runCSPScanProducer() {
	log.Println("Starting CSP Scan Producer")
	ctx := context.Background()
	for {
		t, err := m.storage.GetOldestOutdatedTarget(ctx, storage.ScanTypeCSP, m.config.CSPScanInterval)
		if err != nil {
			log.Printf("Producer: Error fetching CSP target: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}
		if t == nil {
			time.Sleep(10 * time.Second)
			continue
		}

		if !m.canEnqueue(ctx, string(JobTypeCSPScan), t.Input) {
			time.Sleep(1 * time.Second)
		} else if err := m.queue.Enqueue(ctx, Job{Type: JobTypeCSPScan, Input: t.Input}); err != nil {
			log.Printf("Producer: failed to enqueue CSP scan for %s: %v", t.Input, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// --- Processors ---

func (m *Manager) processResolution(ctx context.Context, j Job) {
	log.Printf("Worker: Resolving %s", j.Input)
	ips, err := net.LookupIP(j.Input)
	if err != nil {
		msg := dnsErrorMessage(err)
		log.Printf("Worker: Failed to resolve %s: %s", j.Input, msg)
		if terr := m.storage.RecordResolveFailure(ctx, j.Input, msg); terr != nil {
			log.Printf("Worker: failed to record resolve failure for %s: %v", j.Input, terr)
		}
		m.failJob(ctx, j, msg)
		return
	}

	var ipStrings []string
	for _, ipAddr := range ips {
		ipStrings = append(ipStrings, ipAddr.String())
	}

	err = m.storage.SaveIPs(ctx, j.Input, ipStrings)
	if err != nil {
		log.Printf("Worker: Failed to save IPs for %s: %v", j.Input, err)
		m.failJob(ctx, j, err.Error())
	} else {
		log.Printf("Worker: Resolved %s to %v", j.Input, ipStrings)
		m.completeJob(ctx, j)
	}
}

func (m *Manager) processPortScan(ctx context.Context, j Job, scanner *ports.SimpleScanner) {
	log.Printf("Worker: Scanning IP %s", j.Address)

	// Get previous ports before scanning
	prevPorts, _ := m.storage.GetPreviousPortCounts(ctx, j.Address)
	prevSet := make(map[int]bool, len(prevPorts))
	for _, p := range prevPorts {
		prevSet[p] = true
	}

	openPorts, err := scanner.Scan(j.Address)
	if err != nil {
		log.Printf("Worker: Failed to scan %s: %v", j.Address, err)
		m.failJob(ctx, j, err.Error())
		return
	}

	err = m.storage.SavePortScan(ctx, j.Address, openPorts)
	if err != nil {
		log.Printf("Worker: Failed to save results for %s: %v", j.Address, err)
		m.failJob(ctx, j, err.Error())
		return
	}

	log.Printf("Worker: Saved %d ports for %s", len(openPorts), j.Address)
	m.completeJob(ctx, j)

	// Check for new open ports
	var newPorts []int
	for _, p := range openPorts {
		if !prevSet[p] {
			newPorts = append(newPorts, p)
		}
	}
	if len(newPorts) > 0 {
		portStrs := make([]string, len(newPorts))
		for i, p := range newPorts {
			portStrs[i] = fmt.Sprintf("%d", p)
		}
		m.dispatcher.Dispatch(ctx, notifier.Event{
			Type:      notifier.EventNewOpenPorts,
			Target:    j.Address,
			Message:   fmt.Sprintf("New open ports detected on %s: %s", j.Address, strings.Join(portStrs, ", ")),
			Details:   map[string]any{"new_ports": newPorts, "all_ports": openPorts},
			Timestamp: time.Now(),
		})
	}
}

func (m *Manager) processSSLScan(ctx context.Context, j Job, scanner *ssl.SSLLabsScanner) {
	log.Printf("Worker: SSL Scanning %s", j.Input)

	// Preflight: only ask SSL Labs about hosts that actually serve a cert on 443.
	// Avoids hammering the API (and 529s) with non-web names like DKIM/MX records.
	if !servesTLS(j.Input) {
		log.Printf("Worker: %s serves no certificate on port 443, skipping SSL Labs", j.Input)
		if serr := m.storage.SaveSSLScan(ctx, j.Input, storage.SSLResult{
			Grade:  "-",
			Status: "No HTTPS service on port 443",
		}); serr != nil {
			log.Printf("Worker: failed to save SSL scan for %s: %v", j.Input, serr)
		}
		m.completeJob(ctx, j)
		return
	}

	prevGrade, _ := m.storage.GetPreviousSSLGrade(ctx, j.Input)

	res, err := scanner.Scan(j.Input)
	if err != nil {
		log.Printf("Worker: SSL Scan failed for %s: %v", j.Input, err)
		saveRes := storage.SSLResult{
			Grade:  "F",
			Status: "Error: " + err.Error(),
		}
		if serr := m.storage.SaveSSLScan(ctx, j.Input, saveRes); serr != nil {
			log.Printf("Worker: failed to save SSL scan for %s: %v", j.Input, serr)
		}
		m.failJob(ctx, j, err.Error())
		return
	}

	saveRes := storage.SSLResult{
		Grade:           res.Grade,
		Status:          res.Status,
		CertIssuer:      res.CertIssuer,
		CertSubject:     res.CertSubject,
		CertExpiry:      res.CertExpiry,
		Protocols:       res.Protocols,
		Vulnerabilities: res.Vulnerabilities,
	}

	err = m.storage.SaveSSLScan(ctx, j.Input, saveRes)
	if err != nil {
		log.Printf("Worker: Failed to save SSL for %s: %v", j.Input, err)
		m.failJob(ctx, j, err.Error())
		return
	}

	log.Printf("Worker: Saved SSL for %s", j.Input)
	m.completeJob(ctx, j)

	// Check for grade drop
	if prevGrade != "" && res.Grade > prevGrade {
		m.dispatcher.Dispatch(ctx, notifier.Event{
			Type:      notifier.EventSSLGradeDrop,
			Target:    j.Input,
			Message:   fmt.Sprintf("SSL grade dropped for %s: %s → %s", j.Input, prevGrade, res.Grade),
			Details:   map[string]any{"previous_grade": prevGrade, "new_grade": res.Grade},
			Timestamp: time.Now(),
		})
	}

	// Check for expiring cert (<30 days)
	if !res.CertExpiry.IsZero() && time.Until(res.CertExpiry) < 30*24*time.Hour {
		m.dispatcher.Dispatch(ctx, notifier.Event{
			Type:      notifier.EventCertExpiring,
			Target:    j.Input,
			Message:   fmt.Sprintf("Certificate for %s expires on %s", j.Input, res.CertExpiry.Format("2006-01-02")),
			Details:   map[string]any{"cert_expiry": res.CertExpiry, "cert_subject": res.CertSubject},
			Timestamp: time.Now(),
		})
	}
}

func fetchCSPHeaders(client http.Client, host string) (enforce string, reportOnly string, err error) {
	resp, err := client.Get("https://" + host)
	if err != nil {
		resp, err = client.Get("http://" + host)
	}
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Header.Get("Content-Security-Policy"),
		resp.Header.Get("Content-Security-Policy-Report-Only"),
		nil
}

func (m *Manager) processCSPScan(ctx context.Context, j Job, client http.Client, evaluator csp.Evaluator) {
	log.Printf("Worker: CSP Scanning %s", j.Input)
	cspHeader, reportOnly, err := fetchCSPHeaders(client, j.Input)

	var findings []csp.Finding

	if err != nil {
		log.Printf("Worker: CSP Failed to connect to %s: %v", j.Input, err)
		if serr := m.storage.SaveCSPScan(ctx, j.Input, "", []csp.Finding{{
			Description: "Target Unreachable",
			Severity:    csp.SeverityInfo,
		}}); serr != nil {
			log.Printf("Worker: failed to save CSP scan for %s: %v", j.Input, serr)
		}
		m.failJob(ctx, j, err.Error())
		return
	}

	if cspHeader == "" && reportOnly == "" {
		findings = append(findings, csp.Finding{
			Type:        csp.TypeMissingDirectives,
			Description: "No Content-Security-Policy header found.",
			Severity:    csp.SeverityHigh,
			Directive:   "Header",
		})
	} else if cspHeader == "" {
		findings = append(findings, csp.Finding{
			Type:        csp.TypeMissingDirectives,
			Description: "Content-Security-Policy-Report-Only present; no enforcing Content-Security-Policy header.",
			Severity:    csp.SeverityMedium,
			Directive:   "Header",
		})
		f, evalErr := evaluator.Evaluate(reportOnly)
		if evalErr != nil {
			log.Printf("Worker: Error evaluating CSP-Report-Only for %s: %v", j.Input, evalErr)
		}
		findings = append(findings, f...)
		cspHeader = reportOnly
	} else {
		f, err := evaluator.Evaluate(cspHeader)
		if err != nil {
			log.Printf("Worker: Error evaluating CSP for %s: %v", j.Input, err)
		}
		findings = append(findings, f...)
	}

	err = m.storage.SaveCSPScan(ctx, j.Input, cspHeader, findings)
	if err != nil {
		log.Printf("Worker: Failed to save CSP for %s: %v", j.Input, err)
		m.failJob(ctx, j, err.Error())
		return
	}

	log.Printf("Worker: Saved CSP for %s", j.Input)
	m.completeJob(ctx, j)

	// Notify on high-severity CSP findings
	var highFindings []string
	for _, f := range findings {
		if f.Severity <= csp.SeverityMedium {
			highFindings = append(highFindings, f.Description)
		}
	}
	if len(highFindings) > 0 {
		m.dispatcher.Dispatch(ctx, notifier.Event{
			Type:      notifier.EventCSPIssues,
			Target:    j.Input,
			Message:   fmt.Sprintf("CSP issues found on %s: %s", j.Input, strings.Join(highFindings, "; ")),
			Details:   map[string]any{"findings_count": len(highFindings)},
			Timestamp: time.Now(),
		})
	}
}

// --- Helpers ---

// servesTLS reports whether host completes a TLS handshake on :443.
// InsecureSkipVerify because we only care that a cert is served; SSL Labs grades it.
func servesTLS(host string) bool {
	d := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", host+":443", &tls.Config{InsecureSkipVerify: true}) //nolint:gosec
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// dnsErrorMessage turns a net resolver error into a short, deterministic status.
func dnsErrorMessage(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return "no such host (NXDOMAIN)"
		case dnsErr.IsTimeout:
			return "DNS timeout"
		default:
			return "DNS error: " + dnsErr.Err
		}
	}
	return err.Error()
}

// resolveBackoff returns how long to wait before the next attempt given the
// number of prior failures: fibonacci multiples of base, capped at 1h.
func resolveBackoff(attempts int, base time.Duration) time.Duration {
	a, b := 1, 1
	for range attempts {
		a, b = b, a+b
	}
	w := time.Duration(a) * base
	if w > time.Hour {
		return time.Hour
	}
	return w
}
