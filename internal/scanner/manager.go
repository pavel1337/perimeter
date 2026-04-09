package scanner

import (
	"context"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"perimeter/ent/job"
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
	storage  *storage.EntStorage
	config   ScannerConfig
	queue    Queue

	// inFlight is only used with InMemoryQueue
	inFlight   map[string]struct{}
	inFlightMu sync.Mutex
}

func NewManager(s *storage.EntStorage, cfg ScannerConfig) *Manager {
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
		storage:  s,
		config:   cfg,
		queue:    q,
		inFlight: make(map[string]struct{}),
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
		m.storage.CompleteJob(ctx, j.ID, nil)
	}
}

func (m *Manager) failJob(ctx context.Context, j Job, errMsg string) {
	if m.config.UseDBQueue && j.ID > 0 {
		m.storage.FailJob(ctx, j.ID, errMsg)
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

		for _, t := range targets {
			if m.canEnqueue(ctx, string(JobTypeResolution), t.Input) {
				m.queue.Enqueue(ctx, Job{Type: JobTypeResolution, Input: t.Input})
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
		} else {
			m.queue.Enqueue(ctx, Job{Type: JobTypePortScan, Address: ipEntity.Address})
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
		} else {
			m.queue.Enqueue(ctx, Job{Type: JobTypeSSLScan, Input: t.Input})
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
		} else {
			m.queue.Enqueue(ctx, Job{Type: JobTypeCSPScan, Input: t.Input})
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// --- Processors ---

func (m *Manager) processResolution(ctx context.Context, j Job) {
	log.Printf("Worker: Resolving %s", j.Input)
	ips, err := net.LookupIP(j.Input)
	if err != nil {
		log.Printf("Worker: Failed to resolve %s: %v", j.Input, err)
		m.storage.TouchTarget(ctx, j.Input)
		m.failJob(ctx, j, err.Error())
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
	} else {
		log.Printf("Worker: Saved %d ports for %s", len(openPorts), j.Address)
		m.completeJob(ctx, j)
	}
}

func (m *Manager) processSSLScan(ctx context.Context, j Job, scanner *ssl.SSLLabsScanner) {
	log.Printf("Worker: SSL Scanning %s", j.Input)
	res, err := scanner.Scan(j.Input)
	if err != nil {
		log.Printf("Worker: SSL Scan failed for %s: %v", j.Input, err)
		saveRes := storage.SSLResult{
			Grade:  "F",
			Status: "Error: " + err.Error(),
		}
		m.storage.SaveSSLScan(ctx, j.Input, saveRes)
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
	} else {
		log.Printf("Worker: Saved SSL for %s", j.Input)
		m.completeJob(ctx, j)
	}
}

func (m *Manager) processCSPScan(ctx context.Context, j Job, client http.Client, evaluator csp.Evaluator) {
	log.Printf("Worker: CSP Scanning %s", j.Input)
	var cspHeader string
	resp, err := client.Head("https://" + j.Input)
	if err != nil {
		resp, err = client.Head("http://" + j.Input)
	}

	var findings []csp.Finding

	if err != nil {
		log.Printf("Worker: CSP Failed to connect to %s: %v", j.Input, err)
		m.storage.SaveCSPScan(ctx, j.Input, "", []csp.Finding{{
			Description: "Target Unreachable",
			Severity:    csp.SeverityInfo,
		}})
		m.failJob(ctx, j, err.Error())
		return
	}

	defer resp.Body.Close()
	cspHeader = resp.Header.Get("Content-Security-Policy")

	if cspHeader == "" {
		findings = append(findings, csp.Finding{
			Type:        csp.TypeMissingDirectives,
			Description: "No Content-Security-Policy header found.",
			Severity:    csp.SeverityHigh,
			Directive:   "Header",
		})
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
	} else {
		log.Printf("Worker: Saved CSP for %s", j.Input)
		m.completeJob(ctx, j)
	}
}
