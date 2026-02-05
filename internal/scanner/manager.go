package scanner

import (
	"context"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"perimeter/internal/storage"
	"perimeter/scanner/csp"
	"perimeter/scanner/ports"
	"perimeter/scanner/ssl"
)

type ScannerConfig struct {
	PortScanInterval   time.Duration
	SSLScanInterval    time.Duration
	CSPScanInterval    time.Duration
	ResolutionInterval time.Duration // New interval for checking resolutions
	SSLEmail           string
	WorkerCount        int
}

type Manager struct {
	storage storage.Storage
	config  ScannerConfig
	queue   Queue

	// inFlight tracks jobs currently doing work to avoid re-queueing same thing if queue is backed up
	inFlight   map[string]struct{}
	inFlightMu sync.Mutex
}

func NewManager(s storage.Storage, cfg ScannerConfig) *Manager {
	if cfg.ResolutionInterval == 0 {
		cfg.ResolutionInterval = 1 * time.Minute // Default
	}
	if cfg.WorkerCount < 0 {
		cfg.WorkerCount = 0
	}

	return &Manager{
		storage:  s,
		config:   cfg,
		queue:    NewInMemoryQueue(1000), // Buffer size 1000
		inFlight: make(map[string]struct{}),
	}
}

func (m *Manager) Start() {
	// Start Producers
	go m.runResolutionProducer()
	go m.runIPScanProducer()
	go m.runSSLScanProducer()
	go m.runCSPScanProducer()

	// Start Workers
	log.Printf("Starting %d workers", m.config.WorkerCount)
	for i := range m.config.WorkerCount {
		go m.runWorker(i)
	}
}

func (m *Manager) addInFlight(key string) bool {
	m.inFlightMu.Lock()
	defer m.inFlightMu.Unlock()
	if _, ok := m.inFlight[key]; ok {
		return false
	}
	m.inFlight[key] = struct{}{}
	return true
}

func (m *Manager) removeInFlight(key string) {
	m.inFlightMu.Lock()
	defer m.inFlightMu.Unlock()
	delete(m.inFlight, key)
}

func (m *Manager) runWorker(id int) {
	log.Printf("Worker %d started", id)
	ctx := context.Background()

	// Initialize Scanners locally for now (or share if thread-safe)
	// SimpleScanner is struct with values, thread-safe if configuration is read-only.
	portScanner := ports.NewSimpleScanner(100, 50, 3, 1, 1000)

	// SSLLabsScanner usually creates a new request per scan, so it should be fine.
	var sslScanner *ssl.SSLLabsScanner
	if m.config.SSLEmail != "" {
		sslScanner = ssl.NewSSLLabsScanner(m.config.SSLEmail)
	}

	cspEvaluator := csp.NewEvaluator()
	clientHttp := http.Client{Timeout: 5 * time.Second}

	for {
		job, err := m.queue.Dequeue(ctx)
		if err != nil {
			log.Printf("Worker %d: Queue error: %v", id, err)
			return
		}

		key := string(job.Type) + ":" + job.Input
		if job.Type == JobTypePortScan {
			key = string(job.Type) + ":" + job.Address
		}
		switch job.Type {
		case JobTypeResolution:
			m.processResolution(ctx, job)
		case JobTypePortScan:
			m.processPortScan(ctx, job, portScanner)
		case JobTypeSSLScan:
			if sslScanner != nil {
				m.processSSLScan(ctx, job, sslScanner)
			}
		case JobTypeCSPScan:
			m.processCSPScan(ctx, job, clientHttp, cspEvaluator)
		}

		m.removeInFlight(key)
	}
}

// --- Producers ---

func (m *Manager) runResolutionProducer() {
	log.Println("Starting Resolution Producer")
	ctx := context.Background()
	for {
		targets, err := m.storage.GetUnresolvedTargets(ctx, 10)
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
			key := string(JobTypeResolution) + ":" + t.Input
			if m.addInFlight(key) {
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

		key := string(JobTypePortScan) + ":" + ipEntity.Address
		if m.addInFlight(key) {
			m.queue.Enqueue(ctx, Job{Type: JobTypePortScan, Address: ipEntity.Address})
		} else {
			// If already in flight, sleep a bit to allow others to be picked if simple query loop
			// Since GetOldest returns the same one, we need to respect that.
			// Actually, if it's in flight, the fetching loop will keep picking it up until it's processed and timestamp updated.
			// So we need a way to 'skip' it or sleep if we can't add to flight.
			time.Sleep(1 * time.Second)
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

		key := string(JobTypeSSLScan) + ":" + t.Input
		if m.addInFlight(key) {
			m.queue.Enqueue(ctx, Job{Type: JobTypeSSLScan, Input: t.Input})
		} else {
			time.Sleep(1 * time.Second)
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

		key := string(JobTypeCSPScan) + ":" + t.Input
		if m.addInFlight(key) {
			m.queue.Enqueue(ctx, Job{Type: JobTypeCSPScan, Input: t.Input})
		} else {
			time.Sleep(1 * time.Second)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// --- Processors ---

func (m *Manager) processResolution(ctx context.Context, job Job) {
	log.Printf("Worker: Resolving %s", job.Input)
	ips, err := net.LookupIP(job.Input)
	if err != nil {
		log.Printf("Worker: Failed to resolve %s: %v", job.Input, err)
		return
	}

	var ipStrings []string
	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.String())
	}

	err = m.storage.SaveIPs(ctx, job.Input, ipStrings)
	if err != nil {
		log.Printf("Worker: Failed to save IPs for %s: %v", job.Input, err)
	} else {
		log.Printf("Worker: Resolved %s to %v", job.Input, ipStrings)
	}
}

func (m *Manager) processPortScan(ctx context.Context, job Job, scanner *ports.SimpleScanner) {
	log.Printf("Worker: Scanning IP %s", job.Address)
	openPorts, err := scanner.Scan(job.Address)
	if err != nil {
		log.Printf("Worker: Failed to scan %s: %v", job.Address, err)
		return
	}

	err = m.storage.SavePortScan(ctx, job.Address, openPorts)
	if err != nil {
		log.Printf("Worker: Failed to save results for %s: %v", job.Address, err)
	} else {
		log.Printf("Worker: Saved %d ports for %s", len(openPorts), job.Address)
	}
}

func (m *Manager) processSSLScan(ctx context.Context, job Job, scanner *ssl.SSLLabsScanner) {
	log.Printf("Worker: SSL Scanning %s", job.Input)
	res, err := scanner.Scan(job.Input)
	if err != nil {
		log.Printf("Worker: SSL Scan failed for %s: %v", job.Input, err)
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

	err = m.storage.SaveSSLScan(ctx, job.Input, saveRes)
	if err != nil {
		log.Printf("Worker: Failed to save SSL for %s: %v", job.Input, err)
	} else {
		log.Printf("Worker: Saved SSL for %s", job.Input)
	}
}

func (m *Manager) processCSPScan(ctx context.Context, job Job, client http.Client, evaluator csp.Evaluator) {
	log.Printf("Worker: CSP Scanning %s", job.Input)
	var cspHeader string
	resp, err := client.Head("https://" + job.Input)
	if err != nil {
		resp, err = client.Head("http://" + job.Input)
	}

	var findings []csp.Finding

	if err != nil {
		log.Printf("Worker: CSP Failed to connect to %s: %v", job.Input, err)
		m.storage.SaveCSPScan(ctx, job.Input, "", []csp.Finding{{
			Description: "Target Unreachable",
			Severity:    csp.SeverityInfo,
		}})
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
			log.Printf("Worker: Error evaluating CSP for %s: %v", job.Input, err)
		}
		findings = append(findings, f...)
	}

	err = m.storage.SaveCSPScan(ctx, job.Input, cspHeader, findings)
	if err != nil {
		log.Printf("Worker: Failed to save CSP for %s: %v", job.Input, err)
	} else {
		log.Printf("Worker: Saved CSP for %s", job.Input)
	}
}
