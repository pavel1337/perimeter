package scanner

import (
	"context"
	"log"
	"net"
	"net/http"
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
}

type Manager struct {
	storage storage.Storage
	config  ScannerConfig
}

func NewManager(s storage.Storage, cfg ScannerConfig) *Manager {
	if cfg.ResolutionInterval == 0 {
		cfg.ResolutionInterval = 1 * time.Minute // Default
	}
	return &Manager{
		storage: s,
		config:  cfg,
	}
}

func (m *Manager) Start() {
	go m.runResolutionLoop()
	go m.runIPScanLoop()
	go m.runSSLScanLoop()
	go m.runCSPScanLoop()
}

func (m *Manager) runResolutionLoop() {
	log.Println("Starting Resolution Loop")
	ctx := context.Background()

	for {
		// Fetch targets that need resolution (limiting to 10 at a time)
		targets, err := m.storage.GetUnresolvedTargets(ctx, 10)
		if err != nil {
			log.Printf("Resolution: Error fetching targets: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		if len(targets) == 0 {
			time.Sleep(10 * time.Second)
			continue
		}

		for _, t := range targets {
			log.Printf("Resolution: Resolving %s", t.Input)

			// Resolve
			ips, err := net.LookupIP(t.Input)
			if err != nil {
				log.Printf("Resolution: Failed to resolve %s: %v", t.Input, err)
				// Currently we don't mark it as failed in DB, so it might loop.
				// But we are sleeping in main loop.
				// Ideally we should mark 'last_checked' even on failure.
				// For now, let's assume transient DNS issues.
				// To prevent tight loop on bad domains, we could sleep or just rely on the fact we process only 10.
				continue
			}

			var ipStrings []string
			for _, ip := range ips {
				ipStrings = append(ipStrings, ip.String())
			}

			err = m.storage.SaveIPs(ctx, t.Input, ipStrings)
			if err != nil {
				log.Printf("Resolution: Failed to save IPs for %s: %v", t.Input, err)
			} else {
				log.Printf("Resolution: Resolved %s to %v", t.Input, ipStrings)
			}
		}

		time.Sleep(1 * time.Second)
	}
}

func (m *Manager) runIPScanLoop() {
	// Initialize Port Scanner
	scanner := ports.NewSimpleScanner(100, 50, 3, 1, 1000)
	ctx := context.Background()

	log.Println("Starting IP Port Scan Loop")

	for {
		// 1. Fetch oldest IP that hasn't been scanned
		ipEntity, err := m.storage.GetOldestOutdatedIP(ctx, m.config.PortScanInterval)
		if err != nil {
			log.Printf("PortScan: Error fetching IP: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		if ipEntity == nil {
			time.Sleep(10 * time.Second)
			continue
		}

		log.Printf("PortScan: Scanning IP %s", ipEntity.Address)

		// 2. Scan
		openPorts, err := scanner.Scan(ipEntity.Address)
		if err != nil {
			log.Printf("PortScan: Failed to scan %s: %v", ipEntity.Address, err)
			time.Sleep(1 * time.Second)
			continue
		}

		// 3. Save
		err = m.storage.SavePortScan(ctx, ipEntity.Address, openPorts)
		if err != nil {
			log.Printf("PortScan: Failed to save results for %s: %v", ipEntity.Address, err)
		} else {
			log.Printf("PortScan: Saved %d ports for %s", len(openPorts), ipEntity.Address)
		}

		// Small delay
		time.Sleep(1 * time.Second)
	}
}

func (m *Manager) runSSLScanLoop() {
	if m.config.SSLEmail == "" {
		log.Println("SSLScan: No email provided, skipping SSL scans.")
		return
	}

	scanner := ssl.NewSSLLabsScanner(m.config.SSLEmail)
	ctx := context.Background()

	log.Println("Starting SSL Scan Loop")

	for {
		t, err := m.storage.GetOldestOutdatedTarget(ctx, storage.ScanTypeSSL, m.config.SSLScanInterval)
		if err != nil {
			log.Printf("SSLScan: Error fetching target: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		if t == nil {
			time.Sleep(10 * time.Second)
			continue
		}

		log.Printf("SSLScan: Scanning %s", t.Input)

		res, err := scanner.Scan(t.Input)
		if err != nil {
			log.Printf("SSLScan: Scan failed for %s: %v", t.Input, err)
			time.Sleep(5 * time.Second)
			continue
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

		err = m.storage.SaveSSLScan(ctx, t.Input, saveRes)
		if err != nil {
			log.Printf("SSLScan: Failed to save for %s: %v", t.Input, err)
		} else {
			log.Printf("SSLScan: Saved for %s", t.Input)
		}
	}
}

func (m *Manager) runCSPScanLoop() {
	evaluator := csp.NewEvaluator()
	clientHttp := http.Client{Timeout: 5 * time.Second}
	ctx := context.Background()

	log.Println("Starting CSP Scan Loop")

	for {
		t, err := m.storage.GetOldestOutdatedTarget(ctx, storage.ScanTypeCSP, m.config.CSPScanInterval)
		if err != nil {
			log.Printf("CSPScan: Error fetching target: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		if t == nil {
			time.Sleep(10 * time.Second)
			continue
		}

		log.Printf("CSPScan: Scanning %s", t.Input)

		var cspHeader string
		resp, err := clientHttp.Head("https://" + t.Input)
		if err != nil {
			resp, err = clientHttp.Head("http://" + t.Input)
		}

		var findings []csp.Finding

		if err != nil {
			log.Printf("CSPScan: Failed to connect to %s: %v", t.Input, err)
			m.storage.SaveCSPScan(ctx, t.Input, "", []csp.Finding{{
				Description: "Target Unreachable",
				Severity:    csp.SeverityInfo,
			}})
			continue
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
				log.Printf("CSPScan: Error evaluating CSP for %s: %v", t.Input, err)
			}
			findings = append(findings, f...)
		}

		err = m.storage.SaveCSPScan(ctx, t.Input, cspHeader, findings)
		if err != nil {
			log.Printf("CSPScan: Failed to save for %s: %v", t.Input, err)
		} else {
			log.Printf("CSPScan: Saved for %s", t.Input)
		}
	}
}
