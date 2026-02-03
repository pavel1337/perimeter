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
	PortScanInterval time.Duration
	SSLScanInterval  time.Duration
	CSPScanInterval  time.Duration
	SSLEmail         string
}

type Manager struct {
	storage storage.Storage
	config  ScannerConfig
}

func NewManager(s storage.Storage, cfg ScannerConfig) *Manager {
	return &Manager{
		storage: s,
		config:  cfg,
	}
}

func (m *Manager) Start() {
	go m.runPortScanLoop()
	go m.runSSLScanLoop()
	go m.runCSPScanLoop()
}

func (m *Manager) runPortScanLoop() {
	// Initialize Port Scanner (parameters from original main.go)
	scanner := ports.NewSimpleScanner(100, 50, 3, 1, 1000)
	ctx := context.Background()

	log.Println("Starting Port Scan Loop")

	for {
		// 1. Fetch oldest target that hasn't been scanned in Interval
		t, err := m.storage.GetOldestOutdatedTarget(ctx, storage.ScanTypePort, m.config.PortScanInterval)
		if err != nil {
			log.Printf("PortScan: Error fetching target: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		if t == nil {
			// No targets need scanning
			// log.Println("PortScan: All targets fresh. Sleeping...")
			time.Sleep(10 * time.Second)
			continue
		}

		log.Printf("PortScan: Scanning %s", t.Input)

		// 2. Scan
		// Determine IP (Logic from original: group by IP. Here we scan individual input)
		// We might want to resolve it.
		// ports.NewSimpleScanner().Scan(host)
		openPorts, err := scanner.Scan(t.Input)
		if err != nil {
			log.Printf("PortScan: Failed to scan %s: %v", t.Input, err)
			// Sleep a bit to avoid hot loop if failure is persistent (though GetOldest should cycle)
			time.Sleep(1 * time.Second)
			continue
		}

		// 3. Save
		err = m.storage.SavePortScan(ctx, t.Input, openPorts)
		if err != nil {
			log.Printf("PortScan: Failed to save results for %s: %v", t.Input, err)
		} else {
			log.Printf("PortScan: Saved %d ports for %s", len(openPorts), t.Input)
		}

		// Small delay to be nice
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

		// Filter non-hostnames (IPs)
		if !isHostname(t.Input) {
			// It will keep picking this IP if we don't do something.
			// But GetOldestOutdatedTarget logic relies on "Timestamp".
			// If we don't scan it, we never update timestamp, so we loop on it.
			// FIX: We must "skip" it effectively.
			// Options:
			// 1. Mark as "skipped" in DB? (No status field in schema currently, except maybe just saving a dummy scan?)
			// 2. Storage should filter IPs for SSL?

			// Let's modify Storage to support filtering, OR just save a "N/A" result to bump timestamp.
			log.Printf("SSLScan: Skipping IP %s (not a hostname)", t.Input)

			// Save empty/dummy result to update timestamp
			m.storage.SaveSSLScan(ctx, t.Input, storage.SSLResult{Status: "Skipped (IP Address)"})
			continue
		}

		log.Printf("SSLScan: Scanning %s", t.Input)

		res, err := scanner.Scan(t.Input)
		if err != nil {
			log.Printf("SSLScan: Scan failed for %s: %v", t.Input, err)
			// Save failure to avoid tight loop retry?
			// The original code retried?
			time.Sleep(5 * time.Second)
			continue
		}

		// Convert result
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

		if !isHostname(t.Input) {
			// Save dummy to bump timestamp
			log.Printf("CSPScan: Skipping IP %s", t.Input)
			m.storage.SaveCSPScan(ctx, t.Input, "N/A - IP Address", nil)
			continue
		}

		log.Printf("CSPScan: Scanning %s", t.Input)

		// Scan Logic from main.go
		var cspHeader string
		resp, err := clientHttp.Head("https://" + t.Input)
		if err != nil {
			resp, err = clientHttp.Head("http://" + t.Input)
		}

		var findings []csp.Finding

		if err != nil {
			log.Printf("CSPScan: Failed to connect to %s: %v", t.Input, err)
			// Original logic: continued.
			// We should save something to bump timestamp, maybe "Unreachable"?
			// Or just ignore and let it be retried (but that blocks others).
			// Saving with empty header implies missing?
			// I'll save with no header and maybe a finding "Unreachable"?
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

func isHostname(input string) bool {
	return net.ParseIP(input) == nil
}
