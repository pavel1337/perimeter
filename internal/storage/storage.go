package storage

import (
	"context"
	"fmt"
	"log"
	"time"

	"perimeter/ent"
	"perimeter/ent/cspscan"
	"perimeter/ent/portscan"
	"perimeter/ent/sslscan"
	"perimeter/ent/target"
	"perimeter/scanner/csp"
)

// ScanType definition
type ScanType string

const (
	ScanTypePort ScanType = "port"
	ScanTypeSSL  ScanType = "ssl"
	ScanTypeCSP  ScanType = "csp"
)

// Storage defines the interface for data access
type Storage interface {
	// General
	Close() error
	ImportTargets(ctx context.Context, lines []string) (int, error)
	GetTargets(ctx context.Context) ([]*ent.Target, error)
	GetTarget(ctx context.Context, id int) (*ent.Target, error)

	// Scanning Logic
	GetOldestOutdatedTarget(ctx context.Context, scanType ScanType, threshold time.Duration) (*ent.Target, error)

	// Saving Results
	SavePortScan(ctx context.Context, input string, openPorts []int) error
	SaveSSLScan(ctx context.Context, input string, result SSLResult) error
	SaveCSPScan(ctx context.Context, input string, header string, findings []csp.Finding) error
}

// SSLResult DTO
type SSLResult struct {
	Grade           string
	Status          string
	CertIssuer      string
	CertSubject     string
	CertExpiry      time.Time
	Protocols       []string
	Vulnerabilities []string
}

// EntStorage implements Storage using Ent
type EntStorage struct {
	client *ent.Client
}

func NewEntStorage(client *ent.Client) *EntStorage {
	return &EntStorage{client: client}
}

func (s *EntStorage) Close() error {
	return s.client.Close()
}

func (s *EntStorage) ImportTargets(ctx context.Context, lines []string) (int, error) {
	count := 0
	for _, line := range lines {
		if line == "" {
			continue
		}
		exists, _ := s.client.Target.Query().Where(target.InputEQ(line)).Exist(ctx)
		if !exists {
			_, err := s.client.Target.Create().SetInput(line).Save(ctx)
			if err != nil {
				log.Printf("Error adding %s: %v", line, err)
			} else {
				count++
			}
		}
	}
	return count, nil
}

func (s *EntStorage) GetTargets(ctx context.Context) ([]*ent.Target, error) {
	return s.client.Target.Query().
		WithScans(func(q *ent.PortScanQuery) {
			q.WithPorts()
		}).
		WithSslScans().
		WithCspScans().
		All(ctx)
}

func (s *EntStorage) GetTarget(ctx context.Context, id int) (*ent.Target, error) {
	return s.client.Target.Query().
		Where(target.ID(id)).
		WithScans(func(q *ent.PortScanQuery) {
			q.WithPorts()
		}).
		WithSslScans().
		WithCspScans().
		Only(ctx)
}

func (s *EntStorage) GetOldestOutdatedTarget(ctx context.Context, scanType ScanType, threshold time.Duration) (*ent.Target, error) {
	cutoff := time.Now().Add(-threshold)

	query := s.client.Target.Query()

	switch scanType {
	case ScanTypePort:
		query.Where(target.Or(
			target.Not(target.HasScans()),
			target.Not(target.HasScansWith(portscan.ScannedAtGTE(cutoff))),
		))
	case ScanTypeSSL:
		query.Where(target.Or(
			target.Not(target.HasSslScans()),
			target.Not(target.HasSslScansWith(sslscan.ScannedAtGTE(cutoff))),
		))
	case ScanTypeCSP:
		query.Where(target.Or(
			target.Not(target.HasCspScans()),
			target.Not(target.HasCspScansWith(cspscan.ScannedAtGTE(cutoff))),
		))
	default:
		return nil, fmt.Errorf("unknown scan type")
	}

	t, err := query.First(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return nil, fmt.Errorf("error fetching target: %v", err)
	}

	return t, nil
}

func (s *EntStorage) SavePortScan(ctx context.Context, input string, openPorts []int) error {
	t, err := s.client.Target.Query().Where(target.Input(input)).First(ctx)
	if err != nil {
		return err
	}

	// For port scan, we might have multiple targets grouped.
	// The interface takes "input" (singular).
	// This implies the scanner loop determines the single target and scans it.
	// In the original code, it grouped by IP.
	// I should probably support grouping or just scan one by one.
	// "worker must fetch the oldest scanned target, and scan it."
	// This implies singular scanning.
	// However, multiple targets might share IP. Scanning one IP covers all updates?
	// If I scan hostname X -> IP Y. Hostname Z -> IP Y.
	// Scanning IP Y covers both.
	// But if I only scan X, do I update Z?
	// The prompt says "fetch the oldest scanned target". It doesn't mention grouping optimization but the old code had it.
	// If I strip grouping, it's safer but less efficient.
	// I will stick to scanning the specific target requested for now.
	// To keep "Grouping" logic, the scanner would need to resolve IPs and handle it.
	// I'll keep it simple: One target -> One scan record.

	scan, err := s.client.PortScan.Create().
		AddTargets(t).
		SetScannedAt(time.Now()).
		Save(ctx)
	if err != nil {
		return err
	}

	if len(openPorts) > 0 {
		builders := make([]*ent.PortCreate, len(openPorts))
		for i, p := range openPorts {
			builders[i] = s.client.Port.Create().
				SetScan(scan).
				SetNumber(p)
		}
		_, err = s.client.Port.CreateBulk(builders...).Save(ctx)
		return err
	}
	return nil
}

func (s *EntStorage) SaveSSLScan(ctx context.Context, input string, res SSLResult) error {
	t, err := s.client.Target.Query().Where(target.Input(input)).First(ctx)
	if err != nil {
		return err
	}

	_, err = s.client.SSLScan.Create().
		SetTarget(t).
		SetScannedAt(time.Now()).
		SetGrade(res.Grade).
		SetStatus(res.Status).
		SetCertIssuer(res.CertIssuer).
		SetCertSubject(res.CertSubject).
		SetCertExpiry(res.CertExpiry).
		SetProtocols(res.Protocols).
		SetVulnerabilities(res.Vulnerabilities).
		Save(ctx)
	return err
}

func (s *EntStorage) SaveCSPScan(ctx context.Context, input string, header string, findings []csp.Finding) error {
	t, err := s.client.Target.Query().Where(target.Input(input)).First(ctx)
	if err != nil {
		return err
	}

	_, err = s.client.CSPScan.Create().
		SetTarget(t).
		SetScannedAt(time.Now()).
		SetCspHeader(header).
		SetFindings(findings).
		Save(ctx)
	return err
}
