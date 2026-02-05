package storage

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"perimeter/ent"
	"perimeter/ent/cspscan"
	"perimeter/ent/ip"
	"perimeter/ent/portscan"
	"perimeter/ent/sslscan"
	"perimeter/ent/target"
	"perimeter/scanner/csp"
)

// ScanType definition
type ScanType string

const (
	ScanTypePort ScanType = "port" // Now applies to IPs
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
	GetOldestOutdatedIP(ctx context.Context, threshold time.Duration) (*ent.IP, error)
	GetUnresolvedTargets(ctx context.Context, limit int) ([]*ent.Target, error)

	// Saving Results
	SaveIPs(ctx context.Context, targetInput string, ipAddresses []string) error
	SavePortScan(ctx context.Context, ipAddress string, openPorts []int) error
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
		isIP := net.ParseIP(line) != nil
		exists, _ := s.client.Target.Query().Where(target.InputEQ(line)).Exist(ctx)
		var err error
		if exists {
			err = s.client.Target.Update().
				Where(target.InputEQ(line)).
				SetIsIP(isIP).
				Exec(ctx)
		} else {
			_, err = s.client.Target.Create().
				SetInput(line).
				SetIsIP(isIP).
				Save(ctx)
		}

		if err != nil {
			log.Printf("Error importing %s: %v", line, err)
		} else {
			count++
		}
	}
	return count, nil
}

func (s *EntStorage) GetTargets(ctx context.Context) ([]*ent.Target, error) {
	return s.client.Target.Query().
		WithIps(func(q *ent.IPQuery) {
			q.WithScans(func(sq *ent.PortScanQuery) {
				sq.WithPorts()
			})
		}).
		WithSslScans().
		WithCspScans().
		All(ctx)
}

func (s *EntStorage) GetTarget(ctx context.Context, id int) (*ent.Target, error) {
	return s.client.Target.Query().
		Where(target.ID(id)).
		WithIps(func(q *ent.IPQuery) {
			q.WithScans(func(sq *ent.PortScanQuery) {
				sq.WithPorts()
			})
		}).
		WithSslScans().
		WithCspScans().
		Only(ctx)
}

// GetOldestOutdatedTarget returns targets for SSL/CSP scans
func (s *EntStorage) GetOldestOutdatedTarget(ctx context.Context, scanType ScanType, threshold time.Duration) (*ent.Target, error) {
	cutoff := time.Now().Add(-threshold)
	query := s.client.Target.Query().Where(target.IsIP(false))

	switch scanType {
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
		return nil, fmt.Errorf("scan type %s not supported for Targets (use GetOldestOutdatedIP for ports)", scanType)
	}

	t, err := query.Order(ent.Asc(target.FieldUpdateTime)).First(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return nil, fmt.Errorf("error fetching target: %v", err)
	}
	return t, nil
}

func (s *EntStorage) GetOldestOutdatedIP(ctx context.Context, threshold time.Duration) (*ent.IP, error) {
	cutoff := time.Now().Add(-threshold)

	i, err := s.client.IP.Query().
		Where(ip.Or(
			ip.Not(ip.HasScans()),
			ip.Not(ip.HasScansWith(portscan.ScannedAtGTE(cutoff))),
		)).
		Order(ent.Asc(ip.FieldUpdateTime)).
		First(ctx)

	if err != nil && !ent.IsNotFound(err) {
		return nil, err
	}
	return i, nil
}

func (s *EntStorage) GetUnresolvedTargets(ctx context.Context, limit int) ([]*ent.Target, error) {
	// For simplicity: Targets with NO IPs.
	// To support re-resolution, we'd need a timestamp on the logic or checks.
	// Let's assume once resolved, it stays. Or we can just check if updated_at is old enough?
	// But updated_at changes on other things.
	// We will return targets that have NO IPs for now.
	return s.client.Target.Query().
		Where(target.Not(target.HasIps())).
		Limit(limit).
		All(ctx)
}

func (s *EntStorage) SaveIPs(ctx context.Context, targetInput string, ipAddresses []string) error {
	t, err := s.client.Target.Query().Where(target.Input(targetInput)).First(ctx)
	if err != nil {
		return err
	}

	// For each IP, find or create, then add to target.
	// Bulk operations are tricky with "Find or Create", so loop is fine for now.
	for _, ipAddr := range ipAddresses {
		// Use Upsert approach or just Check Exist -> Create
		// Ent Upsert support varies by driver (sqlite supports ON CONFLICT)
		// Let's try simple check-create

		// Create IP if not exists
		// We CAN use the ID if we want, but finding by address is safer.
		// Note: IP.Address is unique.

		// Attempt to create. If fails (unique violation), query it.
		// Or query first.

		// 1. Query
		i, err := s.client.IP.Query().Where(ip.Address(ipAddr)).First(ctx)
		if ent.IsNotFound(err) {
			// 2. Create
			i, err = s.client.IP.Create().SetAddress(ipAddr).Save(ctx)
			if err != nil {
				// Race condition possible? Yes. But for this tool, probably accept failure or retry.
				// If we get "constraint failed", we try to fetch again.
				i, err = s.client.IP.Query().Where(ip.Address(ipAddr)).First(ctx)
				if err != nil {
					log.Printf("Failed to recover IP creation for %s: %v", ipAddr, err)
					continue
				}
			}
		} else if err != nil {
			return err
		}

		// 3. Link to Target (AddIps handles deduplication on edge?)
		// Ent Many-to-Many additions:
		err = s.client.Target.UpdateOne(t).AddIps(i).Exec(ctx)
		if err != nil {
			log.Printf("Failed to link IP %s to target %s: %v", ipAddr, t.Input, err)
		}
	}

	// Update timestamp of Target to indicate we processed it?
	s.client.Target.UpdateOne(t).SetUpdateTime(time.Now()).Exec(ctx)

	return nil
}

func (s *EntStorage) SavePortScan(ctx context.Context, ipAddress string, openPorts []int) error {
	i, err := s.client.IP.Query().Where(ip.Address(ipAddress)).First(ctx)
	if err != nil {
		return err
	}

	scan, err := s.client.PortScan.Create().
		SetIP(i).
		SetScannedAt(time.Now()).
		Save(ctx)
	if err != nil {
		return err
	}

	if len(openPorts) > 0 {
		builders := make([]*ent.PortCreate, len(openPorts))
		for idx, p := range openPorts {
			builders[idx] = s.client.Port.Create().
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
