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
	GetTargetBasic(ctx context.Context, id int) (*ent.Target, error)
	GetIPScansPage(ctx context.Context, ipID, limit, offset int) ([]*ent.PortScan, int, error)
	GetSSLScansPage(ctx context.Context, targetID, limit, offset int) ([]*ent.SSLScan, int, error)
	GetCSPScansPage(ctx context.Context, targetID, limit, offset int) ([]*ent.CSPScan, int, error)
	DeleteTarget(ctx context.Context, id int) error

	// Scanning Logic
	GetOldestOutdatedTarget(ctx context.Context, scanType ScanType, threshold time.Duration) (*ent.Target, error)
	GetOldestOutdatedIP(ctx context.Context, threshold time.Duration) (*ent.IP, error)
	GetUnresolvedTargets(ctx context.Context, limit int, threshold time.Duration) ([]*ent.Target, error)
	RecordResolveFailure(ctx context.Context, input, msg string) error
	TouchTarget(ctx context.Context, input string) error

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
		WithTags().
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
		WithTags().
		Only(ctx)
}

// GetTargetBasic loads a target's header info, tags, and IP list, without
// eager-loading each IP's (potentially very long) scan history. Use
// GetIPScansPage to page through an individual IP's scans.
func (s *EntStorage) GetTargetBasic(ctx context.Context, id int) (*ent.Target, error) {
	return s.client.Target.Query().
		Where(target.ID(id)).
		WithIps().
		WithTags().
		Only(ctx)
}

// GetIPScansPage returns one page of an IP's port scans (newest first) plus
// the total scan count.
func (s *EntStorage) GetIPScansPage(ctx context.Context, ipID, limit, offset int) ([]*ent.PortScan, int, error) {
	total, err := s.client.PortScan.Query().
		Where(portscan.HasIPWith(ip.IDEQ(ipID))).
		Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	scans, err := s.client.PortScan.Query().
		Where(portscan.HasIPWith(ip.IDEQ(ipID))).
		Order(ent.Desc(portscan.FieldScannedAt)).
		Limit(limit).
		Offset(offset).
		WithPorts().
		All(ctx)
	if err != nil {
		return nil, 0, err
	}

	return scans, total, nil
}

// GetSSLScansPage returns one page of a target's SSL scans (newest first)
// plus the total scan count.
func (s *EntStorage) GetSSLScansPage(ctx context.Context, targetID, limit, offset int) ([]*ent.SSLScan, int, error) {
	total, err := s.client.SSLScan.Query().
		Where(sslscan.HasTargetWith(target.IDEQ(targetID))).
		Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	scans, err := s.client.SSLScan.Query().
		Where(sslscan.HasTargetWith(target.IDEQ(targetID))).
		Order(ent.Desc(sslscan.FieldScannedAt)).
		Limit(limit).
		Offset(offset).
		All(ctx)
	if err != nil {
		return nil, 0, err
	}

	return scans, total, nil
}

// GetCSPScansPage returns one page of a target's CSP scans (newest first)
// plus the total scan count.
func (s *EntStorage) GetCSPScansPage(ctx context.Context, targetID, limit, offset int) ([]*ent.CSPScan, int, error) {
	total, err := s.client.CSPScan.Query().
		Where(cspscan.HasTargetWith(target.IDEQ(targetID))).
		Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	scans, err := s.client.CSPScan.Query().
		Where(cspscan.HasTargetWith(target.IDEQ(targetID))).
		Order(ent.Desc(cspscan.FieldScannedAt)).
		Limit(limit).
		Offset(offset).
		All(ctx)
	if err != nil {
		return nil, 0, err
	}

	return scans, total, nil
}

func (s *EntStorage) DeleteTarget(ctx context.Context, id int) error {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return err
	}
	// cascade delete scans
	_, err = tx.SSLScan.Delete().Where(sslscan.HasTargetWith(target.ID(id))).Exec(ctx)
	if err != nil {
		return rollback(tx, err)
	}
	_, err = tx.CSPScan.Delete().Where(cspscan.HasTargetWith(target.ID(id))).Exec(ctx)
	if err != nil {
		return rollback(tx, err)
	}

	// cleanup IPs that are orphaned if we want?
	// For now let's just delete the target. M2M edges to IPs will be removed automatically.
	// But IPs themselves remain, which is probably desired as they might be shared or re-discovered.

	err = tx.Target.DeleteOneID(id).Exec(ctx)
	if err != nil {
		return rollback(tx, err)
	}

	return tx.Commit()
}

func rollback(tx *ent.Tx, err error) error {
	if rerr := tx.Rollback(); rerr != nil {
		err = fmt.Errorf("%w: %v", err, rerr)
	}
	return err
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

// GetUnresolvedTargets returns up to limit targets with no IPs, oldest-attempt
// first. The caller applies per-target backoff (see scanner.resolveBackoff);
// oldest-first ordering means if the head isn't due yet, none are.
func (s *EntStorage) GetUnresolvedTargets(ctx context.Context, limit int, _ time.Duration) ([]*ent.Target, error) {
	return s.client.Target.Query().
		Where(target.Not(target.HasIps())).
		Order(ent.Asc(target.FieldUpdateTime)).
		Limit(limit).
		All(ctx)
}

// RecordResolveFailure bumps the attempt counter and stores a status message.
// UpdateTime is the backoff clock, so it is reset to now.
func (s *EntStorage) RecordResolveFailure(ctx context.Context, input, msg string) error {
	return s.client.Target.Update().
		Where(target.Input(input)).
		AddResolveAttempts(1).
		SetResolveError(msg).
		SetUpdateTime(time.Now()).
		Exec(ctx)
}

func (s *EntStorage) TouchTarget(ctx context.Context, input string) error {
	return s.client.Target.Update().
		Where(target.Input(input)).
		SetUpdateTime(time.Now()).
		Exec(ctx)
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

	// Resolved successfully: clear backoff state and update timestamp.
	if err := s.client.Target.UpdateOne(t).
		SetResolveAttempts(0).
		SetResolveError("").
		SetUpdateTime(time.Now()).Exec(ctx); err != nil {
		log.Printf("Failed to update target timestamp for %s: %v", t.Input, err)
	}

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

// GetPreviousPortCounts returns the set of open ports from the most recent scan for an IP.
func (s *EntStorage) GetPreviousPortCounts(ctx context.Context, ipAddress string) ([]int, error) {
	i, err := s.client.IP.Query().Where(ip.Address(ipAddress)).First(ctx)
	if err != nil {
		return nil, err
	}

	scan, err := s.client.PortScan.Query().
		Where(portscan.HasIPWith(ip.IDEQ(i.ID))).
		Order(ent.Desc(portscan.FieldScannedAt)).
		WithPorts().
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	var ports []int
	for _, p := range scan.Edges.Ports {
		ports = append(ports, p.Number)
	}
	return ports, nil
}

// GetPreviousSSLGrade returns the grade from the most recent SSL scan for a target.
func (s *EntStorage) GetPreviousSSLGrade(ctx context.Context, input string) (string, error) {
	t, err := s.client.Target.Query().Where(target.Input(input)).First(ctx)
	if err != nil {
		return "", err
	}

	scan, err := s.client.SSLScan.Query().
		Where(sslscan.HasTargetWith(target.IDEQ(t.ID))).
		Order(ent.Desc(sslscan.FieldScannedAt)).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return "", nil
		}
		return "", err
	}

	return scan.Grade, nil
}
