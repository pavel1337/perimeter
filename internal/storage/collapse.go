package storage

import (
	"context"
	"log"
	"slices"
	"time"

	"perimeter/ent"
	"perimeter/ent/cspscan"
	"perimeter/ent/ip"
	"perimeter/ent/port"
	"perimeter/ent/portscan"
	"perimeter/ent/sslscan"
	"perimeter/ent/target"
	"perimeter/scanner/csp"
)

// scanPorts returns the open ports recorded by a loaded port scan.
func scanPorts(scan *ent.PortScan) []int {
	numbers := make([]int, 0, len(scan.Edges.Ports))
	for _, p := range scan.Edges.Ports {
		numbers = append(numbers, p.Number)
	}
	return numbers
}

// samePorts reports whether two port lists describe the same open set,
// regardless of order or duplicates.
func samePorts(a, b []int) bool {
	x := slices.Clone(a)
	y := slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

// sameSSL reports whether a stored SSL scan carries the same result as res.
func sameSSL(scan *ent.SSLScan, res SSLResult) bool {
	return scan.Grade == res.Grade &&
		scan.Status == res.Status &&
		scan.CertIssuer == res.CertIssuer &&
		scan.CertSubject == res.CertSubject &&
		scan.CertExpiry.Equal(res.CertExpiry) &&
		slices.Equal(scan.Protocols, res.Protocols) &&
		slices.Equal(scan.Vulnerabilities, res.Vulnerabilities)
}

// sameCSP reports whether a stored CSP scan carries the same result.
func sameCSP(scan *ent.CSPScan, header string, findings []csp.Finding) bool {
	return scan.CspHeader == header && slices.Equal(scan.Findings, findings)
}

// lastSeen is the effective end of a row's period. Rows written before issue #4
// have no last_seen_at, so they cover a single instant.
func lastSeen(scannedAt, lastSeenAt time.Time) time.Time {
	if lastSeenAt.IsZero() {
		return scannedAt
	}
	return lastSeenAt
}

// checks is the effective number of scans a row already represents.
func checks(count int) int {
	if count < 1 {
		return 1
	}
	return count
}

// collapseStats counts what a backfill pass touched.
type collapseStats struct {
	read, kept, deleted int
}

func (c *collapseStats) log(kind string) {
	if c.read == 0 {
		return
	}
	log.Printf("Backfill (%s): read %d rows, kept %d, deleted %d", kind, c.read, c.kept, c.deleted)
}

// CollapseScanHistory folds runs of identical consecutive scan rows into a
// single row carrying a period (scanned_at .. last_seen_at) and a check count.
//
// Rows written before issue #4 carry check_count = 0, and every row written
// after it carries at least 1, so check_count is its own guard: a second run
// finds nothing and no version table is needed. Work is batched per IP/target
// in one transaction each, so a crash resumes on the next boot.
//
// This rewrites history destructively and has no undo. Snapshot the database
// before the first run.
func (s *EntStorage) CollapseScanHistory(ctx context.Context) error {
	client := s.client
	var ports, ssl, csps collapseStats

	ipIDs, err := client.IP.Query().Where(ip.HasScansWith(portscan.CheckCountEQ(0))).IDs(ctx)
	if err != nil {
		return err
	}
	for _, id := range ipIDs {
		if err := collapsePortScans(ctx, client, id, &ports); err != nil {
			return err
		}
	}
	ports.log("port")

	sslIDs, err := client.Target.Query().Where(target.HasSslScansWith(sslscan.CheckCountEQ(0))).IDs(ctx)
	if err != nil {
		return err
	}
	for _, id := range sslIDs {
		if err := collapseSSLScans(ctx, client, id, &ssl); err != nil {
			return err
		}
	}
	ssl.log("ssl")

	cspIDs, err := client.Target.Query().Where(target.HasCspScansWith(cspscan.CheckCountEQ(0))).IDs(ctx)
	if err != nil {
		return err
	}
	for _, id := range cspIDs {
		if err := collapseCSPScans(ctx, client, id, &csps); err != nil {
			return err
		}
	}
	csps.log("csp")

	return nil
}

func collapsePortScans(ctx context.Context, client *ent.Client, ipID int, stats *collapseStats) error {
	tx, err := client.Tx(ctx)
	if err != nil {
		return err
	}

	scans, err := tx.PortScan.Query().
		Where(portscan.HasIPWith(ip.IDEQ(ipID))).
		Order(ent.Asc(portscan.FieldScannedAt), ent.Asc(portscan.FieldID)).
		WithPorts().
		All(ctx)
	if err != nil {
		return rollback(tx, err)
	}
	stats.read += len(scans)

	var drop []int
	for start := 0; start < len(scans); {
		end := start + 1
		for end < len(scans) && samePorts(scanPorts(scans[start]), scanPorts(scans[end])) {
			end++
		}

		head, tail := scans[start], scans[end-1]
		count := 0
		for _, s := range scans[start:end] {
			count += checks(s.CheckCount)
		}
		if err := tx.PortScan.UpdateOne(head).
			SetLastSeenAt(lastSeen(tail.ScannedAt, tail.LastSeenAt)).
			SetCheckCount(count).
			Exec(ctx); err != nil {
			return rollback(tx, err)
		}
		for _, s := range scans[start+1 : end] {
			drop = append(drop, s.ID)
		}
		stats.kept++
		start = end
	}

	if len(drop) > 0 {
		if _, err := tx.Port.Delete().Where(port.HasScanWith(portscan.IDIn(drop...))).Exec(ctx); err != nil {
			return rollback(tx, err)
		}
		if _, err := tx.PortScan.Delete().Where(portscan.IDIn(drop...)).Exec(ctx); err != nil {
			return rollback(tx, err)
		}
		stats.deleted += len(drop)
	}

	return tx.Commit()
}

func collapseSSLScans(ctx context.Context, client *ent.Client, targetID int, stats *collapseStats) error {
	tx, err := client.Tx(ctx)
	if err != nil {
		return err
	}

	scans, err := tx.SSLScan.Query().
		Where(sslscan.HasTargetWith(target.IDEQ(targetID))).
		Order(ent.Asc(sslscan.FieldScannedAt), ent.Asc(sslscan.FieldID)).
		All(ctx)
	if err != nil {
		return rollback(tx, err)
	}
	stats.read += len(scans)

	var drop []int
	for start := 0; start < len(scans); {
		end := start + 1
		for end < len(scans) && sameSSLScans(scans[start], scans[end]) {
			end++
		}

		head, tail := scans[start], scans[end-1]
		count := 0
		for _, s := range scans[start:end] {
			count += checks(s.CheckCount)
		}
		if err := tx.SSLScan.UpdateOne(head).
			SetLastSeenAt(lastSeen(tail.ScannedAt, tail.LastSeenAt)).
			SetCheckCount(count).
			Exec(ctx); err != nil {
			return rollback(tx, err)
		}
		for _, s := range scans[start+1 : end] {
			drop = append(drop, s.ID)
		}
		stats.kept++
		start = end
	}

	if len(drop) > 0 {
		if _, err := tx.SSLScan.Delete().Where(sslscan.IDIn(drop...)).Exec(ctx); err != nil {
			return rollback(tx, err)
		}
		stats.deleted += len(drop)
	}

	return tx.Commit()
}

// sameSSLScans compares two stored rows through the same fingerprint the write
// path uses.
func sameSSLScans(a, b *ent.SSLScan) bool {
	return sameSSL(a, SSLResult{
		Grade:           b.Grade,
		Status:          b.Status,
		CertIssuer:      b.CertIssuer,
		CertSubject:     b.CertSubject,
		CertExpiry:      b.CertExpiry,
		Protocols:       b.Protocols,
		Vulnerabilities: b.Vulnerabilities,
	})
}

func collapseCSPScans(ctx context.Context, client *ent.Client, targetID int, stats *collapseStats) error {
	tx, err := client.Tx(ctx)
	if err != nil {
		return err
	}

	scans, err := tx.CSPScan.Query().
		Where(cspscan.HasTargetWith(target.IDEQ(targetID))).
		Order(ent.Asc(cspscan.FieldScannedAt), ent.Asc(cspscan.FieldID)).
		All(ctx)
	if err != nil {
		return rollback(tx, err)
	}
	stats.read += len(scans)

	var drop []int
	for start := 0; start < len(scans); {
		end := start + 1
		for end < len(scans) && sameCSP(scans[start], scans[end].CspHeader, scans[end].Findings) {
			end++
		}

		head, tail := scans[start], scans[end-1]
		count := 0
		for _, s := range scans[start:end] {
			count += checks(s.CheckCount)
		}
		if err := tx.CSPScan.UpdateOne(head).
			SetLastSeenAt(lastSeen(tail.ScannedAt, tail.LastSeenAt)).
			SetCheckCount(count).
			Exec(ctx); err != nil {
			return rollback(tx, err)
		}
		for _, s := range scans[start+1 : end] {
			drop = append(drop, s.ID)
		}
		stats.kept++
		start = end
	}

	if len(drop) > 0 {
		if _, err := tx.CSPScan.Delete().Where(cspscan.IDIn(drop...)).Exec(ctx); err != nil {
			return rollback(tx, err)
		}
		stats.deleted += len(drop)
	}

	return tx.Commit()
}
