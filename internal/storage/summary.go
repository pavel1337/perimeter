package storage

import (
	"context"
	"log"
	"time"

	"perimeter/ent"
	"perimeter/ent/cspscan"
	"perimeter/ent/ip"
	"perimeter/ent/portscan"
	"perimeter/ent/predicate"
	"perimeter/ent/sslscan"
	"perimeter/ent/target"
)

// summary is the denormalized view of a target's newest scans kept on the
// target row, so the dashboard can sort and filter on it in SQL (issue #14).
type summary struct {
	reachability    target.Reachability
	sslGrade        string
	sslGradeRank    int
	certExpiry      *time.Time
	cspFindingCount *int
	openPortCount   int
}

// gradeRanks orders SSL Labs grades best-first, so sorting by rank needs no
// CASE expression. T (untrusted) and M (name mismatch) fail like F. Anything
// else ("-" for no HTTPS, "" for an assessment that did not finish) is 0.
var gradeRanks = map[string]int{
	"A+": 8, "A": 7, "A-": 6, "B": 5, "C": 4, "D": 3, "E": 2,
	"F": 1, "T": 1, "M": 1,
}

// summarize derives the summary from a target whose edges hold only its
// newest scans: each IP's newest port scan with its ports, and the newest
// SSL and CSP scan. refreshSummary and BackfillSummary load that shape in
// different ways; this is the one place the values are defined.
func summarize(t *ent.Target) summary {
	sum := summary{reachability: loadedFacts(t).decide()}
	for _, i := range t.Edges.Ips {
		if len(i.Edges.Scans) > 0 {
			sum.openPortCount += len(i.Edges.Scans[0].Edges.Ports)
		}
	}
	if len(t.Edges.SslScans) > 0 {
		ssl := t.Edges.SslScans[0]
		sum.sslGrade = ssl.Grade
		sum.sslGradeRank = gradeRanks[ssl.Grade]
		if !ssl.CertExpiry.IsZero() {
			exp := ssl.CertExpiry
			sum.certExpiry = &exp
		}
	}
	// A probe that got no response says nothing about the policy.
	if len(t.Edges.CspScans) > 0 && t.Edges.CspScans[0].ProbeError == "" {
		n := len(t.Edges.CspScans[0].Findings)
		sum.cspFindingCount = &n
	}
	return sum
}

// matches reports whether t already stores this summary.
func (sum summary) matches(t *ent.Target) bool {
	return t.Reachability == sum.reachability &&
		t.LatestSslGrade == sum.sslGrade &&
		t.LatestSslGradeRank == sum.sslGradeRank &&
		sameTime(t.LatestCertExpiry, sum.certExpiry) &&
		sameInt(t.LatestCspFindingCount, sum.cspFindingCount) &&
		t.OpenPortCount == sum.openPortCount
}

func (sum summary) save(ctx context.Context, client *ent.Client, t *ent.Target) error {
	if sum.matches(t) {
		return nil
	}
	u := client.Target.UpdateOne(t).
		SetReachability(sum.reachability).
		SetLatestSslGradeRank(sum.sslGradeRank).
		SetOpenPortCount(sum.openPortCount)
	// Unknown is NULL, like the other summary columns.
	if sum.sslGrade != "" {
		u.SetLatestSslGrade(sum.sslGrade)
	} else {
		u.ClearLatestSslGrade()
	}
	if sum.certExpiry != nil {
		u.SetLatestCertExpiry(*sum.certExpiry)
	} else {
		u.ClearLatestCertExpiry()
	}
	if sum.cspFindingCount != nil {
		u.SetLatestCspFindingCount(*sum.cspFindingCount)
	} else {
		u.ClearLatestCspFindingCount()
	}
	return u.Exec(ctx)
}

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

func sameInt(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// refreshSummary rebuilds the summary of the matching targets from their
// stored scans. Every scan write calls it; pass a transactional client to
// keep it in step with the write.
//
// It queries each target's newest scans directly rather than through
// latestPerParent: that subquery groups the whole scan table, which is fine
// for one dashboard load but not on every scan write.
func refreshSummary(ctx context.Context, client *ent.Client, where ...predicate.Target) error {
	targets, err := client.Target.Query().Where(where...).WithIps().All(ctx)
	if err != nil {
		return err
	}
	for _, t := range targets {
		if err := loadNewestScans(ctx, client, t); err != nil {
			return err
		}
		if err := summarize(t).save(ctx, client, t); err != nil {
			return err
		}
	}
	return nil
}

// loadNewestScans fills t's scan edges with only the newest rows, the shape
// summarize reads. t must already carry its IPs.
func loadNewestScans(ctx context.Context, client *ent.Client, t *ent.Target) error {
	for _, i := range t.Edges.Ips {
		scan, err := client.PortScan.Query().
			Where(portscan.HasIPWith(ip.IDEQ(i.ID))).
			Order(ent.Desc(portscan.FieldScannedAt), ent.Desc(portscan.FieldID)).
			WithPorts().
			First(ctx)
		if err != nil && !ent.IsNotFound(err) {
			return err
		}
		i.Edges.Scans = nonNil(scan)
	}

	ssl, err := client.SSLScan.Query().
		Where(sslscan.HasTargetWith(target.IDEQ(t.ID))).
		Order(ent.Desc(sslscan.FieldScannedAt), ent.Desc(sslscan.FieldID)).
		First(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return err
	}
	t.Edges.SslScans = nonNil(ssl)

	csp, err := client.CSPScan.Query().
		Where(cspscan.HasTargetWith(target.IDEQ(t.ID))).
		Order(ent.Desc(cspscan.FieldScannedAt), ent.Desc(cspscan.FieldID)).
		First(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return err
	}
	t.Edges.CspScans = nonNil(csp)
	return nil
}

// nonNil wraps the result of a First query as an edge slice.
func nonNil[T any](v *T) []*T {
	if v == nil {
		return nil
	}
	return []*T{v}
}

// BackfillSummary rebuilds every target's summary from the scan tables. The
// summary is a cache, so this is always safe to rerun.
func (s *EntStorage) BackfillSummary(ctx context.Context) error {
	// One pass with latestPerParent, instead of refreshSummary's per-target
	// queries.
	targets, err := s.client.Target.Query().
		WithIps(func(q *ent.IPQuery) {
			q.WithScans(func(sq *ent.PortScanQuery) {
				sq.Where(latestPerParent(portscan.Table, portscan.IPColumn)).
					WithPorts()
			})
		}).
		WithSslScans(func(q *ent.SSLScanQuery) {
			q.Where(latestPerParent(sslscan.Table, sslscan.TargetColumn))
		}).
		WithCspScans(func(q *ent.CSPScanQuery) {
			q.Where(latestPerParent(cspscan.Table, cspscan.TargetColumn))
		}).
		All(ctx)
	if err != nil {
		return err
	}

	changed := 0
	counts := map[target.Reachability]int{}
	for _, t := range targets {
		sum := summarize(t)
		counts[sum.reachability]++
		if sum.matches(t) {
			continue
		}
		if err := sum.save(ctx, s.client, t); err != nil {
			return err
		}
		changed++
	}

	log.Printf("Backfill (summary): %d targets, %d updated; reachability %v", len(targets), changed, counts)
	return nil
}
