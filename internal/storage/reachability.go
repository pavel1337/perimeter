package storage

import (
	"context"
	"log"

	"perimeter/ent"
	"perimeter/ent/cspscan"
	"perimeter/ent/ip"
	"perimeter/ent/portscan"
	"perimeter/ent/predicate"
	"perimeter/ent/target"
	"perimeter/scanner/csp"
)

// reachFacts is what reachability is decided from. The write paths and the
// backfill gather it differently, but both go through decide, so there is one
// definition of each state.
type reachFacts struct {
	isIP          bool
	resolved      bool // has at least one IP
	resolveFailed bool // resolve_error set; cleared on the next resolve
	portsScanned  bool // some IP has a port scan
	portsOpen     bool // some IP's newest port scan has an open port
	httpProbed    bool // has a CSP scan
	httpAnswered  bool // newest CSP scan got an HTTP response
}

// decide maps facts to a state. A target is ok if anything answers: an open
// port or an HTTP response. A mail or SSH host with no website is reachable;
// the CSP column says separately that it has no HTTP (issue #15).
//
// The CSP producer probes targets whether or not they have resolved, so a
// probe result outranks "no IPs yet". Port scans can only promote a domain to
// ok, never mark it unreachable: the HTTP probe is the check every domain
// gets, so until it has run a domain with nothing open is still pending. Bare
// IPs get no HTTP probe, so for them the port scan is the only check.
func (f reachFacts) decide() target.Reachability {
	switch {
	case f.portsOpen || f.httpAnswered:
		return target.ReachabilityOk
	case !f.resolved && f.resolveFailed:
		return target.ReachabilityUnresolved
	case f.httpProbed, f.isIP && f.portsScanned:
		return target.ReachabilityUnreachable
	default:
		return target.ReachabilityPending
	}
}

// refreshReachability recomputes reachability for the matching targets from
// their stored scans. Pass a transactional client to keep it in step with the
// write that triggered it.
//
// It queries each target's newest scans directly rather than through
// latestPerParent: that subquery groups the whole scan table, which is fine
// for one dashboard load but not on every scan write.
func refreshReachability(ctx context.Context, client *ent.Client, where ...predicate.Target) error {
	targets, err := client.Target.Query().Where(where...).WithIps().All(ctx)
	if err != nil {
		return err
	}
	for _, t := range targets {
		f := reachFacts{
			isIP:          t.IsIP,
			resolved:      len(t.Edges.Ips) > 0,
			resolveFailed: t.ResolveError != "",
		}
		for _, i := range t.Edges.Ips {
			scan, err := client.PortScan.Query().
				Where(portscan.HasIPWith(ip.IDEQ(i.ID))).
				Order(ent.Desc(portscan.FieldScannedAt), ent.Desc(portscan.FieldID)).
				WithPorts().
				First(ctx)
			if ent.IsNotFound(err) {
				continue
			}
			if err != nil {
				return err
			}
			f.portsScanned = true
			f.portsOpen = f.portsOpen || len(scan.Edges.Ports) > 0
		}
		latest, err := client.CSPScan.Query().
			Where(cspscan.HasTargetWith(target.IDEQ(t.ID))).
			Order(ent.Desc(cspscan.FieldScannedAt), ent.Desc(cspscan.FieldID)).
			First(ctx)
		if err != nil && !ent.IsNotFound(err) {
			return err
		}
		if latest != nil {
			f.httpProbed = true
			f.httpAnswered = latest.ProbeError == ""
		}

		if r := f.decide(); r != t.Reachability {
			if err := client.Target.UpdateOne(t).SetReachability(r).Exec(ctx); err != nil {
				return err
			}
		}
	}
	return nil
}

// legacyUnreachable is the description of the synthetic finding the CSP
// scanner used to write when a target did not answer, before issue #15.
const legacyUnreachable = "Target Unreachable"

// legacyProbeError is what a converted legacy row reports: the original
// network error was never stored.
const legacyProbeError = "no response"

// isLegacyUnreachable reports whether findings is exactly the old synthetic
// "Target Unreachable" marker.
func isLegacyUnreachable(findings []csp.Finding) bool {
	return len(findings) == 1 && findings[0].Description == legacyUnreachable
}

// BackfillReachability moves CSP scans off the "Target Unreachable" magic
// finding onto probe_error, then derives every target's reachability from its
// current state. Both steps overwrite with values computed from the data, so
// a rerun after a crash just recomputes them.
func (s *EntStorage) BackfillReachability(ctx context.Context) error {
	converted, err := s.convertLegacyUnreachable(ctx)
	if err != nil {
		return err
	}

	// One pass with latestPerParent, instead of refreshReachability's
	// per-target queries.
	targets, err := s.client.Target.Query().
		WithIps(func(q *ent.IPQuery) {
			q.WithScans(func(sq *ent.PortScanQuery) {
				sq.Where(latestPerParent(portscan.Table, portscan.IPColumn)).
					WithPorts()
			})
		}).
		WithCspScans(func(q *ent.CSPScanQuery) {
			q.Where(latestPerParent(cspscan.Table, cspscan.TargetColumn))
		}).
		All(ctx)
	if err != nil {
		return err
	}

	counts := map[target.Reachability]int{}
	for _, t := range targets {
		r := loadedFacts(t).decide()
		counts[r]++
		if r == t.Reachability {
			continue
		}
		if err := s.client.Target.UpdateOne(t).SetReachability(r).Exec(ctx); err != nil {
			return err
		}
	}

	log.Printf("Backfill (reachability): converted %d legacy CSP rows; %d targets: %v", converted, len(targets), counts)
	return nil
}

// loadedFacts reads reachFacts off a target loaded with its IPs, each IP's
// newest port scan, and its newest CSP scan.
func loadedFacts(t *ent.Target) reachFacts {
	f := reachFacts{
		isIP:          t.IsIP,
		resolved:      len(t.Edges.Ips) > 0,
		resolveFailed: t.ResolveError != "",
		httpProbed:    len(t.Edges.CspScans) > 0,
	}
	for _, i := range t.Edges.Ips {
		if len(i.Edges.Scans) == 0 {
			continue
		}
		f.portsScanned = true
		f.portsOpen = f.portsOpen || len(i.Edges.Scans[0].Edges.Ports) > 0
	}
	if f.httpProbed {
		f.httpAnswered = t.Edges.CspScans[0].ProbeError == ""
	}
	return f
}

func (s *EntStorage) convertLegacyUnreachable(ctx context.Context) (int, error) {
	// Findings is a JSON blob, so match in Go. Only header-less rows can carry
	// the marker, which keeps the scan small.
	scans, err := s.client.CSPScan.Query().
		Where(cspscan.CspHeader(""), cspscan.Or(cspscan.ProbeErrorIsNil(), cspscan.ProbeError(""))).
		All(ctx)
	if err != nil {
		return 0, err
	}

	n := 0
	for _, sc := range scans {
		if !isLegacyUnreachable(sc.Findings) {
			continue
		}
		if err := s.client.CSPScan.UpdateOne(sc).
			ClearFindings().
			SetProbeError(legacyProbeError).
			Exec(ctx); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
