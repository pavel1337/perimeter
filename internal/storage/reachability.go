package storage

import (
	"context"
	"log"

	"perimeter/ent"
	"perimeter/ent/cspscan"
	"perimeter/ent/target"
	"perimeter/scanner/csp"
)

// reachFacts is what reachability is decided from, read off the newest scans
// by loadedFacts as part of summarize.
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
// finding onto probe_error, then rebuilds every target's summary, which
// includes reachability. Both steps overwrite with values computed from the
// data, so a rerun after a crash just recomputes them.
func (s *EntStorage) BackfillReachability(ctx context.Context) error {
	converted, err := s.convertLegacyUnreachable(ctx)
	if err != nil {
		return err
	}
	log.Printf("Backfill (reachability): converted %d legacy CSP rows", converted)

	return s.BackfillSummary(ctx)
}

// loadedFacts reads reachFacts off a target loaded as summarize expects.
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
