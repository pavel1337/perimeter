package service

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"perimeter/ent"
	"perimeter/ent/cspscan"
	"perimeter/ent/dnschange"
	"perimeter/ent/ip"
	"perimeter/ent/portscan"
	"perimeter/ent/schema"
	"perimeter/ent/sslscan"
	"perimeter/ent/target"
	"perimeter/internal/storage"
	"perimeter/scanner/csp"
)

// Change kinds.
const (
	ChangeTargetAdded       = "target_added"
	ChangeTargetDeleted     = "target_deleted"
	ChangeSSLGradeChanged   = "ssl_grade_changed"
	ChangeCertRenewed       = "cert_renewed"
	ChangePortsOpened       = "ports_opened"
	ChangePortsClosed       = "ports_closed"
	ChangeCSPChanged        = "csp_changed"
	ChangeBecameUnreachable = "became_unreachable"
	ChangeBecameReachable   = "became_reachable"
	// ChangeDNSChanged: a name moved to other IPs, no longer resolves, or
	// resolves again (issue #74).
	ChangeDNSChanged = "dns_changed"
)

// Change is one thing that happened to a target, dated when it was first
// observed. From and To carry the before and after values where the kind has
// them; IP is set for port and reachability changes.
type Change struct {
	At       time.Time `json:"at"`
	TargetID int       `json:"target_id"`
	Target   string    `json:"target"`
	Kind     string    `json:"kind"`
	From     string    `json:"from,omitempty"`
	To       string    `json:"to,omitempty"`
	IP       string    `json:"ip,omitempty"`
	Summary  string    `json:"summary"`
}

// ChangesSince lists the changes observed after since, oldest first. The
// limit defaults to 200 and is capped at 1000; truncated reports whether more
// changes followed the returned ones.
func (s *Service) ChangesSince(ctx context.Context, since time.Time, limit int) ([]Change, bool, error) {
	limit = clampLimit(limit, 200, 1000)
	// SQLite stores times as text with the server's local offset, so the
	// bound must carry that offset to compare correctly.
	since = since.Local()
	all, err := s.allChangesSince(ctx, since)
	if err != nil {
		return nil, false, err
	}
	// Stored text carries a monotonic suffix that a parsed bound lacks, so the
	// change at exactly since compares as newer. A poll wants strictly after.
	all = slices.DeleteFunc(all, func(c Change) bool { return !c.At.After(since) })
	if len(all) <= limit {
		return all, false, nil
	}
	cut := pageCut(all, limit)
	return all[:cut], cut < len(all), nil
}

// pageCut picks where a page of more than limit changes ends. The next poll
// starts strictly after the last change's time, so a page must not split
// changes that share a time: it ends before such a group, or, when the group
// fills the whole page, after it.
func pageCut(all []Change, limit int) int {
	at := all[limit-1].At
	if !all[limit].At.Equal(at) {
		return limit
	}
	cut := limit - 1
	for cut > 0 && all[cut-1].At.Equal(at) {
		cut--
	}
	if cut > 0 {
		return cut
	}
	for cut = limit; cut < len(all) && all[cut].At.Equal(at); cut++ {
	}
	return cut
}

// allChangesSince is ChangesSince without the cap, oldest first.
func (s *Service) allChangesSince(ctx context.Context, since time.Time) ([]Change, error) {
	var out []Change
	for _, collect := range []func(context.Context, time.Time) ([]Change, error){
		s.targetChanges,
		s.sslChanges,
		s.cspChanges,
		s.portChanges,
		s.dnsChanges,
	} {
		cs, err := collect(ctx, since)
		if err != nil {
			return nil, err
		}
		out = append(out, cs...)
	}
	slices.SortStableFunc(out, func(a, b Change) int { return a.At.Compare(b.At) })
	return out, nil
}

// newChange fills the fields every change shares.
func newChange(tg *ent.Target, at time.Time, kind, from, to, ip, summary string) Change {
	return Change{
		At:       at,
		TargetID: tg.ID,
		Target:   tg.Input,
		Kind:     kind,
		From:     from,
		To:       to,
		IP:       ip,
		Summary:  summary,
	}
}

// targetChanges reports targets added and deleted after since. Soft-deleted
// rows are read on purpose: deleting a target is itself a change.
func (s *Service) targetChanges(ctx context.Context, since time.Time) ([]Change, error) {
	ctx = schema.SkipSoftDelete(ctx)
	added, err := s.client.Target.Query().Where(target.CreateTimeGT(since)).All(ctx)
	if err != nil {
		return nil, err
	}
	deleted, err := s.client.Target.Query().Where(target.DeletedAtGT(since)).All(ctx)
	if err != nil {
		return nil, err
	}
	var out []Change
	for _, t := range added {
		out = append(out, newChange(t, t.CreateTime, ChangeTargetAdded, "", "", "", t.Input+" added"))
	}
	for _, t := range deleted {
		out = append(out, newChange(t, *t.DeletedAt, ChangeTargetDeleted, "", "", "", t.Input+" deleted"))
	}
	return out, nil
}

// dnsChanges reports the re-resolves recorded after since (issue #74). Names
// behind CDNs rotate their IPs, so a change that keeps one of the old IPs is
// left to the target's history; the feed reports a name that moved away
// from all of its IPs, stopped resolving, or resolves again.
func (s *Service) dnsChanges(ctx context.Context, since time.Time) ([]Change, error) {
	rows, err := s.client.DNSChange.Query().
		Where(dnschange.ChangedAtGT(since), dnschange.HasTargetWith(target.DeletedAtIsNil())).
		Order(ent.Asc(dnschange.FieldChangedAt), ent.Asc(dnschange.FieldID)).
		WithTarget().
		All(ctx)
	if err != nil {
		return nil, err
	}
	var out []Change
	for _, dc := range rows {
		tg := dc.Edges.Target
		if tg == nil || (dc.Kind == dnschange.KindChanged && !dnsMovedAway(dc)) {
			continue
		}
		out = append(out, newChange(tg, dc.ChangedAt, ChangeDNSChanged,
			strings.Join(dc.Removed, ", "), strings.Join(dc.Added, ", "), "",
			tg.Input+": "+DNSChangeSummary(dc)))
	}
	return out, nil
}

// dnsMovedAway reports whether a change kept none of the old IPs.
func dnsMovedAway(dc *ent.DNSChange) bool {
	return dc.Kept == 0 && len(dc.Added) > 0
}

// DNSChangeSummary describes a DNS change in a few words.
func DNSChangeSummary(dc *ent.DNSChange) string {
	switch dc.Kind {
	case dnschange.KindGone:
		return "name no longer resolves (was " + strings.Join(dc.Removed, ", ") + ")"
	case dnschange.KindBack:
		return "resolves again, to " + strings.Join(dc.Added, ", ")
	}
	var parts []string
	if len(dc.Removed) > 0 {
		parts = append(parts, strings.Join(dc.Removed, ", "))
	}
	switch {
	case len(dc.Removed) > 0 && len(dc.Added) > 0:
		return "DNS moved from " + parts[0] + " to " + strings.Join(dc.Added, ", ")
	case len(dc.Added) > 0:
		return "DNS added " + strings.Join(dc.Added, ", ")
	default:
		return "DNS removed " + parts[0]
	}
}

// sslChanges compares each SSL row written after since with the row before
// it for the same target. Rows are only written when the result changes, so
// a row is a change; the first grade ever is a change from none. Failed
// checks are skipped on both sides, so A → (error) → A is no change (#61).
func (s *Service) sslChanges(ctx context.Context, since time.Time) ([]Change, error) {
	result := sslscan.Not(sslscan.StatusHasPrefix(storage.SSLErrorPrefix))
	rows, err := s.client.SSLScan.Query().
		Where(sslscan.ScannedAtGT(since), sslscan.HasTargetWith(target.DeletedAtIsNil()), result).
		Order(ent.Asc(sslscan.FieldScannedAt), ent.Asc(sslscan.FieldID)).
		WithTarget().
		All(ctx)
	if err != nil {
		return nil, err
	}
	prev := make(map[int]*ent.SSLScan)
	var out []Change
	for _, sc := range rows {
		tg := sc.Edges.Target
		if tg == nil {
			continue
		}
		if _, ok := prev[tg.ID]; !ok {
			base, err := s.client.SSLScan.Query().
				Where(sslscan.HasTargetWith(target.ID(tg.ID)), sslscan.ScannedAtLTE(since), result).
				Order(ent.Desc(sslscan.FieldScannedAt), ent.Desc(sslscan.FieldID)).
				First(ctx)
			if err != nil && !ent.IsNotFound(err) {
				return nil, err
			}
			prev[tg.ID] = base
		}
		out = append(out, sslTransitions(tg, prev[tg.ID], sc)...)
		prev[tg.ID] = sc
	}
	return out, nil
}

// sslHistorySummary describes what an SSL row changed against the previous
// result, with the same comparison as sslTransitions (issue #78): a new row
// is also written when only the certificate changes, so "grade A → A" was
// wrong for a renewal.
func sslHistorySummary(p, r *ent.SSLScan) string {
	var parts []string
	if p.Grade != r.Grade {
		parts = append(parts, fmt.Sprintf("grade %s → %s", orNone(p.Grade), orNone(r.Grade)))
	}
	if !p.CertExpiry.IsZero() && r.CertExpiry.After(p.CertExpiry) {
		parts = append(parts, "certificate renewed, now expires "+r.CertExpiry.Format("2006-01-02"))
	}
	if len(parts) == 0 {
		return "certificate changed"
	}
	return strings.Join(parts, "; ")
}

// sslTransitions returns what changed between the previous SSL row p (nil if
// none) and the new row r.
func sslTransitions(tg *ent.Target, p, r *ent.SSLScan) []Change {
	if p == nil {
		if r.Grade == "" {
			return nil
		}
		return []Change{newChange(tg, r.ScannedAt, ChangeSSLGradeChanged, "", r.Grade,
			"", fmt.Sprintf("%s: SSL grade %s", tg.Input, r.Grade))}
	}
	var out []Change
	if p.Grade != r.Grade {
		out = append(out, newChange(tg, r.ScannedAt, ChangeSSLGradeChanged, p.Grade, r.Grade, "",
			fmt.Sprintf("%s: SSL grade %s → %s", tg.Input, orNone(p.Grade), orNone(r.Grade))))
	}
	// Only a later expiry counts as a renewal; a shorter one is not a
	// renewal and a zero one means the scan had no expiry.
	if !p.CertExpiry.IsZero() && r.CertExpiry.After(p.CertExpiry) {
		out = append(out, newChange(tg, r.ScannedAt, ChangeCertRenewed,
			p.CertExpiry.Format(time.RFC3339), r.CertExpiry.Format(time.RFC3339), "",
			fmt.Sprintf("%s: certificate renewed, now expires %s", tg.Input, r.CertExpiry.Format("2006-01-02"))))
	}
	return out
}

// cspChanges compares each CSP row written after since with the row before it
// for the same target. A target's first evaluation is a change from not
// checked, like a first SSL grade.
func (s *Service) cspChanges(ctx context.Context, since time.Time) ([]Change, error) {
	rows, err := s.client.CSPScan.Query().
		Where(cspscan.ScannedAtGT(since), cspscan.HasTargetWith(target.DeletedAtIsNil())).
		Order(ent.Asc(cspscan.FieldScannedAt), ent.Asc(cspscan.FieldID)).
		WithTarget().
		All(ctx)
	if err != nil {
		return nil, err
	}
	prev := make(map[int]*ent.CSPScan)
	var out []Change
	for _, sc := range rows {
		tg := sc.Edges.Target
		if tg == nil {
			continue
		}
		if _, ok := prev[tg.ID]; !ok {
			base, err := s.client.CSPScan.Query().
				Where(cspscan.HasTargetWith(target.ID(tg.ID)), cspscan.ScannedAtLTE(since)).
				Order(ent.Desc(cspscan.FieldScannedAt), ent.Desc(cspscan.FieldID)).
				First(ctx)
			if err != nil && !ent.IsNotFound(err) {
				return nil, err
			}
			prev[tg.ID] = base
		}
		if p := prev[tg.ID]; p == nil {
			out = append(out, cspFirstChange(tg, sc))
		} else if c, ok := cspChange(tg, p, sc); ok {
			out = append(out, c)
		}
		prev[tg.ID] = sc
	}
	return out, nil
}

// cspState describes a CSP row in a few words: the probe error, an error
// page, or a finding count.
func cspState(sc *ent.CSPScan) string {
	if sc.ProbeError != "" {
		return cspNoResponse(sc.ProbeError)
	}
	if sc.RedirectHost != "" {
		return "redirects to " + sc.RedirectHost
	}
	if code, ok := storage.CSPNoApp(sc); ok {
		return fmt.Sprintf("no application served (%d)", code)
	}
	return findingCount(len(sc.Findings))
}

// cspFirstChange reports a target's first CSP result: from not checked to the
// new state.
func cspFirstChange(tg *ent.Target, r *ent.CSPScan) Change {
	after := cspState(r)
	return newChange(tg, r.ScannedAt, ChangeCSPChanged, "not checked", after, "",
		fmt.Sprintf("%s: CSP not checked → %s", tg.Input, after))
}

// findingCount renders a findings count in the right plural: "1 finding",
// "3 findings".
func findingCount(n int) string {
	if n == 1 {
		return "1 finding"
	}
	return fmt.Sprintf("%d findings", n)
}

// cspNoResponse is how a probe error reads: "no response (timed out)".
func cspNoResponse(probeErr string) string {
	if probeErr == "" || probeErr == "no response" {
		return "no response"
	}
	return "no response (" + probeErr + ")"
}

// cspChange reports what changed between CSP rows p and r, if it is worth a
// change (issue #69). One probe error after another is not: the target was
// unreachable before and still is. "Policy changed" is only said when both
// rows got an answer and the header changed but the state reads the same.
func cspChange(tg *ent.Target, p, r *ent.CSPScan) (Change, bool) {
	if p.ProbeError != "" && r.ProbeError != "" {
		return Change{}, false
	}
	before, after := cspState(p), cspState(r)
	summary := fmt.Sprintf("%s: CSP %s → %s", tg.Input, before, after)
	if before == after {
		if csp.MaskNonces(p.CspHeader) == csp.MaskNonces(r.CspHeader) {
			// Only the status, URL or certificate note moved.
			return Change{}, false
		}
		summary = tg.Input + ": CSP policy changed"
	}
	return newChange(tg, r.ScannedAt, ChangeCSPChanged, before, after, "", summary), true
}

// portState is what a port-scan baseline needs: the previous row of an IP,
// and the previous row that answered (no scan error).
type portState struct {
	last   *ent.PortScan
	lastOK *ent.PortScan
}

// portChanges compares each port scan row written after since with the row
// before it for the same IP, and fans every change out to the live targets
// sharing that IP. A row with a scan error is a transition to or from
// unreachable; port diffs are taken against the last row that answered.
func (s *Service) portChanges(ctx context.Context, since time.Time) ([]Change, error) {
	rows, err := s.client.PortScan.Query().
		Where(portscan.ScannedAtGT(since), portscan.HasIPWith(ip.HasTargetsWith(target.DeletedAtIsNil()))).
		Order(ent.Asc(portscan.FieldScannedAt), ent.Asc(portscan.FieldID)).
		WithIP(func(q *ent.IPQuery) { q.WithTargets() }).
		WithPorts().
		All(ctx)
	if err != nil {
		return nil, err
	}
	states := make(map[int]*portState)
	var out []Change
	for _, sc := range rows {
		addr := sc.Edges.IP
		st, ok := states[addr.ID]
		if !ok {
			st, err = s.portBaseline(ctx, addr.ID, since)
			if err != nil {
				return nil, err
			}
			states[addr.ID] = st
		}
		out = append(out, portTransitions(addr, st, sc)...)
		st.last = sc
		if sc.ScanError == "" {
			st.lastOK = sc
		}
	}
	return out, nil
}

// portBaseline loads the state of an IP just before since.
func (s *Service) portBaseline(ctx context.Context, ipID int, since time.Time) (*portState, error) {
	last, err := s.client.PortScan.Query().
		Where(portscan.HasIPWith(ip.ID(ipID)), portscan.ScannedAtLTE(since)).
		Order(ent.Desc(portscan.FieldScannedAt), ent.Desc(portscan.FieldID)).
		WithPorts().
		First(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return nil, err
	}
	st := &portState{last: last}
	switch {
	case last == nil:
	case last.ScanError == "":
		st.lastOK = last
	default:
		st.lastOK, err = s.client.PortScan.Query().
			Where(
				portscan.HasIPWith(ip.ID(ipID)),
				portscan.ScannedAtLTE(since),
				portscan.Or(portscan.ScanErrorIsNil(), portscan.ScanError("")),
			).
			Order(ent.Desc(portscan.FieldScannedAt), ent.Desc(portscan.FieldID)).
			WithPorts().
			First(ctx)
		if err != nil && !ent.IsNotFound(err) {
			return nil, err
		}
	}
	return st, nil
}

// portTransitions returns what changed on an IP between its previous row
// (st.last) and the new row r. On an IP's first answered scan every open
// port counts as opened, so a new target's ports show up in a poll.
func portTransitions(addr *ent.IP, st *portState, r *ent.PortScan) []Change {
	var out []Change
	for _, tg := range addr.Edges.Targets {
		switch {
		case st.last == nil:
		case r.ScanError != "" && st.last.ScanError == "":
			out = append(out, newChange(tg, r.ScannedAt, ChangeBecameUnreachable, "reachable", "unreachable", addr.Address,
				fmt.Sprintf("%s: %s unreachable (%s)", tg.Input, addr.Address, r.ScanError)))
		case r.ScanError == "" && st.last.ScanError != "":
			out = append(out, newChange(tg, r.ScannedAt, ChangeBecameReachable, "unreachable", "reachable", addr.Address,
				fmt.Sprintf("%s: %s reachable again", tg.Input, addr.Address)))
		}
	}
	if r.ScanError != "" {
		return out
	}
	var prev []int
	if st.lastOK != nil {
		prev = portNumbers(st.lastOK)
	}
	added, removed := portDelta(prev, portNumbers(r))
	for _, tg := range addr.Edges.Targets {
		if len(added) > 0 {
			out = append(out, newChange(tg, r.ScannedAt, ChangePortsOpened, "", joinInts(added), addr.Address,
				fmt.Sprintf("%s: %s %s opened on %s", tg.Input, portNoun(added), joinInts(added), addr.Address)))
		}
		if len(removed) > 0 {
			out = append(out, newChange(tg, r.ScannedAt, ChangePortsClosed, joinInts(removed), "", addr.Address,
				fmt.Sprintf("%s: %s %s closed on %s", tg.Input, portNoun(removed), joinInts(removed), addr.Address)))
		}
	}
	return out
}

func portNoun(ports []int) string {
	if len(ports) == 1 {
		return "port"
	}
	return "ports"
}

// portDelta returns the ports in cur but not prev, and the reverse. Both
// lists are short, so membership is a linear scan.
func portDelta(prev, cur []int) (added, removed []int) {
	for _, p := range cur {
		if !slices.Contains(prev, p) {
			added = append(added, p)
		}
	}
	for _, p := range prev {
		if !slices.Contains(cur, p) {
			removed = append(removed, p)
		}
	}
	return added, removed
}
