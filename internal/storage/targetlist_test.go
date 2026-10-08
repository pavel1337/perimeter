package storage_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"perimeter/ent/target"
	"perimeter/internal/storage"
	"perimeter/scanner/csp"
)

// fixtureRow describes one target, seeded through the public write API.
type fixtureRow struct {
	input      string
	hasIP      bool
	ports      []int // newest open ports on the IP
	grade      string
	expiry     time.Time
	csp        *int // findings in the newest CSP scan; nil means never probed
	probeErr   bool // newest CSP probe got no response
	resolveErr bool // resolution failed
}

func cspN(n int) *int { return &n }

// dashboardRows is the shared fixture. Expected values in the tests below are
// worked out by hand from it:
//
//	input  ports  grade  expiry  csp  reachability
//	a      3      A      +10d    2    ok
//	b      0      -      -       -    pending
//	c      5      B      +400d   0    ok
//	d      3      A+     -5d     2    ok (expired cert)
//	e      1      C      +25d    -    ok
//	f      3      A      +10d    0    ok
//	g      0      -      -       -    unreachable (probe got no response)
//	h      0      -      -       -    unresolved
func dashboardRows(now time.Time) []fixtureRow {
	in := func(days int) time.Time { return now.Add(time.Duration(days) * 24 * time.Hour) }
	return []fixtureRow{
		{input: "a.test", hasIP: true, ports: []int{22, 80, 443}, grade: "A", expiry: in(10), csp: cspN(2)},
		{input: "b.test", hasIP: true},
		{input: "c.test", hasIP: true, ports: []int{22, 23, 25, 80, 443}, grade: "B", expiry: in(400), csp: cspN(0)},
		{input: "d.test", hasIP: true, ports: []int{80, 443, 8080}, grade: "A+", expiry: in(-5), csp: cspN(2)},
		{input: "e.test", hasIP: true, ports: []int{8443}, grade: "C", expiry: in(25)},
		{input: "f.test", hasIP: true, ports: []int{22, 80, 8080}, grade: "A", expiry: in(10), csp: cspN(0)},
		{input: "g.test", probeErr: true},
		{input: "h.test", resolveErr: true},
	}
}

var ipSeq int

// seedTargets writes rows through the public API, so the summary columns are
// filled by the same write paths production uses.
func seedTargets(t *testing.T, s *storage.EntStorage, rows []fixtureRow) {
	t.Helper()
	ctx := context.Background()
	must := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	for _, r := range rows {
		_, err := s.ImportTargets(ctx, []string{r.input})
		must("ImportTargets "+r.input, err)
		if r.resolveErr {
			must("RecordResolveFailure "+r.input, s.RecordResolveFailure(ctx, r.input, "no such host"))
		}
		if r.hasIP {
			ipSeq++
			addr := fmt.Sprintf("10.1.%d.%d", ipSeq/250, ipSeq%250+1)
			must("SaveIPs "+r.input, s.SaveIPs(ctx, r.input, []string{addr}))
			must("SavePortScan "+r.input, s.SavePortScan(ctx, addr, r.ports))
		}
		if r.grade != "" {
			must("SaveSSLScan "+r.input, s.SaveSSLScan(ctx, r.input, storage.SSLResult{
				Grade:      r.grade,
				Status:     "READY",
				CertExpiry: r.expiry,
			}))
		}
		switch {
		case r.probeErr:
			must("SaveCSPUnreachable "+r.input, s.SaveCSPUnreachable(ctx, r.input, "connection refused"))
		case r.csp != nil:
			must("SaveCSPScan "+r.input, s.SaveCSPScan(ctx, r.input, "", make([]csp.Finding, *r.csp)))
		}
	}
}

func newDashboardStorage(t *testing.T) *storage.EntStorage {
	t.Helper()
	s := newTestStorage(t)
	seedTargets(t, s, dashboardRows(time.Now()))
	return s
}

func listInputs(t *testing.T, s *storage.EntStorage, f storage.TargetFilter, sort storage.TargetSort, limit, offset int) []string {
	t.Helper()
	ts, err := s.ListTargets(context.Background(), f, sort, limit, offset)
	if err != nil {
		t.Fatalf("ListTargets(%+v, %+v, %d, %d): %v", f, sort, limit, offset, err)
	}
	out := []string{}
	for _, tg := range ts {
		out = append(out, tg.Input)
	}
	return out
}

func assertInputs(t *testing.T, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestListTargetsFilters(t *testing.T) {
	s := newDashboardStorage(t)
	tests := []struct {
		name string
		f    storage.TargetFilter
		want []string
	}{
		{"no filter", storage.TargetFilter{}, []string{"a.test", "b.test", "c.test", "d.test", "e.test", "f.test", "g.test", "h.test"}},
		{"state unreachable", storage.TargetFilter{States: []target.Reachability{target.ReachabilityUnreachable}}, []string{"g.test"}},
		{"state unresolved", storage.TargetFilter{States: []target.Reachability{target.ReachabilityUnresolved}}, []string{"h.test"}},
		{"state pending", storage.TargetFilter{States: []target.Reachability{target.ReachabilityPending}}, []string{"b.test"}},
		{"states ok or unresolved", storage.TargetFilter{States: []target.Reachability{target.ReachabilityOk, target.ReachabilityUnresolved}}, []string{"a.test", "c.test", "d.test", "e.test", "f.test", "h.test"}},
		{"csp issues", storage.TargetFilter{CSP: "issues"}, []string{"a.test", "d.test"}},
		{"csp ok", storage.TargetFilter{CSP: "ok"}, []string{"c.test", "f.test"}},
		{"csp none", storage.TargetFilter{CSP: "none"}, []string{"b.test", "e.test", "g.test", "h.test"}},
		{"ssl grade A", storage.TargetFilter{SSLGrade: "A"}, []string{"a.test", "f.test"}},
		{"ssl grade A+", storage.TargetFilter{SSLGrade: "A+"}, []string{"d.test"}},
		{"ssl below A", storage.TargetFilter{SSLBelow: "A"}, []string{"c.test", "e.test"}},
		{"ssl below A+", storage.TargetFilter{SSLBelow: "A+"}, []string{"a.test", "c.test", "e.test", "f.test"}},
		{"ssl below C matches nothing", storage.TargetFilter{SSLBelow: "C"}, []string{}},
		{"port 443", storage.TargetFilter{Port: 443}, []string{"a.test", "c.test", "d.test"}},
		{"port 8080", storage.TargetFilter{Port: 8080}, []string{"d.test", "f.test"}},
		{"port 8443", storage.TargetFilter{Port: 8443}, []string{"e.test"}},
		{"port nobody has", storage.TargetFilter{Port: 9999}, []string{}},
		{"expiring within 30d includes expired", storage.TargetFilter{ExpiringWithin: 30 * 24 * time.Hour}, []string{"a.test", "d.test", "e.test", "f.test"}},
		{"expiring within 1h is only expired", storage.TargetFilter{ExpiringWithin: time.Hour}, []string{"d.test"}},
		{"combined: csp issues and expiring", storage.TargetFilter{CSP: "issues", ExpiringWithin: 30 * 24 * time.Hour}, []string{"a.test", "d.test"}},
		{"combined: ok state, csp issues, grade A", storage.TargetFilter{States: []target.Reachability{target.ReachabilityOk}, CSP: "issues", SSLGrade: "A"}, []string{"a.test"}},
		{"combined: ssl below A+ and port 443", storage.TargetFilter{SSLBelow: "A+", Port: 443}, []string{"a.test", "c.test"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertInputs(t, listInputs(t, s, tc.f, storage.TargetSort{}, 0, 0), tc.want)
		})
	}
}

func TestListTargetsSortEveryFieldBothDirections(t *testing.T) {
	s := newDashboardStorage(t)
	tests := []struct {
		name string
		sort storage.TargetSort
		want []string
	}{
		// Input: alphabetical either way.
		{"target asc", storage.TargetSort{Field: storage.SortTarget}, []string{"a.test", "b.test", "c.test", "d.test", "e.test", "f.test", "g.test", "h.test"}},
		{"target desc", storage.TargetSort{Field: storage.SortTarget, Desc: true}, []string{"h.test", "g.test", "f.test", "e.test", "d.test", "c.test", "b.test", "a.test"}},
		// Ports (count): ties on input; zero-port rows are real values, not NULL.
		{"ports asc", storage.TargetSort{Field: storage.SortPorts}, []string{"b.test", "g.test", "h.test", "e.test", "a.test", "d.test", "f.test", "c.test"}},
		{"ports desc", storage.TargetSort{Field: storage.SortPorts, Desc: true}, []string{"c.test", "a.test", "d.test", "f.test", "e.test", "b.test", "g.test", "h.test"}},
		// CSP: NULLs (b, e, g, h) last in both directions.
		{"csp asc", storage.TargetSort{Field: storage.SortCSP}, []string{"c.test", "f.test", "a.test", "d.test", "b.test", "e.test", "g.test", "h.test"}},
		{"csp desc", storage.TargetSort{Field: storage.SortCSP, Desc: true}, []string{"a.test", "d.test", "c.test", "f.test", "b.test", "e.test", "g.test", "h.test"}},
		// SSL: ascending is best first; ungraded (b, g, h) last in both directions.
		{"ssl asc (best first)", storage.TargetSort{Field: storage.SortSSL}, []string{"d.test", "a.test", "f.test", "c.test", "e.test", "b.test", "g.test", "h.test"}},
		{"ssl desc (worst first)", storage.TargetSort{Field: storage.SortSSL, Desc: true}, []string{"e.test", "c.test", "a.test", "f.test", "d.test", "b.test", "g.test", "h.test"}},
		// Expiry: asc soonest first; NULLs (b, g, h) last in both directions.
		{"expiry asc (soonest first)", storage.TargetSort{Field: storage.SortExpiry}, []string{"d.test", "a.test", "f.test", "e.test", "c.test", "b.test", "g.test", "h.test"}},
		{"expiry desc (latest first)", storage.TargetSort{Field: storage.SortExpiry, Desc: true}, []string{"c.test", "e.test", "a.test", "f.test", "d.test", "b.test", "g.test", "h.test"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertInputs(t, listInputs(t, s, storage.TargetFilter{}, tc.sort, 0, 0), tc.want)
		})
	}
}

func TestListTargetsPagingIsDisjointAndOrdered(t *testing.T) {
	s := newDashboardStorage(t)
	sort := storage.TargetSort{Field: storage.SortExpiry}
	full := listInputs(t, s, storage.TargetFilter{}, sort, 0, 0)
	if len(full) != 8 {
		t.Fatalf("full list has %d rows, want 8", len(full))
	}

	var paged []string
	pages := [][]string{
		listInputs(t, s, storage.TargetFilter{}, sort, 3, 0),
		listInputs(t, s, storage.TargetFilter{}, sort, 3, 3),
		listInputs(t, s, storage.TargetFilter{}, sort, 3, 6),
	}
	assertInputs(t, pages[0], []string{"d.test", "a.test", "f.test"})
	assertInputs(t, pages[1], []string{"e.test", "c.test", "b.test"})
	assertInputs(t, pages[2], []string{"g.test", "h.test"})
	for _, p := range pages {
		paged = append(paged, p...)
	}
	assertInputs(t, paged, full)

	// Offset without a limit: everything after the offset.
	assertInputs(t, listInputs(t, s, storage.TargetFilter{}, sort, 0, 6), []string{"g.test", "h.test"})
}

func TestListTargetsFilterAndSortTogether(t *testing.T) {
	s := newDashboardStorage(t)
	// Filter first, then order: only the matches are sorted.
	got := listInputs(t, s, storage.TargetFilter{CSP: "issues", ExpiringWithin: 30 * 24 * time.Hour},
		storage.TargetSort{Field: storage.SortSSL, Desc: true}, 0, 0)
	assertInputs(t, got, []string{"a.test", "d.test"})
	got = listInputs(t, s, storage.TargetFilter{Port: 443},
		storage.TargetSort{Field: storage.SortPorts}, 0, 0)
	assertInputs(t, got, []string{"a.test", "d.test", "c.test"})
}

func TestListTargetsLoadsDetails(t *testing.T) {
	s := newDashboardStorage(t)
	ts, err := s.ListTargets(context.Background(), storage.TargetFilter{Port: 8443}, storage.TargetSort{}, 0, 0)
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(ts) != 1 {
		t.Fatalf("got %d targets, want 1", len(ts))
	}
	tg := ts[0]
	if len(tg.Edges.Ips) != 1 || len(tg.Edges.Ips[0].Edges.Scans) != 1 {
		t.Fatalf("IPs or newest scans not loaded: %+v", tg.Edges.Ips)
	}
	if ports := tg.Edges.Ips[0].Edges.Scans[0].Edges.Ports; len(ports) != 1 || ports[0].Number != 8443 {
		t.Errorf("ports = %v, want [8443]", ports)
	}
	if len(tg.Edges.SslScans) != 1 || tg.Edges.SslScans[0].Grade != "C" {
		t.Errorf("SSL scan not loaded: %+v", tg.Edges.SslScans)
	}
}

func TestListTargetsPortOnlyNewestScanCounts(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	if _, err := s.ImportTargets(ctx, []string{"old.test", "new.test"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}

	// old.test had 443 open in an older scan, closed in the newest one.
	if err := s.SaveIPs(ctx, "old.test", []string{"10.2.0.1"}); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}
	if err := s.SavePortScan(ctx, "10.2.0.1", []int{443}); err != nil {
		t.Fatalf("SavePortScan: %v", err)
	}
	if err := s.SavePortScan(ctx, "10.2.0.1", []int{80}); err != nil {
		t.Fatalf("SavePortScan: %v", err)
	}

	// new.test has 443 open in its only, newest scan.
	if err := s.SaveIPs(ctx, "new.test", []string{"10.2.0.2"}); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}
	if err := s.SavePortScan(ctx, "10.2.0.2", []int{443}); err != nil {
		t.Fatalf("SavePortScan: %v", err)
	}

	assertInputs(t, listInputs(t, s, storage.TargetFilter{Port: 443}, storage.TargetSort{}, 0, 0), []string{"new.test"})
	assertInputs(t, listInputs(t, s, storage.TargetFilter{Port: 80}, storage.TargetSort{}, 0, 0), []string{"old.test"})

	stats, err := s.TargetStats(ctx, storage.TargetFilter{Port: 443}, time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("TargetStats: %v", err)
	}
	if stats.Total != 1 {
		t.Errorf("stats.Total with port 443 = %d, want 1", stats.Total)
	}
}

func TestListTargetsInvalidArguments(t *testing.T) {
	s := newDashboardStorage(t)
	ctx := context.Background()

	if _, err := s.ListTargets(ctx, storage.TargetFilter{CSP: "bogus"}, storage.TargetSort{}, 0, 0); !errors.Is(err, storage.ErrInvalidCSPFilter) {
		t.Errorf("CSP bogus: err = %v, want ErrInvalidCSPFilter", err)
	}
	if _, err := s.ListTargets(ctx, storage.TargetFilter{SSLBelow: "Z"}, storage.TargetSort{}, 0, 0); !errors.Is(err, storage.ErrInvalidGrade) {
		t.Errorf("SSLBelow Z: err = %v, want ErrInvalidGrade", err)
	}
	if _, err := s.ListTargets(ctx, storage.TargetFilter{}, storage.TargetSort{Field: "bogus"}, 0, 0); !errors.Is(err, storage.ErrInvalidSort) {
		t.Errorf("sort bogus: err = %v, want ErrInvalidSort", err)
	}
	// Empty SSLBelow is "no constraint", not an invalid grade.
	if _, err := s.ListTargets(ctx, storage.TargetFilter{SSLBelow: ""}, storage.TargetSort{}, 0, 0); err != nil {
		t.Errorf("empty SSLBelow: err = %v, want nil", err)
	}
}

func TestTargetStatsFilters(t *testing.T) {
	s := newDashboardStorage(t)
	ctx := context.Background()
	now := time.Now()
	window := 30 * 24 * time.Hour
	tests := []struct {
		name string
		f    storage.TargetFilter
		now  time.Time
		want storage.TargetStats
	}{
		// Expiring: a (+10d), e (+25d), f (+10d). d is expired, c is outside.
		// CSP issues: a and d. Open ports: 3+0+5+3+1+3+0+0.
		{"all", storage.TargetFilter{}, now, storage.TargetStats{Total: 8, OpenPorts: 15, ExpiringCerts: 3, CSPIssues: 2}},
		{"states ok", storage.TargetFilter{States: []target.Reachability{target.ReachabilityOk}}, now,
			storage.TargetStats{Total: 5, OpenPorts: 15, ExpiringCerts: 3, CSPIssues: 2}},
		{"csp ok", storage.TargetFilter{CSP: "ok"}, now, storage.TargetStats{Total: 2, OpenPorts: 8, ExpiringCerts: 1, CSPIssues: 0}},
		{"port 8443", storage.TargetFilter{Port: 8443}, now, storage.TargetStats{Total: 1, OpenPorts: 1, ExpiringCerts: 1, CSPIssues: 0}},
		// The clock moves to +20d: e (+25d) is the only certificate left in
		// the window, and a and f have already expired.
		{"later now", storage.TargetFilter{}, now.Add(20 * 24 * time.Hour), storage.TargetStats{Total: 8, OpenPorts: 15, ExpiringCerts: 1, CSPIssues: 2}},
		// Empty match set: zeros, no error.
		{"empty match", storage.TargetFilter{CSP: "none", SSLGrade: "A+"}, now, storage.TargetStats{}},
		{"no such port", storage.TargetFilter{Port: 9999}, now, storage.TargetStats{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.TargetStats(ctx, tc.f, tc.now, window)
			if err != nil {
				t.Fatalf("TargetStats: %v", err)
			}
			if got != tc.want {
				t.Errorf("TargetStats = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestTargetStatsIsOverAllMatchesNotAPage(t *testing.T) {
	s := newDashboardStorage(t)
	ctx := context.Background()
	f := storage.TargetFilter{}

	page := listInputs(t, s, f, storage.TargetSort{Field: storage.SortTarget}, 2, 0)
	if len(page) != 2 {
		t.Fatalf("page has %d rows, want 2", len(page))
	}
	stats, err := s.TargetStats(ctx, f, time.Now(), 30*24*time.Hour)
	if err != nil {
		t.Fatalf("TargetStats: %v", err)
	}
	if stats.Total != 8 {
		t.Errorf("stats.Total = %d, want 8 (all matches, not the page of 2)", stats.Total)
	}
}

func TestTargetStatsInvalidArguments(t *testing.T) {
	s := newDashboardStorage(t)
	ctx := context.Background()
	if _, err := s.TargetStats(ctx, storage.TargetFilter{CSP: "bogus"}, time.Now(), time.Hour); !errors.Is(err, storage.ErrInvalidCSPFilter) {
		t.Errorf("CSP bogus: err = %v, want ErrInvalidCSPFilter", err)
	}
	if _, err := s.TargetStats(ctx, storage.TargetFilter{SSLBelow: "Z"}, time.Now(), time.Hour); !errors.Is(err, storage.ErrInvalidGrade) {
		t.Errorf("SSLBelow Z: err = %v, want ErrInvalidGrade", err)
	}
}
