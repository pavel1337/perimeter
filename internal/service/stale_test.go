package service_test

import (
	"testing"
	"time"

	"perimeter/ent/cspscan"
	"perimeter/ent/predicate"
	"perimeter/ent/sslscan"
	"perimeter/ent/target"
	"perimeter/internal/service"
	"perimeter/internal/storage"
	"perimeter/scanner/csp"
)

func TestStale(t *testing.T) {
	now := time.Now()
	if service.Stale(now.Add(-90*time.Minute), time.Hour, now) {
		t.Error("1.5 intervals old is not stale")
	}
	if !service.Stale(now.Add(-3*time.Hour), time.Hour, now) {
		t.Error("3 intervals old is stale")
	}
	if service.Stale(time.Time{}, time.Hour, now) || service.Stale(now.Add(-100*time.Hour), 0, now) {
		t.Error("no time or no interval is never stale")
	}
}

// Results last checked over two intervals ago are marked stale and counted
// in the summary (issue #76).
func TestStaleResults(t *testing.T) {
	f := newFixture(t)
	f.svc.SetRescanConfig(time.Minute, true)
	f.svc.SetScanIntervals(service.ScanIntervals{Ports: time.Hour, SSL: 12 * time.Hour, CSP: time.Hour})
	f.target("old.example.com")
	f.target("fresh.example.com")
	for _, in := range []string{"old.example.com", "fresh.example.com"} {
		f.must(f.st.SaveSSLScan(f.ctx, in, storage.SSLResult{Grade: "A", Status: "READY"}))
		f.must(f.st.SaveCSPScan(f.ctx, in, "default-src 'self'", []csp.Finding{}))
	}
	f.must(f.st.SaveIPs(f.ctx, "old.example.com", []string{"192.0.2.1"}, time.Hour))
	f.must(f.st.SavePortScan(f.ctx, "192.0.2.1", []int{443}))

	// Age old.example.com's results: SSL 25h (> 2x12h), CSP and ports 3h.
	old := f.id("old.example.com")
	_, err := f.client.SSLScan.Update().Where(sslscanOf(old)).SetLastSeenAt(time.Now().Add(-25 * time.Hour)).Save(f.ctx)
	f.must(err)
	_, err = f.client.CSPScan.Update().Where(cspscanOf(old)).SetLastSeenAt(time.Now().Add(-3 * time.Hour)).Save(f.ctx)
	f.must(err)
	_, err = f.client.PortScan.Update().SetLastSeenAt(time.Now().Add(-3 * time.Hour)).Save(f.ctx)
	f.must(err)

	d, err := f.svc.GetTarget(f.ctx, old)
	f.must(err)
	if !d.SSL.Stale || !d.CSP.Stale || len(d.IPs) != 1 || !d.IPs[0].Stale {
		t.Errorf("old target: ssl=%v csp=%v ips=%+v, want all stale", d.SSL.Stale, d.CSP.Stale, d.IPs)
	}
	fresh, err := f.svc.GetTarget(f.ctx, f.id("fresh.example.com"))
	f.must(err)
	if fresh.SSL.Stale || fresh.CSP.Stale {
		t.Error("fresh target marked stale")
	}

	sum, err := f.svc.Summary(f.ctx, time.Now())
	f.must(err)
	if got := sum.Totals.Stale; got != (service.StaleTotals{SSL: 1, CSP: 1, Ports: 1}) {
		t.Errorf("stale totals = %+v, want 1 of each", got)
	}
}

func sslscanOf(id int) predicate.SSLScan { return sslscan.HasTargetWith(target.ID(id)) }
func cspscanOf(id int) predicate.CSPScan { return cspscan.HasTargetWith(target.ID(id)) }
