package storage_test

import (
	"context"
	"testing"

	"perimeter/ent"
	"perimeter/ent/target"
	"perimeter/internal/storage"
	"perimeter/scanner/csp"
)

func reachabilityOf(t *testing.T, s *storage.EntStorage, input string) target.Reachability {
	t.Helper()
	targets, err := s.GetTargets(context.Background())
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	for _, tg := range targets {
		if tg.Input == input {
			return tg.Reachability
		}
	}
	t.Fatalf("target %s not found", input)
	return ""
}

func TestReachabilityLifecycle(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	step := func(name string, want target.Reachability) {
		t.Helper()
		if got := reachabilityOf(t, s, "example.com"); got != want {
			t.Errorf("%s: reachability = %s, want %s", name, got, want)
		}
	}

	step("imported", target.ReachabilityPending)

	if err := s.RecordResolveFailure(ctx, "example.com", "no such host (NXDOMAIN)"); err != nil {
		t.Fatalf("RecordResolveFailure: %v", err)
	}
	step("resolve failed", target.ReachabilityUnresolved)

	if err := s.SaveIPs(ctx, "example.com", []string{"10.0.0.1"}); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}
	step("resolved, not probed", target.ReachabilityPending)

	if err := s.SaveCSPUnreachable(ctx, "example.com", "connection refused"); err != nil {
		t.Fatalf("SaveCSPUnreachable: %v", err)
	}
	step("probe got no response", target.ReachabilityUnreachable)

	// Re-resolving says nothing about whether it answers.
	if err := s.SaveIPs(ctx, "example.com", []string{"10.0.0.1"}); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}
	step("re-resolved", target.ReachabilityUnreachable)

	if err := s.SaveCSPScan(ctx, "example.com", "default-src 'self'", nil); err != nil {
		t.Fatalf("SaveCSPScan: %v", err)
	}
	step("probe answered", target.ReachabilityOk)
}

func TestSaveCSPUnreachableHasNoFindings(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	for range 2 {
		if err := s.SaveCSPUnreachable(ctx, "example.com", "timed out"); err != nil {
			t.Fatalf("SaveCSPUnreachable: %v", err)
		}
	}
	// A different reason is a different result, so it starts a new row.
	if err := s.SaveCSPUnreachable(ctx, "example.com", "connection refused"); err != nil {
		t.Fatalf("SaveCSPUnreachable: %v", err)
	}

	targets, _ := s.GetTargets(ctx)
	scans, total, err := s.GetCSPScansPage(ctx, targets[0].ID, 10, 0)
	if err != nil {
		t.Fatalf("GetCSPScansPage: %v", err)
	}
	if total != 2 {
		t.Fatalf("rows = %d, want 2 (identical probes collapse)", total)
	}
	if scans[0].ProbeError != "connection refused" || scans[1].ProbeError != "timed out" {
		t.Errorf("probe errors = %q, %q", scans[0].ProbeError, scans[1].ProbeError)
	}
	if scans[1].CheckCount != 2 {
		t.Errorf("timed out row check_count = %d, want 2", scans[1].CheckCount)
	}
	for _, sc := range scans {
		if len(sc.Findings) != 0 {
			t.Errorf("unreachable scan carries findings: %v", sc.Findings)
		}
	}

	// Coming back up must not collapse onto the unreachable row.
	if err := s.SaveCSPScan(ctx, "example.com", "", []csp.Finding{{Description: "No Content-Security-Policy header found."}}); err != nil {
		t.Fatalf("SaveCSPScan: %v", err)
	}
	if _, total, _ := s.GetCSPScansPage(ctx, targets[0].ID, 10, 0); total != 3 {
		t.Errorf("rows = %d, want 3", total)
	}
}

func TestPortScanReachability(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"10.0.0.1", "mail.example"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	for _, in := range []string{"10.0.0.1", "mail.example"} {
		if err := s.SaveIPs(ctx, in, []string{"10.0.0.1"}); err != nil {
			t.Fatalf("SaveIPs: %v", err)
		}
	}
	check := func(name string, wantIP, wantDomain target.Reachability) {
		t.Helper()
		if got := reachabilityOf(t, s, "10.0.0.1"); got != wantIP {
			t.Errorf("%s: bare IP = %s, want %s", name, got, wantIP)
		}
		if got := reachabilityOf(t, s, "mail.example"); got != wantDomain {
			t.Errorf("%s: domain = %s, want %s", name, got, wantDomain)
		}
	}

	if err := s.SavePortScan(ctx, "10.0.0.1", nil); err != nil {
		t.Fatalf("SavePortScan: %v", err)
	}
	// The port scan is the bare IP's only check; the domain still has its
	// HTTP probe to come.
	check("nothing open", target.ReachabilityUnreachable, target.ReachabilityPending)

	if err := s.SavePortScan(ctx, "10.0.0.1", []int{25}); err != nil {
		t.Fatalf("SavePortScan: %v", err)
	}
	check("port open", target.ReachabilityOk, target.ReachabilityOk)

	// A mail server with no website still answers.
	if err := s.SaveCSPUnreachable(ctx, "mail.example", "connection refused"); err != nil {
		t.Fatalf("SaveCSPUnreachable: %v", err)
	}
	check("no HTTP, port open", target.ReachabilityOk, target.ReachabilityOk)

	if err := s.SavePortScan(ctx, "10.0.0.1", nil); err != nil {
		t.Fatalf("SavePortScan: %v", err)
	}
	check("nothing answers", target.ReachabilityUnreachable, target.ReachabilityUnreachable)

	// A newly resolved target picks up the scans already on its IP.
	if _, err := s.ImportTargets(ctx, []string{"www.example"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	if err := s.SavePortScan(ctx, "10.0.0.1", []int{443}); err != nil {
		t.Fatalf("SavePortScan: %v", err)
	}
	if err := s.SaveIPs(ctx, "www.example", []string{"10.0.0.1"}); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}
	if got := reachabilityOf(t, s, "www.example"); got != target.ReachabilityOk {
		t.Errorf("resolved onto an open IP: %s, want ok", got)
	}
}

func TestGetTargetsFiltersByReachability(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"up.example", "down.example", "gone.example", "new.example"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	if err := s.SaveCSPScan(ctx, "up.example", "default-src 'self'", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCSPUnreachable(ctx, "down.example", "timed out"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordResolveFailure(ctx, "gone.example", "no such host (NXDOMAIN)"); err != nil {
		t.Fatal(err)
	}

	inputs := func(ts []*ent.Target) map[string]bool {
		m := map[string]bool{}
		for _, tg := range ts {
			m[tg.Input] = true
		}
		return m
	}

	down, err := s.GetTargets(ctx, target.ReachabilityUnreachable, target.ReachabilityUnresolved)
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	got := inputs(down)
	if len(got) != 2 || !got["down.example"] || !got["gone.example"] {
		t.Errorf("down targets = %v, want down.example and gone.example", got)
	}

	all, _ := s.GetTargets(ctx)
	if len(all) != 4 {
		t.Errorf("unfiltered = %d targets, want 4", len(all))
	}
}
