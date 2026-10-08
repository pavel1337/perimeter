package storage_test

import (
	"context"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/internal/storage"
	"perimeter/scanner/csp"
)

func targetByInput(t *testing.T, s *storage.EntStorage, input string) *ent.Target {
	t.Helper()
	targets, err := s.GetTargets(context.Background())
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	for _, tg := range targets {
		if tg.Input == input {
			return tg
		}
	}
	t.Fatalf("target %s not found", input)
	return nil
}

func TestSummaryFreshTarget(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	tg := targetByInput(t, s, "example.com")

	if tg.LatestSslGradeRank != 0 {
		t.Errorf("rank = %d, want 0", tg.LatestSslGradeRank)
	}
	if tg.LatestSslGrade != "" {
		t.Errorf("grade = %q, want empty", tg.LatestSslGrade)
	}
	if tg.LatestCertExpiry != nil {
		t.Errorf("cert expiry = %v, want nil", tg.LatestCertExpiry)
	}
	if tg.LatestCspFindingCount != nil {
		t.Errorf("csp count = %d, want nil", *tg.LatestCspFindingCount)
	}
	if tg.OpenPortCount != 0 {
		t.Errorf("open port count = %d, want 0", tg.OpenPortCount)
	}
}

func TestSummarySSLGrade(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	expiry := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	if err := s.SaveSSLScan(ctx, "example.com", storage.SSLResult{
		Grade:      "A+",
		Status:     "READY",
		CertExpiry: expiry,
	}); err != nil {
		t.Fatalf("SaveSSLScan A+: %v", err)
	}
	tg := targetByInput(t, s, "example.com")
	if tg.LatestSslGrade != "A+" || tg.LatestSslGradeRank != 8 {
		t.Errorf("after A+: grade = %q rank = %d, want A+ 8", tg.LatestSslGrade, tg.LatestSslGradeRank)
	}
	if tg.LatestCertExpiry == nil {
		t.Fatalf("after A+: cert expiry = nil, want %v", expiry)
	}
	if d := tg.LatestCertExpiry.Sub(expiry); d > time.Second || d < -time.Second {
		t.Errorf("after A+: cert expiry = %v, want %v", *tg.LatestCertExpiry, expiry)
	}

	// A newer scan with no expiry must clear the stored expiry.
	if err := s.SaveSSLScan(ctx, "example.com", storage.SSLResult{Grade: "B", Status: "READY"}); err != nil {
		t.Fatalf("SaveSSLScan B: %v", err)
	}
	tg = targetByInput(t, s, "example.com")
	if tg.LatestSslGrade != "B" || tg.LatestSslGradeRank != 5 {
		t.Errorf("after B: grade = %q rank = %d, want B 5", tg.LatestSslGrade, tg.LatestSslGradeRank)
	}
	if tg.LatestCertExpiry != nil {
		t.Errorf("after B: cert expiry = %v, want nil", *tg.LatestCertExpiry)
	}

	// No HTTPS maps to rank 0.
	if err := s.SaveSSLScan(ctx, "example.com", storage.SSLResult{Grade: "-", Status: "READY"}); err != nil {
		t.Fatalf("SaveSSLScan -: %v", err)
	}
	tg = targetByInput(t, s, "example.com")
	if tg.LatestSslGrade != "-" || tg.LatestSslGradeRank != 0 {
		t.Errorf("after -: grade = %q rank = %d, want - 0", tg.LatestSslGrade, tg.LatestSslGradeRank)
	}

	// Untrusted chain ranks like F.
	if err := s.SaveSSLScan(ctx, "example.com", storage.SSLResult{Grade: "T", Status: "READY"}); err != nil {
		t.Fatalf("SaveSSLScan T: %v", err)
	}
	tg = targetByInput(t, s, "example.com")
	if tg.LatestSslGrade != "T" || tg.LatestSslGradeRank != 1 {
		t.Errorf("after T: grade = %q rank = %d, want T 1", tg.LatestSslGrade, tg.LatestSslGradeRank)
	}
}

func TestSummaryCSPFindingCount(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	countOf := func() *int {
		t.Helper()
		return targetByInput(t, s, "example.com").LatestCspFindingCount
	}
	wantCount := func(name string, want int) {
		t.Helper()
		got := countOf()
		if got == nil {
			t.Errorf("%s: csp count = nil, want %d", name, want)
			return
		}
		if *got != want {
			t.Errorf("%s: csp count = %d, want %d", name, *got, want)
		}
	}

	twoFindings := []csp.Finding{
		{Description: "No Content-Security-Policy header found."},
		{Description: "Unsafe inline script allowed."},
	}
	if err := s.SaveCSPScan(ctx, "example.com", "default-src 'self'", twoFindings); err != nil {
		t.Fatalf("SaveCSPScan: %v", err)
	}
	wantCount("two findings", 2)

	if err := s.SaveCSPScan(ctx, "example.com", "default-src 'self'", nil); err != nil {
		t.Fatalf("SaveCSPScan: %v", err)
	}
	wantCount("no findings", 0)

	if err := s.SaveCSPUnreachable(ctx, "example.com", "connection refused"); err != nil {
		t.Fatalf("SaveCSPUnreachable: %v", err)
	}
	if got := countOf(); got != nil {
		t.Errorf("unreachable: csp count = %d, want nil", *got)
	}
}

func TestSummaryOpenPortCount(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"a.example", "b.example"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	if err := s.SaveIPs(ctx, "a.example", []string{"10.0.0.1", "10.0.0.2"}); err != nil {
		t.Fatalf("SaveIPs a: %v", err)
	}
	if err := s.SaveIPs(ctx, "b.example", []string{"10.0.0.2"}); err != nil {
		t.Fatalf("SaveIPs b: %v", err)
	}
	ports := func(name string, wantA, wantB int) {
		t.Helper()
		if got := targetByInput(t, s, "a.example").OpenPortCount; got != wantA {
			t.Errorf("%s: a.example open ports = %d, want %d", name, got, wantA)
		}
		if got := targetByInput(t, s, "b.example").OpenPortCount; got != wantB {
			t.Errorf("%s: b.example open ports = %d, want %d", name, got, wantB)
		}
	}

	if err := s.SavePortScan(ctx, "10.0.0.1", []int{22, 80}); err != nil {
		t.Fatalf("SavePortScan 10.0.0.1: %v", err)
	}
	if err := s.SavePortScan(ctx, "10.0.0.2", []int{443}); err != nil {
		t.Fatalf("SavePortScan 10.0.0.2: %v", err)
	}
	ports("first scans", 3, 1)

	// A scan of the shared IP refreshes every target linked to it.
	if err := s.SavePortScan(ctx, "10.0.0.2", nil); err != nil {
		t.Fatalf("SavePortScan 10.0.0.2 empty: %v", err)
	}
	ports("shared IP closed", 2, 0)

	// A target linked to an IP that already has a scan is counted at once.
	if _, err := s.ImportTargets(ctx, []string{"c.example"}); err != nil {
		t.Fatalf("ImportTargets c: %v", err)
	}
	if err := s.SaveIPs(ctx, "c.example", []string{"10.0.0.1"}); err != nil {
		t.Fatalf("SaveIPs c: %v", err)
	}
	if got := targetByInput(t, s, "c.example").OpenPortCount; got != 2 {
		t.Errorf("c.example open ports = %d, want 2", got)
	}
}

func TestSummaryUnchangedOnIdenticalSSLScan(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	expiry := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	res := storage.SSLResult{Grade: "A", Status: "READY", CertExpiry: expiry}
	for i := range 2 {
		if err := s.SaveSSLScan(ctx, "example.com", res); err != nil {
			t.Fatalf("SaveSSLScan #%d: %v", i+1, err)
		}
	}

	tg := targetByInput(t, s, "example.com")
	if tg.LatestSslGrade != "A" || tg.LatestSslGradeRank != 7 {
		t.Errorf("grade = %q rank = %d, want A 7", tg.LatestSslGrade, tg.LatestSslGradeRank)
	}
	if tg.LatestCertExpiry == nil {
		t.Fatalf("cert expiry = nil, want %v", expiry)
	}
	if d := tg.LatestCertExpiry.Sub(expiry); d > time.Second || d < -time.Second {
		t.Errorf("cert expiry = %v, want %v", *tg.LatestCertExpiry, expiry)
	}
}
