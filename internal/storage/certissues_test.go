package storage_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"perimeter/internal/storage"
)

func TestCertProblems(t *testing.T) {
	if got := storage.CertProblems(storage.CertSelfSigned | storage.CertNoChain); !slices.Equal(got, []string{"self-signed", "untrusted chain"}) {
		t.Errorf("CertProblems(self-signed|no chain) = %v", got)
	}
	if got := storage.CertProblems(0); got != nil {
		t.Errorf("CertProblems(0) = %v, want none", got)
	}
	if !storage.CertNotOurs(storage.CertNameMismatch) || !storage.CertNotOurs(storage.CertSelfSigned|storage.CertExpired) {
		t.Error("name mismatch and self-signed certificates are not ours")
	}
	if storage.CertNotOurs(storage.CertExpired) || storage.CertNotOurs(storage.CertNoChain) {
		t.Error("expired and broken-chain certificates are ours")
	}
}

// A self-signed or someone else's certificate has no expiry in the summary,
// so it is left out of the expiring lists; an expired one of ours stays,
// and T and M are filtered apart from configuration grades (issue #73).
func TestUntrustedCertificatesInSummary(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	soon := time.Now().Add(5 * 24 * time.Hour)
	past := time.Now().Add(-24 * time.Hour)
	if _, err := s.ImportTargets(ctx, []string{"selfsigned.test", "cname.test", "expired.test", "weak.test"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	for in, res := range map[string]storage.SSLResult{
		"selfsigned.test": {Grade: "T", Status: "READY", CertExpiry: soon, CertIssues: storage.CertSelfSigned | storage.CertNoChain},
		"cname.test":      {Grade: "M", Status: "READY", CertExpiry: soon, CertIssues: storage.CertNameMismatch},
		"expired.test":    {Grade: "T", Status: "READY", CertExpiry: past, CertIssues: storage.CertExpired},
		"weak.test":       {Grade: "F", Status: "READY", CertExpiry: soon},
	} {
		if err := s.SaveSSLScan(ctx, in, res); err != nil {
			t.Fatalf("SaveSSLScan %s: %v", in, err)
		}
	}

	expiring := inputs(t, s, storage.TargetFilter{ExpiringWithin: 30 * 24 * time.Hour})
	if want := []string{"expired.test", "weak.test"}; !slices.Equal(expiring, want) {
		t.Errorf("expiring = %v, want %v (self-signed and name mismatch left out)", expiring, want)
	}
	if got := inputs(t, s, storage.TargetFilter{SSLBelow: "B", CertTrust: "trusted"}); !slices.Equal(got, []string{"weak.test"}) {
		t.Errorf("trusted weak grades = %v, want [weak.test]", got)
	}
	if got := inputs(t, s, storage.TargetFilter{CertTrust: "untrusted"}); !slices.Equal(got, []string{"cname.test", "expired.test", "selfsigned.test"}) {
		t.Errorf("untrusted = %v", got)
	}
}

func inputs(t *testing.T, s *storage.EntStorage, f storage.TargetFilter) []string {
	t.Helper()
	targets, err := s.ListTargets(context.Background(), f, storage.TargetSort{}, 100, 0)
	if err != nil {
		t.Fatalf("ListTargets(%+v): %v", f, err)
	}
	var out []string
	for _, tg := range targets {
		out = append(out, tg.Input)
	}
	slices.Sort(out)
	return out
}
