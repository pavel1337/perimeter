package service_test

import (
	"testing"
	"time"

	"perimeter/internal/storage"
)

// The history describes an SSL row by what changed: a renewal isn't
// "grade A → A" (issue #78).
func TestHistorySSLSummaries(t *testing.T) {
	f := newFixture(t)
	f.target("example.com")
	exp1 := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	exp2 := time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)
	f.must(f.st.SaveSSLScan(f.ctx, "example.com", storage.SSLResult{Grade: "A", Status: "READY", CertExpiry: exp1}))
	f.must(f.st.SaveSSLScan(f.ctx, "example.com", storage.SSLResult{Grade: "A", Status: "READY", CertExpiry: exp2}))
	f.must(f.st.SaveSSLScan(f.ctx, "example.com", storage.SSLResult{Grade: "A", Status: "READY", CertExpiry: exp2, CertIssuer: "Other CA"}))
	f.must(f.st.SaveSSLScan(f.ctx, "example.com", storage.SSLResult{Grade: "B", Status: "READY", CertExpiry: exp2, CertIssuer: "Other CA"}))

	page, err := f.svc.TargetHistory(f.ctx, f.id("example.com"), 0, 0)
	f.must(err)
	var got []string
	for _, e := range page.Items {
		if e.Kind == "ssl" {
			got = append(got, e.Summary)
		}
	}
	want := []string{"grade A → B", "certificate changed", "certificate renewed, now expires 2027-02-01", "grade A"}
	if len(got) != len(want) {
		t.Fatalf("ssl history = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}
