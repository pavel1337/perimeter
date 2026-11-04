package scanner

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"perimeter/internal/storage"
)

// What a failed TLS pre-check stores (issue #61): right after a graded result
// a failed check (retried after storage.SSLRetryAfter), otherwise or again the
// target gets "-".
func TestPrecheckFailure(t *testing.T) {
	m, st := newManagerForTest(t)
	ctx := context.Background()
	if _, err := st.ImportTargets(ctx, []string{"example.com", "nxdomain.test"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}

	// No SSL rows: the target keeps the "-" it would be scanned with.
	res := m.precheckFailure(ctx, "example.com", errors.New("connection refused"))
	if res.Grade != "-" || res.Status != "No HTTPS service on port 443" {
		t.Errorf("got %+v, want grade - and %q", res, "No HTTPS service on port 443")
	}

	// Right after a graded result: a failed check, so the last real grade
	// survives and the check is retried soon.
	if err := st.SaveSSLScan(ctx, "example.com", storage.SSLResult{Grade: "A", Status: "READY"}); err != nil {
		t.Fatalf("SaveSSLScan A: %v", err)
	}
	res = m.precheckFailure(ctx, "example.com", errors.New("connection refused"))
	if res.Grade != "" || !strings.HasPrefix(res.Status, storage.SSLErrorPrefix) {
		t.Errorf("got %+v, want grade empty and status with the %q prefix", res, storage.SSLErrorPrefix)
	}
	if err := st.SaveSSLScan(ctx, "example.com", res); err != nil {
		t.Fatalf("SaveSSLScan failed check: %v", err)
	}

	// Second failure in a row: now the target really gets "-".
	res = m.precheckFailure(ctx, "example.com", errors.New("connection refused"))
	if res.Grade != "-" || res.Status != "No HTTPS service on port 443" {
		t.Errorf("got %+v, want grade - again", res)
	}

	// NXDOMAIN without a prior grade.
	res = m.precheckFailure(ctx, "nxdomain.test", &net.DNSError{Err: "no such host", Name: "nxdomain.test", IsNotFound: true})
	if res.Grade != "-" || res.Status != "Not resolved: no such host (NXDOMAIN)" {
		t.Errorf("got %+v, want grade - and %q", res, "Not resolved: no such host (NXDOMAIN)")
	}
}
