package service_test

import (
	"strings"
	"testing"
	"time"

	"perimeter/internal/service"
	"perimeter/internal/storage"
)

// A failed check is stored with an "Error: " status and no grade; the changes
// feed, the history and the target detail must skip it and keep the last real
// result (issue #61).
func saveFailedSSLCheck(t *testing.T, f *fixture, input string) {
	t.Helper()
	f.must(f.st.SaveSSLScan(f.ctx, input, storage.SSLResult{Status: storage.SSLErrorPrefix + "scan failed"}))
}

// sslGradeChanges returns the SSL grade changes of a ChangesSince window.
func sslGradeChanges(t *testing.T, f *fixture) []service.Change {
	t.Helper()
	got, _, err := f.svc.ChangesSince(f.ctx, time.Time{}, 0)
	f.must(err)
	var out []service.Change
	for _, c := range got {
		if c.Kind == service.ChangeSSLGradeChanged {
			out = append(out, c)
		}
	}
	return out
}

func TestSSLChangesSkipFailedChecks(t *testing.T) {
	exp := time.Now().Add(100 * 24 * time.Hour)

	t.Run("A, failed check, A again: one change", func(t *testing.T) {
		f := newFixture(t)
		f.target("example.com")
		f.ssl("example.com", "A", exp)
		saveFailedSSLCheck(t, f, "example.com")
		f.ssl("example.com", "A", exp)

		cs := sslGradeChanges(t, f)
		if len(cs) != 1 {
			t.Fatalf("got %d ssl grade changes, want 1 (the first A):\n%s", len(cs), describe(cs))
		}
		if cs[0].From != "" || cs[0].To != "A" {
			t.Errorf("change = %q -> %q, want \"\" -> A", cs[0].From, cs[0].To)
		}
		for _, c := range cs {
			if c.To == "" {
				t.Errorf("grade change to none: %+v", c)
			}
		}
	})

	t.Run("A, failed check, B: change A to B", func(t *testing.T) {
		f := newFixture(t)
		f.target("example.com")
		f.ssl("example.com", "A", exp)
		saveFailedSSLCheck(t, f, "example.com")
		f.ssl("example.com", "B", exp)

		cs := sslGradeChanges(t, f)
		if len(cs) != 2 {
			t.Fatalf("got %d ssl grade changes, want 2:\n%s", len(cs), describe(cs))
		}
		if cs[0].From != "" || cs[0].To != "A" {
			t.Errorf("first change = %q -> %q, want \"\" -> A", cs[0].From, cs[0].To)
		}
		if cs[1].From != "A" || cs[1].To != "B" {
			t.Errorf("second change = %q -> %q, want A -> B", cs[1].From, cs[1].To)
		}
	})
}

func TestHistoryLabelsFailedSSLCheck(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().Add(100 * 24 * time.Hour)
	f.target("example.com")
	f.ssl("example.com", "A", exp)
	saveFailedSSLCheck(t, f, "example.com")
	f.ssl("example.com", "B", exp)

	page, err := f.svc.TargetHistory(f.ctx, f.id("example.com"), 0, 0)
	f.must(err)
	var ssls []service.HistoryEntry
	for _, e := range page.Items {
		if e.Kind == "ssl" {
			ssls = append(ssls, e)
		}
	}
	if len(ssls) != 3 {
		t.Fatalf("got %d ssl history entries, want 3", len(ssls))
	}
	// Newest first: B, the failed check, A.
	if got := ssls[0].Summary; got != "grade A → B" {
		t.Errorf("newest summary = %q, want %q (the failed check is skipped)", got, "grade A → B")
	}
	if ssls[0].Grade != "B" {
		t.Errorf("newest grade = %q, want B", ssls[0].Grade)
	}
	if got := ssls[1].Summary; got != "SSL check failed" {
		t.Errorf("failed entry summary = %q, want %q", got, "SSL check failed")
	}
	// The reason is reported without the "Error: " prefix.
	if got := ssls[1].Error; got != "scan failed" {
		t.Errorf("failed entry error = %q, want %q (without the %q prefix)", got, "scan failed", storage.SSLErrorPrefix)
	}
	if strings.HasPrefix(ssls[1].Error, storage.SSLErrorPrefix) {
		t.Errorf("failed entry error = %q, must not carry the %q prefix", ssls[1].Error, storage.SSLErrorPrefix)
	}
}

func TestGetTargetReportsFailedSSLCheck(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().Add(100 * 24 * time.Hour)
	f.target("example.com")
	f.ssl("example.com", "A", exp)
	f.must(f.st.SaveSSLScan(f.ctx, "example.com", storage.SSLResult{
		Status: storage.SSLErrorPrefix + "TLS pre-check: connection refused",
	}))

	d, err := f.svc.GetTarget(f.ctx, f.id("example.com"))
	f.must(err)
	if d.SSL == nil {
		t.Fatal("GetTarget SSL = nil, want the last real result with the failure next to it")
	}
	if d.SSL.Grade != "A" {
		t.Errorf("ssl grade = %q, want A (the last real result)", d.SSL.Grade)
	}
	if d.SSL.LastCheckError == "" {
		t.Error("last_check_error is empty, want the failure reason")
	}
	if got := d.SSL.LastCheckError; got != "TLS pre-check: connection refused" {
		t.Errorf("last_check_error = %q, want %q (without the %q prefix)", got, "TLS pre-check: connection refused", storage.SSLErrorPrefix)
	}
	if strings.HasPrefix(d.SSL.LastCheckError, storage.SSLErrorPrefix) {
		t.Errorf("last_check_error = %q, must not carry the %q prefix", d.SSL.LastCheckError, storage.SSLErrorPrefix)
	}
	if d.SSL.LastCheckFailedAt == nil {
		t.Error("last_check_failed_at = nil, want set")
	}
}
