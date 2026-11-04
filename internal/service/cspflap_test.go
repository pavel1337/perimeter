package service_test

import (
	"strings"
	"testing"
	"time"

	"perimeter/internal/service"
	"perimeter/scanner/csp"
)

func cspChanges(t *testing.T, f *fixture) []service.Change {
	t.Helper()
	got, _, err := f.svc.ChangesSince(f.ctx, time.Time{}, 0)
	f.must(err)
	var out []service.Change
	for _, c := range got {
		if c.Kind == service.ChangeCSPChanged {
			out = append(out, c)
		}
	}
	return out
}

// Probe errors read as what they are, and one error after another is no
// change (issue #69).
func TestCSPProbeErrorsInFeed(t *testing.T) {
	f := newFixture(t)
	f.target("example.com")
	finding := csp.Finding{Type: csp.TypeMissingDirectives, Directive: "Header", Severity: csp.SeverityHigh}
	f.must(f.st.SaveCSPScan(f.ctx, "example.com", "", []csp.Finding{finding}))
	f.must(f.st.SaveCSPUnreachable(f.ctx, "example.com", "timed out"))
	f.must(f.st.SaveCSPUnreachable(f.ctx, "example.com", "connection reset"))
	f.must(f.st.SaveCSPUnreachable(f.ctx, "example.com", "timed out"))

	cs := cspChanges(t, f)
	if len(cs) != 2 {
		t.Fatalf("got %d CSP changes, want 2 (first result, then to timed out):\n%s", len(cs), describe(cs))
	}
	if cs[1].From != "1 finding" || cs[1].To != "no response (timed out)" {
		t.Errorf("change = %q -> %q, want 1 finding -> no response (timed out)", cs[1].From, cs[1].To)
	}
	for _, c := range cs {
		if strings.Contains(c.Summary, "policy changed") {
			t.Errorf("error flap reported as %q", c.Summary)
		}
	}

	page, err := f.svc.TargetHistory(f.ctx, f.id("example.com"), 0, 0)
	f.must(err)
	if page.Items[0].Summary != "CSP no response (timed out)" {
		t.Errorf("newest history entry = %q, want CSP no response (timed out)", page.Items[0].Summary)
	}
}

// "Policy changed" only when the header really changed; a new nonce isn't.
func TestCSPPolicyChanged(t *testing.T) {
	f := newFixture(t)
	f.target("example.com")
	finding := csp.Finding{Type: csp.TypeScriptUnsafeInline, Directive: "script-src", Severity: csp.SeverityHigh}
	f.must(f.st.SaveCSPScan(f.ctx, "example.com", "script-src 'unsafe-inline' 'nonce-a'", []csp.Finding{finding}))
	f.must(f.st.SaveCSPScan(f.ctx, "example.com", "script-src 'unsafe-inline' 'nonce-b'", []csp.Finding{finding}))
	f.must(f.st.SaveCSPScan(f.ctx, "example.com", "script-src 'unsafe-inline' https:", []csp.Finding{finding}))

	cs := cspChanges(t, f)
	if len(cs) != 2 || !strings.HasSuffix(cs[1].Summary, "CSP policy changed") {
		t.Errorf("got %s, want the first result then one policy change", describe(cs))
	}
}
