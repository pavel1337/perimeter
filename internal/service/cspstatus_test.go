package service_test

import (
	"strings"
	"testing"
	"time"

	"perimeter/internal/service"
	"perimeter/internal/storage"
	"perimeter/scanner/csp"
)

// A 404 is shown as "no application served (404)" in the changes feed and
// the history (issue #67).
func TestCSPErrorPageInFeedAndHistory(t *testing.T) {
	f := newFixture(t)
	f.target("example.com")
	id := f.id("example.com")
	missing := csp.Finding{Type: csp.TypeMissingDirectives, Directive: "Header", Severity: csp.SeverityHigh}
	f.must(f.st.SaveCSPResponse(f.ctx, "example.com", storage.CSPResponse{Findings: []csp.Finding{missing}, StatusCode: 200}))
	f.must(f.st.SaveCSPResponse(f.ctx, "example.com", storage.CSPResponse{StatusCode: 404, FinalURL: "https://example.com/"}))

	got, _, err := f.svc.ChangesSince(f.ctx, time.Time{}, 0)
	f.must(err)
	var last service.Change
	for _, c := range got {
		if c.Kind == service.ChangeCSPChanged {
			last = c
		}
	}
	if last.To != "no application served (404)" || last.From != "1 finding" {
		t.Errorf("last CSP change = %q -> %q, want 1 finding -> no application served (404)", last.From, last.To)
	}

	d, err := f.svc.GetTarget(f.ctx, id)
	f.must(err)
	if d.CSP == nil || d.CSP.StatusCode != 404 || d.CSP.FinalURL != "https://example.com/" || len(d.CSP.Findings) != 0 {
		t.Errorf("CSP detail = %+v, want 404 at https://example.com/ with no findings", d.CSP)
	}

	page, err := f.svc.TargetHistory(f.ctx, id, 0, 0)
	f.must(err)
	found := false
	for _, e := range page.Items {
		if e.Kind == "csp" && strings.Contains(e.Summary, "no application served (404)") {
			found = true
		}
	}
	if !found {
		t.Errorf("history has no \"no application served (404)\" entry: %+v", page.Items)
	}
}
