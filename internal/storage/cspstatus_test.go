package storage_test

import (
	"context"
	"testing"

	"perimeter/internal/storage"
	"perimeter/scanner/csp"
)

// A 404 page serves no application: it has no CSP finding count, so it isn't
// a CSP issue, and it isn't the previous result new findings are compared
// with (issue #67).
func TestCSPErrorPageIsNotJudged(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	missing := csp.Finding{Type: csp.TypeMissingDirectives, Directive: "Header", Severity: csp.SeverityHigh}
	if err := s.SaveCSPResponse(ctx, "example.com", storage.CSPResponse{Findings: []csp.Finding{missing}, StatusCode: 200, FinalURL: "https://example.com/"}); err != nil {
		t.Fatalf("SaveCSPResponse 200: %v", err)
	}
	if err := s.SaveCSPResponse(ctx, "example.com", storage.CSPResponse{StatusCode: 404, FinalURL: "https://example.com/"}); err != nil {
		t.Fatalf("SaveCSPResponse 404: %v", err)
	}
	targets, err := s.GetTargets(ctx)
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	tg := targets[0]
	if tg.LatestCspFindingCount != nil {
		t.Errorf("csp finding count = %d after a 404, want nil (not judged)", *tg.LatestCspFindingCount)
	}
	if code, ok := storage.CSPNoApp(tg.Edges.CspScans[0]); !ok || code != 404 {
		t.Errorf("CSPNoApp = %d %v, want 404 true", code, ok)
	}
	prev, had, err := s.GetPreviousCSPFindings(ctx, "example.com")
	if err != nil || !had || len(prev) != 1 {
		t.Errorf("previous findings = %v had=%v err=%v, want the 200's finding", prev, had, err)
	}
	// A status or URL change is a new row; the same response collapses.
	if err := s.SaveCSPResponse(ctx, "example.com", storage.CSPResponse{StatusCode: 404, FinalURL: "https://example.com/"}); err != nil {
		t.Fatalf("SaveCSPResponse 404 again: %v", err)
	}
	_, n, err := s.GetCSPScansPage(ctx, tg.ID, 10, 0)
	if err != nil || n != 2 {
		t.Errorf("csp rows = %d (err %v), want 2 (the repeated 404 collapses)", n, err)
	}
}
