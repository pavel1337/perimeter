package scanner

import (
	"context"
	"testing"

	"perimeter/scanner/csp"
)

var (
	missingCSP = csp.Finding{Type: csp.TypeMissingDirectives, Directive: "Header", Severity: csp.SeverityHigh, Description: "No Content-Security-Policy header found."}
	unsafeEval = csp.Finding{Type: csp.TypeScriptUnsafeEval, Directive: "script-src", Severity: csp.SeverityMedium, Description: "'unsafe-eval' allows eval"}
	lowNote    = csp.Finding{Type: csp.TypeReportingDestinationMissing, Directive: "report-uri", Severity: csp.SeverityInfo, Description: "no reporting"}
)

// The CSP notification only carries findings the last answered scan didn't
// have (issue #66).
func TestNewCSPIssues(t *testing.T) {
	// First result: every medium or higher finding.
	if got := newCSPIssues(nil, false, []csp.Finding{missingCSP, lowNote}); len(got) != 1 || got[0] != missingCSP {
		t.Errorf("first result = %v, want only the high finding", got)
	}
	// Same findings again: nothing.
	if got := newCSPIssues([]csp.Finding{missingCSP}, true, []csp.Finding{missingCSP}); len(got) != 0 {
		t.Errorf("unchanged findings = %v, want none", got)
	}
	// One new finding: only that one.
	if got := newCSPIssues([]csp.Finding{unsafeEval}, true, []csp.Finding{missingCSP, unsafeEval}); len(got) != 1 || got[0] != missingCSP {
		t.Errorf("one new finding = %v, want only %v", got, missingCSP)
	}
	// A new low finding doesn't notify.
	if got := newCSPIssues(nil, true, []csp.Finding{lowNote}); len(got) != 0 {
		t.Errorf("new low finding = %v, want none", got)
	}
	// A finding whose value only changed nonce is not new.
	n1 := csp.Finding{Type: csp.TypeNonceLength, Directive: "script-src", Severity: csp.SeverityMedium, Value: "'nonce-aa'", Description: "nonce 'nonce-aa' is short"}
	n2 := n1
	n2.Value, n2.Description = "'nonce-bb'", "nonce 'nonce-bb' is short"
	if got := newCSPIssues([]csp.Finding{n1}, true, []csp.Finding{n2}); len(got) != 0 {
		t.Errorf("nonce-only change = %v, want none", got)
	}
}

// The previous findings come from the last scan that got an answer, so a
// flap through "no response" doesn't notify again.
func TestPreviousCSPFindingsSkipProbeErrors(t *testing.T) {
	_, st := newManagerForTest(t)
	ctx := context.Background()
	if _, err := st.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	if _, had, err := st.GetPreviousCSPFindings(ctx, "example.com"); err != nil || had {
		t.Fatalf("before any scan: had=%v err=%v, want none", had, err)
	}
	if err := st.SaveCSPScan(ctx, "example.com", "", []csp.Finding{missingCSP}); err != nil {
		t.Fatalf("SaveCSPScan: %v", err)
	}
	if err := st.SaveCSPUnreachable(ctx, "example.com", "timed out"); err != nil {
		t.Fatalf("SaveCSPUnreachable: %v", err)
	}
	prev, had, err := st.GetPreviousCSPFindings(ctx, "example.com")
	if err != nil || !had || len(prev) != 1 || prev[0] != missingCSP {
		t.Errorf("after a probe error: %v had=%v err=%v, want the answered scan's finding", prev, had, err)
	}
}
