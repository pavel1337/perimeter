package scanner

import (
	"net/http"
	"testing"

	"perimeter/scanner/csp"
)

// CSP is judged on 2xx responses only (issue #67).
func TestEvaluateCSPOnlyOnAppResponses(t *testing.T) {
	ev := csp.NewEvaluator()
	for _, code := range []int{http.StatusUnauthorized, http.StatusNotFound, http.StatusBadGateway} {
		if f, _ := evaluateCSP(cspProbe{status: code}, ev, "x"); len(f) != 0 {
			t.Errorf("%d without CSP gave %v, want no findings", code, f)
		}
	}
	f, _ := evaluateCSP(cspProbe{status: http.StatusOK}, ev, "x")
	if len(f) != 1 || f[0].Type != csp.TypeMissingDirectives || f[0].Severity != csp.SeverityHigh {
		t.Errorf("200 without CSP gave %v, want the missing-CSP finding", f)
	}
	f, header := evaluateCSP(cspProbe{status: http.StatusOK, reportOnly: "default-src 'none'"}, ev, "x")
	if header != "default-src 'none'" || len(f) == 0 {
		t.Errorf("200 with report-only gave %v from %q", f, header)
	}
}
