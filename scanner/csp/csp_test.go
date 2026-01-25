package csp

import (
	"fmt"
	"testing"
)

func TestEvaluate(t *testing.T) {
	eval := NewEvaluator()
	cspStr := "script-src 'unsafe-inline' https://google.com; object-src 'none'"
	findings, err := eval.Evaluate(cspStr)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	for _, f := range findings {
		fmt.Printf("Finding: %+v\n", f)
	}

	// Expect unsafe-inline finding
	foundUnsafe := false
	for _, f := range findings {
		if f.Type == TypeScriptUnsafeInline {
			foundUnsafe = true
		}
	}
	if !foundUnsafe {
		t.Error("Expected unsafe-inline finding")
	}
}
