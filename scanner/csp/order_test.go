package csp

import (
	"slices"
	"testing"
)

// A header that trips the checks ranging over maps (IP sources, nonce length,
// effective directives) in several directives.
const orderHeader = "script-src 'nonce-abc' 1.2.3.4 http://10.0.0.1 'unsafe-inline' *; " +
	"style-src 127.0.0.1 'nonce-xy'; img-src 192.168.0.1; object-src *; default-src 10.1.1.1"

// The same header always gives the same findings in the same order (#65).
func TestEvaluateIsDeterministic(t *testing.T) {
	e := NewEvaluator()
	first, err := e.Evaluate(orderHeader)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(first) < 5 {
		t.Fatalf("got %d findings, want a header with several, to make order matter", len(first))
	}
	for i := range 100 {
		got, _ := e.Evaluate(orderHeader)
		if !slices.Equal(got, first) {
			t.Fatalf("run %d gave a different list:\n%v\nwant\n%v", i, got, first)
		}
	}
}

func TestGetEffectiveDirectivesIsSorted(t *testing.T) {
	c := Parse("script-src 'self'; default-src 'none'")
	for range 50 {
		got := c.GetEffectiveDirectives([]string{DirectiveStyleSrc, DirectiveScriptSrc, DirectiveImgSrc})
		if !slices.IsSorted(got) {
			t.Fatalf("GetEffectiveDirectives = %v, want sorted", got)
		}
	}
}

func TestMaskNonces(t *testing.T) {
	a := "script-src 'nonce-AbC123==' 'strict-dynamic'; style-src 'nonce-x'"
	b := "script-src 'nonce-zzz' 'strict-dynamic'; style-src 'nonce-q9'"
	if MaskNonces(a) != MaskNonces(b) {
		t.Errorf("headers differing only in nonces mask differently:\n%s\n%s", MaskNonces(a), MaskNonces(b))
	}
	if MaskNonces("script-src 'self'") != "script-src 'self'" {
		t.Error("a header without nonces changed")
	}
	if MaskNonces(a) == MaskNonces("script-src 'nonce-x' 'unsafe-inline'; style-src 'nonce-x'") {
		t.Error("a real policy change was masked away")
	}
}
