package scanner

import (
	"testing"

	"perimeter/ent"
)

// A target picked for an SSL rescan yields a job that asks for a fresh
// assessment; an ordinary target does not.
func TestSSLJobFreshFollowsRescanFlag(t *testing.T) {
	pending := sslJob(&ent.Target{Input: "example.com", SslRescanPending: true})
	if !pending.Fresh || pending.Input != "example.com" || pending.Type != JobTypeSSLScan {
		t.Errorf("pending job = %+v, want a fresh SSL job for example.com", pending)
	}
	if sslJob(&ent.Target{Input: "example.com"}).Fresh {
		t.Errorf("ordinary SSL job is marked fresh")
	}
}

// A grade-drop notification needs a known grade on both sides and ranks the
// grades instead of comparing their letters (#63).
func TestGradeDropped(t *testing.T) {
	cases := []struct {
		prev, next string
		want       bool
	}{
		{"A", "A+", false}, // better, even though "A+" sorts before "A"
		{"A+", "A", true},
		{"-", "A", false}, // recovering from a failed pre-check is not a drop
		{"A", "-", false},
		{"A", "T", true},
		{"B", "C", true},
		{"F", "T", false}, // same rank, not worse
		{"", "B", false},  // no previous grade to compare with
		{"B", "", false},  // assessment did not finish
	}
	for _, tc := range cases {
		if got := gradeDropped(tc.prev, tc.next); got != tc.want {
			t.Errorf("gradeDropped(%q, %q) = %v, want %v", tc.prev, tc.next, got, tc.want)
		}
	}
}
