package scanner

import (
	"testing"
	"time"
)

func TestResolveBackoff(t *testing.T) {
	base := time.Minute
	// fibonacci multiples of base: 1,1,2,3,5,8,...
	cases := map[int]time.Duration{
		0:   1 * time.Minute,
		1:   1 * time.Minute,
		2:   2 * time.Minute,
		3:   3 * time.Minute,
		4:   5 * time.Minute,
		5:   8 * time.Minute,
		100: time.Hour, // capped
	}
	for attempts, want := range cases {
		if got := resolveBackoff(attempts, base); got != want {
			t.Errorf("resolveBackoff(%d) = %v, want %v", attempts, got, want)
		}
	}
}
