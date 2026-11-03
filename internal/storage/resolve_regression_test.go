package storage_test

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"perimeter/internal/storage"
)

// linkedIPs returns the sorted addresses of the target's linked IPs.
func linkedIPs(t *testing.T, ctx context.Context, s *storage.EntStorage, id int) []string {
	t.Helper()
	tg, err := s.GetTarget(ctx, id)
	if err != nil {
		t.Fatalf("GetTarget(%d): %v", id, err)
	}
	var out []string
	for _, i := range tg.Edges.Ips {
		out = append(out, i.Address)
	}
	sortStrings(out)
	return out
}

func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j-1] > ss[j]; j-- {
			ss[j-1], ss[j] = ss[j], ss[j-1]
		}
	}
}

// SCENARIO_HAPPY_PATH: SaveIPs links the answer's IPs.
func TestResolveHappyPathSaveIPs(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	ids := importHosts(t, s, "happy", 1)
	id := ids[0]
	input := mustTargetInput(t, s, id)

	if err := s.SaveIPs(ctx, input, []string{"192.0.2.1", "192.0.2.2"}); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}
	if got := linkedIPs(t, ctx, s, id); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Errorf("linked = %v, want [192.0.2.1 192.0.2.2]", got)
	}
}

// SCENARIO_DEFECT_REGRESSION (regression): an answer that changes from A to B
// leaves only B linked. The previous implementation only ever added links, so
// stale IPs were never unlinked (issue #59). This test compiles on the
// upstream source and fails there: upstream links both A and B.
func TestResolveRegressionSaveIPsReplacesOldIPs(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	ids := importHosts(t, s, "replace", 1)
	id := ids[0]
	input := mustTargetInput(t, s, id)

	if err := s.SaveIPs(ctx, input, []string{"192.0.2.1", "192.0.2.2"}); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}
	if got := linkedIPs(t, ctx, s, id); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Fatalf("after first SaveIPs = %v, want [192.0.2.1 192.0.2.2]", got)
	}

	// The answer changes from A to B: only B must remain linked.
	if err := s.SaveIPs(ctx, input, []string{"192.0.2.3"}); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}
	if got := linkedIPs(t, ctx, s, id); !slices.Equal(got, []string{"192.0.2.3"}) {
		t.Errorf("after answer change = %v, want [192.0.2.3] (stale IPs unlinked)", got)
	}
}

// SCENARIO_DEFECT_REGRESSION (regression): an IP shared with another target
// stays linked when one target drops it from its answer.
func TestResolveRegressionSaveIPsKeepsSharedIPs(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	ids := importHosts(t, s, "share", 2)
	a, b := ids[0], ids[1]
	inputA := mustTargetInput(t, s, a)
	inputB := mustTargetInput(t, s, b)

	if err := s.SaveIPs(ctx, inputA, []string{"192.0.2.10", "192.0.2.11"}); err != nil {
		t.Fatalf("SaveIPs A: %v", err)
	}
	if err := s.SaveIPs(ctx, inputB, []string{"192.0.2.10"}); err != nil {
		t.Fatalf("SaveIPs B: %v", err)
	}

	// A changes its answer away from the shared IP; B must still link it.
	if err := s.SaveIPs(ctx, inputA, []string{"192.0.2.99"}); err != nil {
		t.Fatalf("SaveIPs A again: %v", err)
	}
	if got := linkedIPs(t, ctx, s, a); !slices.Equal(got, []string{"192.0.2.99"}) {
		t.Errorf("A = %v, want [192.0.2.99]", got)
	}
	if got := linkedIPs(t, ctx, s, b); !slices.Equal(got, []string{"192.0.2.10"}) {
		t.Errorf("B = %v, want shared [192.0.2.10] still linked", got)
	}
}

// SCENARIO_DEFECT_REGRESSION (regression): a temporary failure (timeout,
// SERVFAIL) keeps the links and retries with the existing backoff.
func TestResolveRegressionTimeoutKeepsLinks(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	ids := importHosts(t, s, "timeout", 1)
	id := ids[0]
	input := mustTargetInput(t, s, id)

	if err := s.SaveIPs(ctx, input, []string{"192.0.2.1"}); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}
	// A temporary failure records the error but must not touch the links.
	if err := s.RecordResolveFailure(ctx, input, "DNS timeout"); err != nil {
		t.Fatalf("RecordResolveFailure: %v", err)
	}
	if got := linkedIPs(t, ctx, s, id); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("linked = %v, want [192.0.2.1] (timeout keeps links)", got)
	}
}

// SCENARIO_DEFECT_REGRESSION (regression): GetUnresolvedTargets re-selects
// targets due for re-resolution based on resolved_at. On the upstream source
// the threshold is ignored and only targets with no IPs are returned, so a
// resolved target is never re-selected: this test fails upstream.
func TestResolveRegressionGetUnresolvedTargetsReschedules(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	ids := importHosts(t, s, "resched", 1)
	if err := s.SaveIPs(ctx, mustTargetInput(t, s, ids[0]), []string{"192.0.2.1"}); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}

	// A zero threshold means the re-resolution window is open: a target that
	// has resolved at least once is due again.
	got, err := s.GetUnresolvedTargets(ctx, 10, 0)
	if err != nil {
		t.Fatalf("GetUnresolvedTargets: %v", err)
	}
	found := false
	for _, g := range got {
		if g.ID == ids[0] {
			found = true
		}
	}
	if !found {
		t.Errorf("target %d not selected for re-resolution", ids[0])
	}
}

// SCENARIO_BOUNDARY (boundary): limit 1 returns at most one target.
func TestResolveBoundaryGetUnresolvedTargetsLimitOne(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	importHosts(t, s, "limit", 3)
	got, err := s.GetUnresolvedTargets(ctx, 1, time.Hour)
	if err != nil {
		t.Fatalf("GetUnresolvedTargets: %v", err)
	}
	if len(got) > 1 {
		t.Errorf("limit 1 returned %d targets, want at most 1", len(got))
	}
}

// SCENARIO_NULL_INPUT (null): an empty IP answer unlinks every IP. On the
// upstream source SaveIPs only ever adds links, so an empty answer leaves the
// old links in place: this test fails upstream.
func TestResolveNullSaveIPsEmptyAnswerUnlinksAll(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	ids := importHosts(t, s, "empty", 1)
	id := ids[0]
	input := mustTargetInput(t, s, id)

	if err := s.SaveIPs(ctx, input, []string{"192.0.2.1"}); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}
	// An empty answer (nil slice) unlinks all IPs without crashing.
	if err := s.SaveIPs(ctx, input, nil); err != nil {
		t.Fatalf("SaveIPs nil: %v", err)
	}
	if got := linkedIPs(t, ctx, s, id); len(got) != 0 {
		t.Errorf("linked = %v, want none after empty answer", got)
	}
}

// SCENARIO_EMPTY_INPUT (empty): an empty IP address collection unlinks every
// IP (an empty answer is a legitimate NODATA result). Fails upstream.
func TestResolveEmptySaveIPsEmptySliceUnlinksAll(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	ids := importHosts(t, s, "emptyslice", 1)
	id := ids[0]
	input := mustTargetInput(t, s, id)

	if err := s.SaveIPs(ctx, input, []string{"192.0.2.1"}); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}
	if err := s.SaveIPs(ctx, input, []string{}); err != nil {
		t.Fatalf("SaveIPs empty slice: %v", err)
	}
	if got := linkedIPs(t, ctx, s, id); len(got) != 0 {
		t.Errorf("linked = %v, want none after empty answer", got)
	}
}

// SCENARIO_NEGATIVE_FAILURE (negative): SaveIPs on a nonexistent target
// returns an error instead of corrupting state.
func TestResolveNegativeSaveIPsUnknownTarget(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	err := s.SaveIPs(ctx, "no.such.target", []string{"192.0.2.1"})
	if err == nil {
		t.Error("SaveIPs on unknown target expected an error, got nil")
	}
}

// SCENARIO_CONCURRENCY_RACE (concurrency): concurrent SaveIPs calls on the
// same target must not crash and leave a consistent link set.
func TestResolveConcurrencyConcurrentSaveIPs(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	ids := importHosts(t, s, "race", 1)
	id := ids[0]
	input := mustTargetInput(t, s, id)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = s.SaveIPs(ctx, input, []string{"192.0.2.1", "192.0.2.2"})
		}(i)
	}
	wg.Wait()
	got := linkedIPs(t, ctx, s, id)
	if !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Errorf("after concurrent SaveIPs = %v, want [192.0.2.1 192.0.2.2]", got)
	}
}
