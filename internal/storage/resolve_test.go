package storage_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"perimeter/ent/target"
	"perimeter/internal/storage"
)

// linkedIPs returns the sorted addresses linked to the target with id.
func linkedIPs(t *testing.T, s *storage.EntStorage, id int) []string {
	t.Helper()
	tg, err := s.GetTarget(context.Background(), id)
	if err != nil {
		t.Fatalf("GetTarget(%d): %v", id, err)
	}
	var addrs []string
	for _, i := range tg.Edges.Ips {
		addrs = append(addrs, i.Address)
	}
	slices.Sort(addrs)
	return addrs
}

// dueIDs returns the ids of the targets due for resolution at now.
func dueIDs(t *testing.T, s *storage.EntStorage, limit int, now time.Time) []int {
	t.Helper()
	due, err := s.GetTargetsDueForResolution(context.Background(), limit, now)
	if err != nil {
		t.Fatalf("GetTargetsDueForResolution: %v", err)
	}
	ids := make([]int, 0, len(due))
	for _, tg := range due {
		ids = append(ids, tg.ID)
	}
	return ids
}

// assertNear reports a failure unless got is within tol of want.
func assertNear(t *testing.T, name string, got *time.Time, want time.Time, tol time.Duration) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s: nil, want about %v", name, want)
	}
	if d := got.Sub(want); d < -tol || d > tol {
		t.Errorf("%s = %v, want about %v (±%v)", name, *got, want, tol)
	}
}

func TestSaveIPsLinksExactlyTheAnswer(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	id := importHosts(t, s, "sv", 1)[0]
	in := mustTargetInput(t, s, id)

	if err := s.SaveIPs(ctx, in, []string{"192.0.2.1", "192.0.2.2"}, time.Hour); err != nil {
		t.Fatalf("SaveIPs (A, B): %v", err)
	}
	if err := s.SaveIPs(ctx, in, []string{"192.0.2.3"}, time.Hour); err != nil {
		t.Fatalf("SaveIPs (C): %v", err)
	}

	if got := linkedIPs(t, s, id); !slices.Equal(got, []string{"192.0.2.3"}) {
		t.Errorf("linked = %v, want only [192.0.2.3]", got)
	}
	tg, err := s.GetTarget(ctx, id)
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if tg.ResolvedAt == nil {
		t.Error("resolved_at is nil, want set")
	}
	assertNear(t, "next_resolve_at", tg.NextResolveAt, time.Now().Add(time.Hour), time.Minute)
	if tg.ResolveAttempts != 0 {
		t.Errorf("resolve_attempts = %d, want 0", tg.ResolveAttempts)
	}
	if tg.ResolveError != "" {
		t.Errorf("resolve_error = %q, want empty", tg.ResolveError)
	}
}

func TestSaveIPsKeepsSharedIP(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"x.example", "y.example"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	for _, in := range []string{"x.example", "y.example"} {
		if err := s.SaveIPs(ctx, in, []string{"192.0.2.10"}, time.Hour); err != nil {
			t.Fatalf("SaveIPs(%s): %v", in, err)
		}
	}

	if err := s.SaveIPs(ctx, "x.example", []string{"192.0.2.99"}, time.Hour); err != nil {
		t.Fatalf("SaveIPs(x -> .99): %v", err)
	}

	xID := idOf(t, s, "x.example")
	yID := idOf(t, s, "y.example")
	if got := linkedIPs(t, s, xID); !slices.Equal(got, []string{"192.0.2.99"}) {
		t.Errorf("x linked = %v, want [192.0.2.99]", got)
	}
	if got := linkedIPs(t, s, yID); !slices.Equal(got, []string{"192.0.2.10"}) {
		t.Errorf("y linked = %v, want [192.0.2.10] (shared IP stays linked)", got)
	}
}

func TestNameGoneUnlinksAndMarksUnresolved(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	id := importHosts(t, s, "ng", 1)[0]
	in := mustTargetInput(t, s, id)

	if err := s.SaveIPs(ctx, in, []string{"192.0.2.1"}, time.Hour); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}
	if err := s.RecordResolveFailure(ctx, in, storage.ResolveFailure{
		Message:  "no such host (NXDOMAIN)",
		NameGone: true,
		RetryIn:  func(int) time.Duration { return 5 * time.Minute },
	}); err != nil {
		t.Fatalf("RecordResolveFailure: %v", err)
	}

	if got := linkedIPs(t, s, id); len(got) != 0 {
		t.Errorf("linked = %v, want none after NameGone", got)
	}
	if got := reachabilityOf(t, s, in); got != target.ReachabilityUnresolved {
		t.Errorf("reachability = %s, want unresolved", got)
	}
	tg, err := s.GetTarget(ctx, id)
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if tg.ResolveError == "" {
		t.Error("resolve_error empty, want the failure message")
	}
	if tg.ResolveAttempts != 1 {
		t.Errorf("resolve_attempts = %d, want 1", tg.ResolveAttempts)
	}
	assertNear(t, "next_resolve_at", tg.NextResolveAt, time.Now().Add(5*time.Minute), time.Minute)
}

func TestTemporaryFailureKeepsLinks(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	id := importHosts(t, s, "tf", 1)[0]
	in := mustTargetInput(t, s, id)

	if err := s.SaveIPs(ctx, in, []string{"192.0.2.1"}, time.Hour); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}

	var seen []int
	failure := storage.ResolveFailure{
		Message:  "DNS timeout",
		NameGone: false,
		RetryIn:  func(n int) time.Duration { seen = append(seen, n); return time.Minute },
	}
	for range 2 {
		if err := s.RecordResolveFailure(ctx, in, failure); err != nil {
			t.Fatalf("RecordResolveFailure: %v", err)
		}
	}

	if got := linkedIPs(t, s, id); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("linked = %v, want the IP kept on temporary failure", got)
	}
	if got := reachabilityOf(t, s, in); got == target.ReachabilityUnresolved {
		t.Errorf("reachability = %s, want not unresolved after a temporary failure", got)
	}
	if !slices.Equal(seen, []int{1, 2}) {
		t.Errorf("RetryIn saw attempts %v, want [1 2]", seen)
	}
	tg, err := s.GetTarget(ctx, id)
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if tg.ResolveAttempts != 2 {
		t.Errorf("resolve_attempts = %d, want 2", tg.ResolveAttempts)
	}

	if err := s.SaveIPs(ctx, in, []string{"192.0.2.1"}, time.Hour); err != nil {
		t.Fatalf("SaveIPs again: %v", err)
	}
	tg, err = s.GetTarget(ctx, id)
	if err != nil {
		t.Fatalf("GetTarget (after SaveIPs): %v", err)
	}
	if tg.ResolveAttempts != 0 {
		t.Errorf("resolve_attempts after SaveIPs = %d, want 0", tg.ResolveAttempts)
	}
	if tg.ResolveError != "" {
		t.Errorf("resolve_error after SaveIPs = %q, want empty", tg.ResolveError)
	}
}

func TestDueForResolution(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	ids := importHosts(t, s, "due", 2)
	a, b := ids[0], ids[1]
	if err := s.SaveIPs(ctx, mustTargetInput(t, s, b), []string{"192.0.2.1"}, time.Hour); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}

	// Now: only the fresh (NULL) target is due; b's hour has not passed.
	if got := dueIDs(t, s, 10, time.Now()); !slices.Equal(got, []int{a}) {
		t.Errorf("due now = %v, want only the fresh target %d", got, a)
	}

	// Two hours on: b is overdue too, and the NULL target still comes first.
	if got := dueIDs(t, s, 10, time.Now().Add(2*time.Hour)); !slices.Equal(got, []int{a, b}) {
		t.Errorf("due at +2h = %v, want %v (NULL first, then the overdue one)", got, ids)
	}

	// The limit cuts the list in that order.
	if got := dueIDs(t, s, 1, time.Now().Add(2*time.Hour)); !slices.Equal(got, []int{a}) {
		t.Errorf("limit 1 = %v, want only %d", got, a)
	}
}

func TestBackoffDoesNotStarveDueTargets(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	ids := importHosts(t, s, "bk", 11)
	failing, overdue := ids[:10], ids[10]

	for _, id := range failing {
		in := mustTargetInput(t, s, id)
		if err := s.RecordResolveFailure(ctx, in, storage.ResolveFailure{
			Message: "DNS timeout",
			RetryIn: func(int) time.Duration { return time.Hour },
		}); err != nil {
			t.Fatalf("RecordResolveFailure(%s): %v", in, err)
		}
	}
	if err := s.SaveIPs(ctx, mustTargetInput(t, s, overdue), []string{"192.0.2.1"}, -time.Second); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}

	if got := dueIDs(t, s, 10, time.Now()); !slices.Equal(got, []int{overdue}) {
		t.Errorf("due = %v, want only the overdue target %d (backed-off targets must not be returned)", got, overdue)
	}
}

func TestRescanMakesTargetDue(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	id := importHosts(t, s, "rs", 1)[0]
	in := mustTargetInput(t, s, id)

	if err := s.SaveIPs(ctx, in, []string{"192.0.2.1"}, time.Hour); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}
	if got := dueIDs(t, s, 10, time.Now()); len(got) != 0 {
		t.Fatalf("before rescan, due = %v, want none", got)
	}

	if _, err := s.RequestRescan(ctx, []int{id}, time.Now(), time.Minute, allRescan); err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}

	if got := dueIDs(t, s, 10, time.Now()); !slices.Equal(got, []int{id}) {
		t.Errorf("after rescan, due = %v, want the target %d", got, id)
	}
	tg, err := s.GetTarget(ctx, id)
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if tg.ResolvedAt == nil {
		t.Error("resolved_at cleared by rescan, want it kept")
	}
}
