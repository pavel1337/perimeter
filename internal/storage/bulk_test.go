package storage_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"perimeter/ent"
	"perimeter/internal/storage"
)

// importHosts imports n targets named "<prefix><i>.example" and returns their ids
// in ascending order.
func importHosts(t *testing.T, s *storage.EntStorage, prefix string, n int) []int {
	t.Helper()
	ctx := context.Background()
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf("%s%d.example", prefix, i)
	}
	if _, err := s.ImportTargets(ctx, lines); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	targets, err := s.GetTargets(ctx)
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	ids := make([]int, 0, len(targets))
	for _, tg := range targets {
		ids = append(ids, tg.ID)
	}
	slices.Sort(ids)
	return ids
}

func TestTargetIDsMatchesFilterAscendingAndSkipsDeleted(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	ids := importHosts(t, s, "t", 4)
	for i, grade := range []string{"A", "B", "A", "A"} {
		input := mustTargetInput(t, s, ids[i])
		if err := s.SaveSSLScan(ctx, input, storage.SSLResult{Grade: grade, Status: "READY"}); err != nil {
			t.Fatalf("SaveSSLScan: %v", err)
		}
	}
	mustDelete(t, s, ids[3])

	got, err := s.TargetIDs(ctx, storage.TargetFilter{SSLGrade: "A"})
	if err != nil {
		t.Fatalf("TargetIDs: %v", err)
	}
	if want := []int{ids[0], ids[2]}; !slices.Equal(got, want) {
		t.Errorf("TargetIDs(SSLGrade A) = %v, want %v (ascending, deleted excluded)", got, want)
	}

	got, err = s.TargetIDs(ctx, storage.TargetFilter{})
	if err != nil {
		t.Fatalf("TargetIDs: %v", err)
	}
	if want := []int{ids[0], ids[1], ids[2]}; !slices.Equal(got, want) {
		t.Errorf("TargetIDs(no filter) = %v, want %v", got, want)
	}
}

func TestTargetIDsInvalidFilter(t *testing.T) {
	s := newTestStorage(t)
	_, err := s.TargetIDs(context.Background(), storage.TargetFilter{SSLBelow: "Z"})
	if !errors.Is(err, storage.ErrInvalidGrade) {
		t.Fatalf("TargetIDs(SSLBelow Z) err = %v, want ErrInvalidGrade", err)
	}
}

func TestDeleteTargetsDeletesLiveOnes(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	ids := importHosts(t, s, "d", 4)
	n, err := s.DeleteTargets(ctx, ids[:3])
	if err != nil {
		t.Fatalf("DeleteTargets: %v", err)
	}
	if n != 3 {
		t.Fatalf("DeleteTargets = %d, want 3", n)
	}

	live, err := s.GetTargets(ctx)
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	if len(live) != 1 || live[0].ID != ids[3] {
		t.Errorf("live targets = %d, want only id %d", len(live), ids[3])
	}
	deleted, err := s.ListDeletedTargets(ctx)
	if err != nil {
		t.Fatalf("ListDeletedTargets: %v", err)
	}
	if len(deleted) != 3 {
		t.Errorf("ListDeletedTargets = %d rows, want 3", len(deleted))
	}
}

func TestDeleteTargetsSkipsDeletedAndUnknown(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	ids := importHosts(t, s, "s", 2)
	mustDelete(t, s, ids[0])

	n, err := s.DeleteTargets(ctx, []int{ids[0], 999999, ids[1]})
	if err != nil {
		t.Fatalf("DeleteTargets: %v", err)
	}
	if n != 1 {
		t.Errorf("DeleteTargets = %d, want 1 (only the live id)", n)
	}
}

func TestDeleteTargetsEmpty(t *testing.T) {
	s := newTestStorage(t)
	n, err := s.DeleteTargets(context.Background(), nil)
	if err != nil || n != 0 {
		t.Fatalf("DeleteTargets(nil) = %d, %v; want 0, nil", n, err)
	}
}

func TestDeleteTargetsAcrossChunks(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	ids := importHosts(t, s, "c", 1005)
	n, err := s.DeleteTargets(ctx, ids)
	if err != nil {
		t.Fatalf("DeleteTargets: %v", err)
	}
	if n != 1005 {
		t.Fatalf("DeleteTargets = %d, want 1005", n)
	}
	live, err := s.TargetIDs(ctx, storage.TargetFilter{})
	if err != nil {
		t.Fatalf("TargetIDs: %v", err)
	}
	if len(live) != 0 {
		t.Errorf("%d targets still live after deleting all", len(live))
	}
}

func TestEachTargetWithHistoryVisitsEachLiveTargetOnceInOrder(t *testing.T) {
	s := newTestStorage(t)
	ids := importHosts(t, s, "e", 250)

	// Shuffled, with a duplicate, so batching and ordering both have to work.
	shuffled := slices.Clone(ids)
	rand.New(rand.NewPCG(1, 2)).Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	shuffled = append(shuffled, ids[0])

	var visited []int
	err := s.EachTargetWithHistory(context.Background(), shuffled, func(tg *ent.Target) error {
		visited = append(visited, tg.ID)
		return nil
	})
	if err != nil {
		t.Fatalf("EachTargetWithHistory: %v", err)
	}
	if !slices.Equal(visited, ids) {
		t.Errorf("visited %d targets, want the 250 live ids once each in ascending order", len(visited))
	}
}

func TestEachTargetWithHistorySkipsDeleted(t *testing.T) {
	s := newTestStorage(t)
	ids := importHosts(t, s, "k", 3)
	mustDelete(t, s, ids[1])

	var visited []int
	err := s.EachTargetWithHistory(context.Background(), []int{ids[2], ids[1], 999999, ids[0]}, func(tg *ent.Target) error {
		visited = append(visited, tg.ID)
		return nil
	})
	if err != nil {
		t.Fatalf("EachTargetWithHistory: %v", err)
	}
	if want := []int{ids[0], ids[2]}; !slices.Equal(visited, want) {
		t.Errorf("visited %v, want %v", visited, want)
	}
}

func TestEachTargetWithHistoryLoadsFullHistory(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	ids := importHosts(t, s, "h", 1)
	for _, grade := range []string{"A", "B"} {
		if err := s.SaveSSLScan(ctx, "h0.example", storage.SSLResult{Grade: grade, Status: "READY"}); err != nil {
			t.Fatalf("SaveSSLScan: %v", err)
		}
	}

	var got *ent.Target
	err := s.EachTargetWithHistory(ctx, ids, func(tg *ent.Target) error {
		got = tg
		return nil
	})
	if err != nil {
		t.Fatalf("EachTargetWithHistory: %v", err)
	}
	if got == nil || len(got.Edges.SslScans) != 2 {
		t.Fatalf("expected 2 ssl scans loaded, got %+v", got)
	}
	if g := got.Edges.SslScans[0].Grade; g != "B" {
		t.Errorf("first ssl scan grade %q, want newest (B)", g)
	}
}

func TestEachTargetWithHistoryStopsOnError(t *testing.T) {
	s := newTestStorage(t)
	ids := importHosts(t, s, "x", 3)
	errStop := errors.New("stop")

	calls := 0
	err := s.EachTargetWithHistory(context.Background(), ids, func(*ent.Target) error {
		calls++
		if calls == 2 {
			return errStop
		}
		return nil
	})
	if !errors.Is(err, errStop) {
		t.Fatalf("err = %v, want errStop", err)
	}
	if calls != 2 {
		t.Errorf("fn called %d times, want 2", calls)
	}
}

func TestGetTargetLoadsFullHistory(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	ids := importHosts(t, s, "g", 1)
	for _, grade := range []string{"A", "B"} {
		if err := s.SaveSSLScan(ctx, "g0.example", storage.SSLResult{Grade: grade, Status: "READY"}); err != nil {
			t.Fatalf("SaveSSLScan: %v", err)
		}
	}
	tg, err := s.GetTarget(ctx, ids[0])
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if len(tg.Edges.SslScans) != 2 || tg.Edges.SslScans[0].Grade != "B" {
		t.Errorf("GetTarget ssl scans = %d, want 2 newest first", len(tg.Edges.SslScans))
	}
}

// mustTargetInput returns the input of the live target with id.
func mustTargetInput(t *testing.T, s *storage.EntStorage, id int) string {
	t.Helper()
	tg, err := s.GetTarget(context.Background(), id)
	if err != nil {
		t.Fatalf("GetTarget(%d): %v", id, err)
	}
	return tg.Input
}
