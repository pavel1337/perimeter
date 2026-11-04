package storage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/internal/storage"
)

// liveHas reports whether a live (non-deleted) target with this input exists.
func liveHas(t *testing.T, s *storage.EntStorage, input string) bool {
	t.Helper()
	targets, err := s.GetTargets(context.Background())
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	for _, tg := range targets {
		if tg.Input == input {
			return true
		}
	}
	return false
}

func mustDelete(t *testing.T, s *storage.EntStorage, id int) {
	t.Helper()
	if err := s.DeleteTarget(context.Background(), id); err != nil {
		t.Fatalf("DeleteTarget(%d): %v", id, err)
	}
}

func idOf(t *testing.T, s *storage.EntStorage, input string) int {
	t.Helper()
	return targetByInput(t, s, input).ID
}

func TestDeleteHidesTargetEverywhere(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"example.com", "keep.test"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	id := idOf(t, s, "example.com")
	mustDelete(t, s, id)

	if liveHas(t, s, "example.com") {
		t.Error("GetTargets still returns the deleted target")
	}
	list, err := s.ListTargets(ctx, storage.TargetFilter{}, storage.TargetSort{}, 0, 0)
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(list) != 1 || list[0].Input != "keep.test" {
		t.Errorf("ListTargets = %d rows, want only keep.test", len(list))
	}
	stats, err := s.TargetStats(ctx, storage.TargetFilter{}, time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("TargetStats: %v", err)
	}
	if stats.Total != 1 {
		t.Errorf("TargetStats.Total = %d, want 1", stats.Total)
	}
	if _, err := s.GetTarget(ctx, id); !ent.IsNotFound(err) {
		t.Errorf("GetTarget error = %v, want NotFound", err)
	}
	if _, err := s.GetTargetBasic(ctx, id); !ent.IsNotFound(err) {
		t.Errorf("GetTargetBasic error = %v, want NotFound", err)
	}

	oldest, err := s.GetOldestOutdatedTarget(ctx, storage.ScanTypeSSL, time.Hour)
	if err != nil {
		t.Fatalf("GetOldestOutdatedTarget: %v", err)
	}
	if oldest == nil || oldest.Input != "keep.test" {
		t.Errorf("GetOldestOutdatedTarget = %v, want keep.test", oldest)
	}

	// example.com has no IPs, so it would be unresolved if it were live.
	unresolved, err := s.GetTargetsDueForResolution(ctx, 10, time.Now())
	if err != nil {
		t.Fatalf("GetTargetsDueForResolution: %v", err)
	}
	for _, tg := range unresolved {
		if tg.Input == "example.com" {
			t.Error("GetTargetsDueForResolution returns the deleted target")
		}
	}

	deleted, err := s.ListDeletedTargets(ctx)
	if err != nil {
		t.Fatalf("ListDeletedTargets: %v", err)
	}
	if len(deleted) != 1 || deleted[0].Input != "example.com" {
		t.Errorf("ListDeletedTargets = %d rows, want example.com", len(deleted))
	}
	if n, err := s.CountDeletedTargets(ctx); err != nil || n != 1 {
		t.Errorf("CountDeletedTargets = %d, %v; want 1", n, err)
	}
}

func TestDeleteNotFound(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if err := s.DeleteTarget(ctx, 9999); !errors.Is(err, storage.ErrTargetNotFound) {
		t.Errorf("delete unknown id: err = %v, want ErrTargetNotFound", err)
	}

	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	id := idOf(t, s, "example.com")
	mustDelete(t, s, id)
	if err := s.DeleteTarget(ctx, id); !errors.Is(err, storage.ErrTargetNotFound) {
		t.Errorf("delete twice: err = %v, want ErrTargetNotFound", err)
	}
}

func TestDeleteKeepsHistoryAcrossRestore(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	if err := s.SaveSSLScan(ctx, "example.com", storage.SSLResult{Grade: "A", Status: "READY"}); err != nil {
		t.Fatalf("SaveSSLScan: %v", err)
	}
	id := idOf(t, s, "example.com")

	mustDelete(t, s, id)
	if err := s.RestoreTarget(ctx, id); err != nil {
		t.Fatalf("RestoreTarget: %v", err)
	}

	if _, total, err := s.GetSSLScansPage(ctx, id, 10, 0); err != nil || total != 1 {
		t.Errorf("GetSSLScansPage total = %d, %v; want 1", total, err)
	}
	if !liveHas(t, s, "example.com") {
		t.Error("restored target missing from GetTargets")
	}
	if n, err := s.CountDeletedTargets(ctx); err != nil || n != 0 {
		t.Errorf("CountDeletedTargets = %d, %v; want 0", n, err)
	}
}

func TestRestoreLiveTargetNotFound(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	id := idOf(t, s, "example.com")
	if err := s.RestoreTarget(ctx, id); !errors.Is(err, storage.ErrTargetNotFound) {
		t.Errorf("restore live target: err = %v, want ErrTargetNotFound", err)
	}
	if err := s.RestoreTarget(ctx, 9999); !errors.Is(err, storage.ErrTargetNotFound) {
		t.Errorf("restore unknown id: err = %v, want ErrTargetNotFound", err)
	}
}

func TestReimportRevivesDeletedTarget(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	if err := s.SaveSSLScan(ctx, "example.com", storage.SSLResult{Grade: "A", Status: "READY"}); err != nil {
		t.Fatalf("SaveSSLScan: %v", err)
	}
	id := idOf(t, s, "example.com")
	mustDelete(t, s, id)

	count, err := s.ImportTargets(ctx, []string{"example.com"})
	if err != nil {
		t.Fatalf("ImportTargets again: %v", err)
	}
	if count != 1 {
		t.Errorf("ImportTargets count = %d, want 1", count)
	}
	if got := idOf(t, s, "example.com"); got != id {
		t.Errorf("revived target id = %d, want %d", got, id)
	}
	if n, err := s.CountDeletedTargets(ctx); err != nil || n != 0 {
		t.Errorf("CountDeletedTargets = %d, %v; want 0", n, err)
	}
	if _, total, err := s.GetSSLScansPage(ctx, id, 10, 0); err != nil || total != 1 {
		t.Errorf("GetSSLScansPage total = %d, %v; want 1", total, err)
	}
}

func TestPurgeLiveTargetNotFound(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	id := idOf(t, s, "example.com")
	if err := s.PurgeTarget(ctx, id); !errors.Is(err, storage.ErrTargetNotFound) {
		t.Fatalf("purge live target: err = %v, want ErrTargetNotFound", err)
	}
	if _, err := s.GetTarget(ctx, id); err != nil {
		t.Errorf("live target gone after refused purge: %v", err)
	}
}

func TestPurgeDeletedTargetRemovesScans(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	if err := s.SaveSSLScan(ctx, "example.com", storage.SSLResult{Grade: "A", Status: "READY"}); err != nil {
		t.Fatalf("SaveSSLScan: %v", err)
	}
	id := idOf(t, s, "example.com")
	mustDelete(t, s, id)

	if err := s.PurgeTarget(ctx, id); err != nil {
		t.Fatalf("PurgeTarget: %v", err)
	}
	if n, err := s.CountDeletedTargets(ctx); err != nil || n != 0 {
		t.Errorf("CountDeletedTargets = %d, %v; want 0", n, err)
	}
	if _, total, err := s.GetSSLScansPage(ctx, id, 10, 0); err != nil || total != 0 {
		t.Errorf("GetSSLScansPage total = %d, %v; want 0", total, err)
	}
	if err := s.PurgeTarget(ctx, id); !errors.Is(err, storage.ErrTargetNotFound) {
		t.Errorf("purge twice: err = %v, want ErrTargetNotFound", err)
	}

	// The input is free again: importing it creates a fresh target.
	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets after purge: %v", err)
	}
	if _, total, err := s.GetSSLScansPage(ctx, idOf(t, s, "example.com"), 10, 0); err != nil || total != 0 {
		t.Errorf("fresh target SSL total = %d, %v; want 0", total, err)
	}
}

func TestGetOutdatedIPsSkipsDeletedOnlyIPs(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"a.test", "b.test", "c.test"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	if err := s.SaveIPs(ctx, "a.test", []string{"1.1.1.1"}, time.Hour); err != nil {
		t.Fatalf("SaveIPs a: %v", err)
	}
	if err := s.SaveIPs(ctx, "b.test", []string{"1.1.1.1"}, time.Hour); err != nil {
		t.Fatalf("SaveIPs b: %v", err)
	}
	if err := s.SaveIPs(ctx, "c.test", []string{"2.2.2.2"}, time.Hour); err != nil {
		t.Fatalf("SaveIPs c: %v", err)
	}

	outdated := func() []string {
		t.Helper()
		ips, err := s.GetOutdatedIPs(ctx, 10, time.Hour)
		if err != nil {
			t.Fatalf("GetOutdatedIPs: %v", err)
		}
		var addrs []string
		for _, i := range ips {
			addrs = append(addrs, i.Address)
		}
		return addrs
	}
	contains := func(list []string, want string) bool {
		for _, a := range list {
			if a == want {
				return true
			}
		}
		return false
	}

	mustDelete(t, s, idOf(t, s, "c.test"))
	got := outdated()
	if contains(got, "2.2.2.2") {
		t.Errorf("IP of deleted-only target returned: %v", got)
	}
	if !contains(got, "1.1.1.1") {
		t.Errorf("shared IP missing while both targets are live: %v", got)
	}

	mustDelete(t, s, idOf(t, s, "a.test"))
	if got := outdated(); !contains(got, "1.1.1.1") {
		t.Errorf("shared IP missing with one live target left: %v", got)
	}
}

func TestRestoreRefreshesSummary(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"10.0.0.1"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	if err := s.SaveIPs(ctx, "10.0.0.1", []string{"10.0.0.1"}, time.Hour); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}
	id := idOf(t, s, "10.0.0.1")
	mustDelete(t, s, id)

	// The target is hidden, so the summary refresh inside SavePortScan skips it.
	if err := s.SavePortScan(ctx, "10.0.0.1", []int{22}); err != nil {
		t.Fatalf("SavePortScan: %v", err)
	}
	if err := s.RestoreTarget(ctx, id); err != nil {
		t.Fatalf("RestoreTarget: %v", err)
	}
	if got := targetByInput(t, s, "10.0.0.1").OpenPortCount; got != 1 {
		t.Errorf("OpenPortCount after restore = %d, want 1", got)
	}
}

// A restored target is rescanned at once: every kind is flagged, the name is
// due for resolution, and the SSL and CSP producers pick it first (#75).
func TestRestoreRequestsRescan(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	if _, err := s.ImportTargets(ctx, []string{"old.test", "other.test"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	for _, in := range []string{"old.test", "other.test"} {
		if err := s.SaveIPs(ctx, in, []string{"192.0.2.7"}, time.Hour); err != nil {
			t.Fatalf("SaveIPs: %v", err)
		}
	}
	ids := map[string]int{}
	targets, err := s.GetTargets(ctx)
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	for _, tg := range targets {
		ids[tg.Input] = tg.ID
	}
	if err := s.DeleteTarget(ctx, ids["old.test"]); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}
	if err := s.RestoreTarget(ctx, ids["old.test"]); err != nil {
		t.Fatalf("RestoreTarget: %v", err)
	}

	tg, err := s.GetTarget(ctx, ids["old.test"])
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if !tg.SslRescanPending || !tg.CspRescanPending || tg.RescanRequestedAt == nil || tg.NextResolveAt != nil {
		t.Errorf("after restore: ssl=%v csp=%v requested=%v next_resolve=%v, want a full rescan",
			tg.SslRescanPending, tg.CspRescanPending, tg.RescanRequestedAt, tg.NextResolveAt)
	}
	for _, kind := range []storage.ScanType{storage.ScanTypeSSL, storage.ScanTypeCSP} {
		next, err := s.GetOldestOutdatedTarget(ctx, kind, time.Hour)
		if err != nil || next == nil || next.Input != "old.test" {
			t.Errorf("%s producer picks %v (err %v), want the restored target first", kind, next, err)
		}
	}
	due, err := s.GetTargetsDueForResolution(ctx, 10, time.Now())
	if err != nil || len(due) != 1 || due[0].Input != "old.test" {
		t.Errorf("due for resolution = %v (err %v), want the restored target", due, err)
	}
	ipsRescan, err := s.GetOutdatedIPs(ctx, 10, time.Hour)
	if err != nil || len(ipsRescan) != 1 {
		t.Errorf("outdated IPs = %v (err %v), want the restored target's IP flagged", ipsRescan, err)
	}
}
