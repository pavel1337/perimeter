package storage_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"perimeter/ent/enttest"
	"perimeter/ent/job"
	"perimeter/internal/storage"

	sqlite "modernc.org/sqlite"
)

// modernc.org/sqlite registers itself as "sqlite"; ent opens the "sqlite3"
// driver name, so alias it here. Pure-Go, no CGO.
func init() { sql.Register("sqlite3", &sqlite.Driver{}) }

func newTestStorage(t *testing.T) *storage.EntStorage {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	t.Cleanup(func() { client.Close() })
	return storage.NewEntStorage(client)
}

func TestImportTargets(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	count, err := s.ImportTargets(ctx, []string{"example.com", "1.2.3.4", ""})
	if err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2, got %d", count)
	}

	targets, err := s.GetTargets(ctx)
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	if len(targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(targets))
	}
}

func TestImportTargetsIdempotent(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}

	targets, err := s.GetTargets(ctx)
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	if len(targets) != 1 {
		t.Errorf("expected 1 target, got %d", len(targets))
	}
}

func TestDeleteTarget(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	targets, _ := s.GetTargets(ctx)
	if len(targets) != 1 {
		t.Fatalf("expected 1 target")
	}

	err := s.DeleteTarget(ctx, targets[0].ID)
	if err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}

	targets, _ = s.GetTargets(ctx)
	if len(targets) != 0 {
		t.Errorf("expected 0 targets, got %d", len(targets))
	}
}

func TestJobCreateClaimComplete(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	_, err := s.CreateJob(ctx, job.TypeResolve, map[string]any{"input": "example.com"})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	j, err := s.ClaimJob(ctx, 5*time.Minute)
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}
	if j == nil {
		t.Fatal("expected a job, got nil")
	}
	if j.Type != job.TypeResolve {
		t.Errorf("expected resolve, got %s", j.Type)
	}

	err = s.CompleteJob(ctx, j.ID, nil)
	if err != nil {
		t.Fatalf("CompleteJob: %v", err)
	}

	// No more jobs
	j2, err := s.ClaimJob(ctx, 5*time.Minute)
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}
	if j2 != nil {
		t.Error("expected no more jobs")
	}
}

func TestJobFail(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	_, err := s.CreateJob(ctx, job.TypePortScan, map[string]any{"address": "1.2.3.4"})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	j, _ := s.ClaimJob(ctx, 5*time.Minute)
	err = s.FailJob(ctx, j.ID, "connection refused")
	if err != nil {
		t.Fatalf("FailJob: %v", err)
	}
}

func TestHasPendingJob(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	has, err := s.HasPendingJob(ctx, job.TypeResolve, "input", "example.com")
	if err != nil {
		t.Fatalf("HasPendingJob: %v", err)
	}
	if has {
		t.Error("expected no pending job")
	}

	if _, err := s.CreateJob(ctx, job.TypeResolve, map[string]any{"input": "example.com"}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	has, err = s.HasPendingJob(ctx, job.TypeResolve, "input", "example.com")
	if err != nil {
		t.Fatalf("HasPendingJob: %v", err)
	}
	if !has {
		t.Error("expected pending job")
	}
}

func TestRecoverStaleJobs(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.CreateJob(ctx, job.TypeResolve, map[string]any{"input": "example.com"}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	// Claim with very short timeout
	j, _ := s.ClaimJob(ctx, 1*time.Millisecond)
	if j == nil {
		t.Fatal("expected a job")
	}

	// Wait for timeout
	time.Sleep(5 * time.Millisecond)

	n, err := s.RecoverStaleJobs(ctx)
	if err != nil {
		t.Fatalf("RecoverStaleJobs: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 recovered, got %d", n)
	}

	// Should be claimable again
	j2, _ := s.ClaimJob(ctx, 5*time.Minute)
	if j2 == nil {
		t.Error("expected job to be reclaimable after recovery")
	}
}

func TestSaveAndGetPortScan(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	if err := s.SaveIPs(ctx, "example.com", []string{"1.2.3.4"}); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}

	err := s.SavePortScan(ctx, "1.2.3.4", []int{80, 443})
	if err != nil {
		t.Fatalf("SavePortScan: %v", err)
	}

	ports, err := s.GetPreviousPortCounts(ctx, "1.2.3.4")
	if err != nil {
		t.Fatalf("GetPreviousPortCounts: %v", err)
	}
	if len(ports) != 2 {
		t.Errorf("expected 2 ports, got %d", len(ports))
	}
}

func TestSaveSSLScan(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if _, err := s.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}

	err := s.SaveSSLScan(ctx, "example.com", storage.SSLResult{
		Grade:  "A+",
		Status: "Ready",
	})
	if err != nil {
		t.Fatalf("SaveSSLScan: %v", err)
	}

	grade, err := s.GetPreviousSSLGrade(ctx, "example.com")
	if err != nil {
		t.Fatalf("GetPreviousSSLGrade: %v", err)
	}
	if grade != "A+" {
		t.Errorf("expected A+, got %s", grade)
	}
}
