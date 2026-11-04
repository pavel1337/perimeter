package storage

import (
	"context"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/ent/enttest"
	"perimeter/ent/sslscan"
	"perimeter/ent/target"
)

// newSSLFailedClient opens a fresh in-memory database per test (t.Name() is
// unique), so every test starts without scan rows.
func newSSLFailedClient(t *testing.T) (*ent.Client, *EntStorage) {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:"+t.Name()+"?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	t.Cleanup(func() { client.Close() })
	return client, NewEntStorage(client)
}

const sslFailedInput = "example.com"

func sslFailedTargetID(t *testing.T, client *ent.Client) int {
	t.Helper()
	id, err := client.Target.Query().
		Where(target.Input(sslFailedInput)).
		OnlyID(context.Background())
	if err != nil {
		t.Fatalf("find target: %v", err)
	}
	return id
}

// newestSSLScanID returns the id of the target's most recent SSL row.
func newestSSLScanID(t *testing.T, client *ent.Client) int {
	t.Helper()
	scan, err := client.SSLScan.Query().
		Where(sslscan.HasTargetWith(target.Input(sslFailedInput))).
		Order(ent.Desc(sslscan.FieldID)).
		First(context.Background())
	if err != nil {
		t.Fatalf("find newest ssl scan: %v", err)
	}
	return scan.ID
}

// saveSSL writes res and ages the row it produced to at.
func saveSSL(t *testing.T, client *ent.Client, s *EntStorage, res SSLResult, at time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := s.SaveSSLScan(ctx, sslFailedInput, res); err != nil {
		t.Fatalf("SaveSSLScan(%+v): %v", res, err)
	}
	id := newestSSLScanID(t, client)
	if err := client.SSLScan.UpdateOneID(id).SetScannedAt(at).SetLastSeenAt(at).Exec(ctx); err != nil {
		t.Fatalf("age ssl scan to %v: %v", at, err)
	}
	// SaveSSLScan schedules the retry from the real clock; move it with the row.
	if SSLCheckFailed(&ent.SSLScan{Status: res.Status}) {
		if err := client.Target.Update().SetSslRetryAt(at.Add(SSLRetryAfter)).Exec(ctx); err != nil {
			t.Fatalf("age ssl_retry_at: %v", err)
		}
	}
}

// A failed check is stored after the last real result, so the summary must
// keep showing the real one (issue #61).
func TestFailedSSLCheckKeepsLastResult(t *testing.T) {
	client, s := newSSLFailedClient(t)
	ctx := context.Background()
	if _, err := s.ImportTargets(ctx, []string{sslFailedInput}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	exp := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	if err := s.SaveSSLScan(ctx, sslFailedInput, SSLResult{Grade: "A", Status: "READY", CertExpiry: exp}); err != nil {
		t.Fatalf("SaveSSLScan A: %v", err)
	}
	time.Sleep(time.Millisecond)
	if err := s.SaveSSLScan(ctx, sslFailedInput, SSLResult{Status: SSLErrorPrefix + "scan failed"}); err != nil {
		t.Fatalf("SaveSSLScan failed check: %v", err)
	}

	id := sslFailedTargetID(t, client)
	tg, err := s.GetTarget(ctx, id)
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if tg.LatestSslGrade != "A" {
		t.Errorf("latest_ssl_grade = %q, want A (a failed check must not clear it)", tg.LatestSslGrade)
	}
	if want := GradeRank("A"); tg.LatestSslGradeRank != want {
		t.Errorf("latest_ssl_grade_rank = %d, want %d", tg.LatestSslGradeRank, want)
	}
	if tg.LatestCertExpiry == nil || !tg.LatestCertExpiry.Equal(exp) {
		t.Errorf("latest_cert_expiry = %v, want %v", tg.LatestCertExpiry, exp)
	}

	result, failed, err := s.GetLatestSSL(ctx, sslFailedInput)
	if err != nil {
		t.Fatalf("GetLatestSSL: %v", err)
	}
	if result == nil || result.Grade != "A" {
		t.Errorf("GetLatestSSL result = %+v, want grade A", result)
	}
	if failed == nil {
		t.Error("GetLatestSSL failed = nil, want the failed check")
	}

	targets, err := s.GetTargets(ctx)
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	if len(targets) != 1 || len(targets[0].Edges.SslScans) != 1 || targets[0].Edges.SslScans[0].Grade != "A" {
		t.Errorf("GetTargets ssl scans = %+v, want the last real result (A)", targets[0].Edges.SslScans)
	}

	if err := s.SaveSSLScan(ctx, sslFailedInput, SSLResult{Grade: "B", Status: "READY", CertExpiry: exp}); err != nil {
		t.Fatalf("SaveSSLScan B: %v", err)
	}
	tg, err = s.GetTarget(ctx, id)
	if err != nil {
		t.Fatalf("GetTarget after B: %v", err)
	}
	if tg.LatestSslGrade != "B" {
		t.Errorf("latest_ssl_grade after B = %q, want B", tg.LatestSslGrade)
	}
	result, failed, err = s.GetLatestSSL(ctx, sslFailedInput)
	if err != nil {
		t.Fatalf("GetLatestSSL after B: %v", err)
	}
	if result == nil || result.Grade != "B" {
		t.Errorf("GetLatestSSL after B = %+v, want grade B", result)
	}
	if failed != nil {
		t.Errorf("GetLatestSSL failed = %+v, want nil after a real result", failed)
	}
}

func TestOnlyFailedSSLChecks(t *testing.T) {
	client, s := newSSLFailedClient(t)
	ctx := context.Background()
	if _, err := s.ImportTargets(ctx, []string{sslFailedInput}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	if err := s.SaveSSLScan(ctx, sslFailedInput, SSLResult{Status: SSLErrorPrefix + "scan failed"}); err != nil {
		t.Fatalf("SaveSSLScan failed check: %v", err)
	}

	tg, err := s.GetTarget(ctx, sslFailedTargetID(t, client))
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if tg.LatestSslGrade != "" {
		t.Errorf("latest_ssl_grade = %q, want empty (no real result yet)", tg.LatestSslGrade)
	}

	result, failed, err := s.GetLatestSSL(ctx, sslFailedInput)
	if err != nil {
		t.Fatalf("GetLatestSSL: %v", err)
	}
	if result != nil {
		t.Errorf("GetLatestSSL result = %+v, want nil", result)
	}
	if failed == nil || !SSLCheckFailed(failed) {
		t.Errorf("GetLatestSSL failed = %+v, want the failed check", failed)
	}
}

// A failed check is retried after SSLRetryAfter instead of waiting out the
// whole scan interval (issue #61).
func TestFailedSSLCheckIsRetriedSooner(t *testing.T) {
	const threshold = 12 * time.Hour

	realA := SSLResult{Grade: "A", Status: "READY"}
	failedCheck := SSLResult{Status: SSLErrorPrefix + "scan failed"}

	run := func(t *testing.T, setup func(t *testing.T, client *ent.Client, s *EntStorage, now time.Time)) *ent.Target {
		client, s := newSSLFailedClient(t)
		ctx := context.Background()
		if _, err := s.ImportTargets(ctx, []string{sslFailedInput}); err != nil {
			t.Fatalf("ImportTargets: %v", err)
		}
		setup(t, client, s, time.Now())

		got, err := s.GetOldestOutdatedTarget(ctx, ScanTypeSSL, threshold)
		if err != nil {
			t.Fatalf("GetOldestOutdatedTarget: %v", err)
		}
		return got
	}

	t.Run("real result 1h old, no failure: not due", func(t *testing.T) {
		got := run(t, func(t *testing.T, c *ent.Client, s *EntStorage, now time.Time) {
			saveSSL(t, c, s, realA, now.Add(-time.Hour))
		})
		if got != nil {
			t.Errorf("got %s, want nil", got.Input)
		}
	})
	t.Run("real result 1h old, failed check 1h old: retry due", func(t *testing.T) {
		got := run(t, func(t *testing.T, c *ent.Client, s *EntStorage, now time.Time) {
			saveSSL(t, c, s, realA, now.Add(-time.Hour))
			saveSSL(t, c, s, failedCheck, now.Add(-time.Hour))
		})
		if got == nil {
			t.Fatal("want the target (a failed check is retried after SSLRetryAfter), got nil")
		}
	})
	t.Run("real result 1h old, failed check 10m old: not due", func(t *testing.T) {
		got := run(t, func(t *testing.T, c *ent.Client, s *EntStorage, now time.Time) {
			saveSSL(t, c, s, realA, now.Add(-time.Hour))
			saveSSL(t, c, s, failedCheck, now.Add(-10*time.Minute))
		})
		if got != nil {
			t.Errorf("got %s, want nil (retry not due yet)", got.Input)
		}
	})
	t.Run("failed check 1h old, then a real result: not due", func(t *testing.T) {
		got := run(t, func(t *testing.T, c *ent.Client, s *EntStorage, now time.Time) {
			saveSSL(t, c, s, failedCheck, now.Add(-2*time.Hour))
			saveSSL(t, c, s, realA, now.Add(-time.Hour))
		})
		if got != nil {
			t.Errorf("got %s, want nil (the result clears the retry)", got.Input)
		}
	})
	t.Run("real result 13h old: due", func(t *testing.T) {
		got := run(t, func(t *testing.T, c *ent.Client, s *EntStorage, now time.Time) {
			saveSSL(t, c, s, realA, now.Add(-13*time.Hour))
		})
		if got == nil {
			t.Fatal("want the target (outdated), got nil")
		}
	})
	t.Run("never scanned: due", func(t *testing.T) {
		got := run(t, func(t *testing.T, c *ent.Client, s *EntStorage, now time.Time) {})
		if got == nil {
			t.Fatal("want the target (never scanned), got nil")
		}
	})
}

// ClearFailedSSLGrades removes the grade that failed checks stored before
// issue #61, which recorded every SSL Labs error as grade F.
func TestClearFailedSSLGrades(t *testing.T) {
	client, s := newSSLFailedClient(t)
	ctx := context.Background()
	if _, err := s.ImportTargets(ctx, []string{sslFailedInput}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	if err := s.SaveSSLScan(ctx, sslFailedInput, SSLResult{Grade: "A", Status: "READY"}); err != nil {
		t.Fatalf("SaveSSLScan A: %v", err)
	}
	time.Sleep(time.Millisecond)
	if err := s.SaveSSLScan(ctx, sslFailedInput, SSLResult{Status: SSLErrorPrefix + "scan failed"}); err != nil {
		t.Fatalf("SaveSSLScan failed check: %v", err)
	}

	// The pre-#61 shape: the failed check carries a grade.
	failedID := newestSSLScanID(t, client)
	if err := client.SSLScan.UpdateOneID(failedID).SetGrade("F").Exec(ctx); err != nil {
		t.Fatalf("force grade F onto the failed row: %v", err)
	}
	if err := s.BackfillSummary(ctx); err != nil {
		t.Fatalf("BackfillSummary: %v", err)
	}
	id := sslFailedTargetID(t, client)
	tg, err := s.GetTarget(ctx, id)
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	if tg.LatestSslGrade != "A" {
		t.Errorf("latest_ssl_grade = %q, want A (a failed check's grade must not count)", tg.LatestSslGrade)
	}

	if err := s.ClearFailedSSLGrades(ctx); err != nil {
		t.Fatalf("ClearFailedSSLGrades: %v", err)
	}
	row, err := client.SSLScan.Get(ctx, failedID)
	if err != nil {
		t.Fatalf("get failed row: %v", err)
	}
	if row.Grade != "" {
		t.Errorf("failed row grade = %q, want cleared", row.Grade)
	}
	tg, err = s.GetTarget(ctx, id)
	if err != nil {
		t.Fatalf("GetTarget after clear: %v", err)
	}
	if tg.LatestSslGrade != "A" {
		t.Errorf("latest_ssl_grade after clear = %q, want A", tg.LatestSslGrade)
	}

	// Rerunning changes nothing.
	before := client.Target.GetX(ctx, id).UpdateTime
	if err := s.ClearFailedSSLGrades(ctx); err != nil {
		t.Fatalf("ClearFailedSSLGrades (second run): %v", err)
	}
	if after := client.Target.GetX(ctx, id).UpdateTime; !before.Equal(after) {
		t.Errorf("second run touched the target row (%v -> %v)", before, after)
	}
	row, err = client.SSLScan.Get(ctx, failedID)
	if err != nil {
		t.Fatalf("get failed row after second run: %v", err)
	}
	if row.Grade != "" {
		t.Errorf("failed row grade = %q, want still cleared", row.Grade)
	}
}
