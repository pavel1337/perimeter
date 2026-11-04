package importer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/ent/enttest"
	"perimeter/ent/importerconfig"
	"perimeter/internal/storage"

	sqlite "modernc.org/sqlite"
)

// ent opens the "sqlite3" driver name; modernc registers itself as "sqlite".
func init() { sql.Register("sqlite3", &sqlite.Driver{}) }

func newTestClient(t *testing.T) *ent.Client {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	t.Cleanup(func() { client.Close() })
	return client
}

// fakeSource is a Source with fixed results, for the SyncOne tests.
type fakeSource struct {
	targets []string
	err     error
}

func (f *fakeSource) Name() string { return "fake" }

// Fetch returns both, so a partial result (targets plus *ZoneErrors) can be
// faked.
func (f *fakeSource) Fetch(context.Context) ([]string, error) {
	return f.targets, f.err
}

// syncLoopFixture builds a SyncLoop over an in-memory sqlite client with a
// fake source registered under provider. A nil src leaves it unregistered.
func syncLoopFixture(t *testing.T, provider importerconfig.Provider, src *fakeSource) (*SyncLoop, *ent.Client) {
	t.Helper()
	client := newTestClient(t)
	reg := NewRegistry()
	if src != nil {
		reg.Register(string(provider), func(config json.RawMessage) (Source, error) { return src, nil })
	}
	return NewSyncLoop(client, reg, storage.NewEntStorage(client)), client
}

func newImporterConfig(t *testing.T, client *ent.Client, provider importerconfig.Provider) *ent.ImporterConfig {
	t.Helper()
	cfg, err := client.ImporterConfig.Create().
		SetProvider(provider).
		SetCredentials(json.RawMessage(`{}`)).
		SetSyncIntervalSeconds(3600).
		SetEnabled(true).
		Save(context.Background())
	if err != nil {
		t.Fatalf("create importer config: %v", err)
	}
	return cfg
}

func ptrT(tm time.Time) *time.Time { return &tm }

func TestDue(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name          string
		interval      int64
		failures      int
		lastSyncAt    *time.Time
		lastAttemptAt *time.Time
		want          bool
	}{
		{name: "never synced is due", interval: 3600, want: true},
		{name: "recent success not due", interval: 3600, lastSyncAt: ptrT(now.Add(-30 * time.Minute)), want: false},
		{name: "success interval elapsed is due", interval: 3600, lastSyncAt: ptrT(now.Add(-time.Hour)), want: true},
		{name: "failures with no attempt are due", interval: 3600, failures: 1, want: true},
		{name: "first failure backs off one interval", interval: 3600, failures: 1, lastAttemptAt: ptrT(now.Add(-30 * time.Minute)), want: false},
		{name: "first failure interval elapsed", interval: 3600, failures: 1, lastAttemptAt: ptrT(now.Add(-time.Hour)), want: true},
		{name: "second failure doubles the backoff", interval: 3600, failures: 2, lastAttemptAt: ptrT(now.Add(-time.Hour)), want: false},
		{name: "doubled backoff elapsed", interval: 3600, failures: 2, lastAttemptAt: ptrT(now.Add(-2 * time.Hour)), want: true},
		{name: "short interval floored at 60s", interval: 30, failures: 1, lastAttemptAt: ptrT(now.Add(-30 * time.Second)), want: false},
		{name: "floored interval elapsed", interval: 30, failures: 1, lastAttemptAt: ptrT(now.Add(-61 * time.Second)), want: true},
		{name: "backoff capped at 24h", interval: 3600, failures: 10, lastAttemptAt: ptrT(now.Add(-23 * time.Hour)), want: false},
		{name: "backoff cap elapsed", interval: 3600, failures: 10, lastAttemptAt: ptrT(now.Add(-25 * time.Hour)), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ent.ImporterConfig{
				SyncIntervalSeconds: tt.interval,
				ConsecutiveFailures: tt.failures,
				LastSyncAt:          tt.lastSyncAt,
				LastAttemptAt:       tt.lastAttemptAt,
			}
			if got := due(cfg, now); got != tt.want {
				t.Errorf("due = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSyncOneSuccess(t *testing.T) {
	loop, client := syncLoopFixture(t, importerconfig.ProviderGandi, &fakeSource{targets: []string{"example.com", "1.2.3.4"}})
	cfg := newImporterConfig(t, client, importerconfig.ProviderGandi)
	// A prior failure, so the success clears it.
	if _, err := client.ImporterConfig.UpdateOne(cfg).SetConsecutiveFailures(2).SetLastError("boom").Save(context.Background()); err != nil {
		t.Fatalf("seed failure state: %v", err)
	}

	count, err := loop.SyncOne(context.Background(), cfg)
	if err != nil {
		t.Fatalf("SyncOne: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}

	updated, err := client.ImporterConfig.Get(context.Background(), cfg.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if updated.LastSyncAt == nil {
		t.Error("last_sync_at not set after success")
	}
	if updated.LastAttemptAt == nil {
		t.Error("last_attempt_at not set after success")
	}
	if updated.LastError != "" {
		t.Errorf("last_error = %q, want empty", updated.LastError)
	}
	if updated.ConsecutiveFailures != 0 {
		t.Errorf("consecutive_failures = %d, want 0", updated.ConsecutiveFailures)
	}
}

func TestSyncOneFailure(t *testing.T) {
	tests := []struct {
		name     string
		provider importerconfig.Provider
		src      *fakeSource
		wantErr  string
	}{
		{name: "fetch fails", provider: importerconfig.ProviderGandi, src: &fakeSource{err: errors.New("boom")}, wantErr: "boom"},
		{name: "unknown provider", provider: importerconfig.ProviderNamecheap, wantErr: "unknown importer provider"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loop, client := syncLoopFixture(t, tt.provider, tt.src)
			cfg := newImporterConfig(t, client, tt.provider)
			// A prior failure, so the counter increments on top of it.
			if _, err := client.ImporterConfig.UpdateOne(cfg).SetConsecutiveFailures(1).Save(context.Background()); err != nil {
				t.Fatalf("seed failures: %v", err)
			}

			count, err := loop.SyncOne(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("SyncOne error = %v, want one containing %q", err, tt.wantErr)
			}
			if count != 0 {
				t.Errorf("count = %d, want 0", count)
			}

			updated, err := client.ImporterConfig.Get(context.Background(), cfg.ID)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if updated.LastSyncAt != nil {
				t.Error("last_sync_at set after failure")
			}
			if updated.LastAttemptAt == nil {
				t.Error("last_attempt_at not set after failure")
			}
			if updated.ConsecutiveFailures != 2 {
				t.Errorf("consecutive_failures = %d, want 2", updated.ConsecutiveFailures)
			}
			if !strings.Contains(updated.LastError, tt.wantErr) {
				t.Errorf("last_error = %q, want one containing %q", updated.LastError, tt.wantErr)
			}
		})
	}
}

func TestSyncOneTruncatesLastError(t *testing.T) {
	loop, client := syncLoopFixture(t, importerconfig.ProviderGandi, &fakeSource{err: errors.New(strings.Repeat("x", 600))})
	cfg := newImporterConfig(t, client, importerconfig.ProviderGandi)
	if _, err := loop.SyncOne(context.Background(), cfg); err == nil {
		t.Fatal("SyncOne: expected error")
	}

	updated, err := client.ImporterConfig.Get(context.Background(), cfg.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(updated.LastError) != lastErrorLimit {
		t.Errorf("last_error length = %d, want %d", len(updated.LastError), lastErrorLimit)
	}
}

func TestSyncOneRunning(t *testing.T) {
	loop, client := syncLoopFixture(t, importerconfig.ProviderGandi, &fakeSource{})
	cfg := newImporterConfig(t, client, importerconfig.ProviderGandi)

	loop.mu.Lock()
	loop.running[cfg.ID] = true
	loop.mu.Unlock()

	if _, err := loop.SyncOne(context.Background(), cfg); !errors.Is(err, ErrSyncRunning) {
		t.Fatalf("SyncOne error = %v, want ErrSyncRunning", err)
	}
}

// Zones that failed to load don't make a sync successful: the names that did
// load are imported, and the sync is recorded as failed with the zone's name
// (issue #71).
func TestSyncOnePartial(t *testing.T) {
	partial := &ZoneErrors{Zones: []ZoneError{{Zone: "example.org", Err: errors.New("gandi API returned 500")}}}
	loop, client := syncLoopFixture(t, importerconfig.ProviderGandi, &fakeSource{
		targets: []string{"example.com", "www.example.com"},
		err:     partial,
	})
	cfg := newImporterConfig(t, client, importerconfig.ProviderGandi)

	count, err := loop.SyncOne(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "zone example.org: gandi API returned 500") {
		t.Fatalf("SyncOne error = %v, want the failed zone", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want the 2 names that loaded", count)
	}
	n, err := client.Target.Query().Count(context.Background())
	if err != nil || n != 2 {
		t.Errorf("targets = %d (err %v), want 2 imported", n, err)
	}
	updated, err := client.ImporterConfig.Get(context.Background(), cfg.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if updated.LastSyncAt != nil {
		t.Error("last_sync_at moved on a partial sync")
	}
	if updated.ConsecutiveFailures != 1 {
		t.Errorf("consecutive_failures = %d, want 1 (backoff applies)", updated.ConsecutiveFailures)
	}
	if !strings.Contains(updated.LastError, "zone example.org") {
		t.Errorf("last_error = %q, want the zone name", updated.LastError)
	}
}
