package importer

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sync"
	"time"

	"perimeter/ent"
	"perimeter/ent/importerconfig"
	"perimeter/internal/storage"
)

// ErrSyncRunning is returned by SyncOne when the importer is already syncing.
var ErrSyncRunning = errors.New("sync already running")

// lastErrorLimit caps the stored error message.
const lastErrorLimit = 500

// backoffFloor is the smallest sync interval the backoff multiplies.
const backoffFloor = 60 * time.Second

// backoffCap is the largest retry interval after failures.
const backoffCap = 24 * time.Hour

// SyncLoop periodically checks enabled importers and runs them.
type SyncLoop struct {
	client   *ent.Client
	registry *Registry
	storage  *storage.EntStorage
	// running guards against the loop and the "Sync now" button syncing the
	// same importer at once.
	mu      sync.Mutex
	running map[int]bool
}

func NewSyncLoop(client *ent.Client, registry *Registry, store *storage.EntStorage) *SyncLoop {
	return &SyncLoop{
		client:   client,
		registry: registry,
		storage:  store,
		running:  make(map[int]bool),
	}
}

// Start runs the sync loop in a goroutine.
func (s *SyncLoop) Start() {
	go s.run()
}

func (s *SyncLoop) run() {
	log.Println("Importer sync loop started")
	for {
		ctx := context.Background()
		s.tick(ctx)
		time.Sleep(30 * time.Second)
	}
}

func (s *SyncLoop) tick(ctx context.Context) {
	configs, err := s.client.ImporterConfig.Query().
		Where(importerconfig.EnabledEQ(true)).
		All(ctx)
	if err != nil {
		log.Printf("Importer sync: error fetching configs: %v", err)
		return
	}

	now := time.Now()
	for _, cfg := range configs {
		if !due(cfg, now) {
			continue // Not due yet
		}
		// SyncOne logs and records failures itself; ErrSyncRunning means the
		// "Sync now" button is mid-sync, so skip it.
		_, _ = s.SyncOne(ctx, cfg)
	}
}

// due reports whether cfg should sync at now. After failures it uses an
// exponential backoff measured from the last attempt; otherwise the plain
// interval measured from the last successful sync.
func due(cfg *ent.ImporterConfig, now time.Time) bool {
	if cfg.ConsecutiveFailures == 0 {
		if cfg.LastSyncAt == nil {
			return true
		}
		interval := time.Duration(cfg.SyncIntervalSeconds) * time.Second
		return !now.Before(cfg.LastSyncAt.Add(interval))
	}

	interval := time.Duration(cfg.SyncIntervalSeconds) * time.Second
	if interval < backoffFloor {
		interval = backoffFloor
	}
	backoff := interval
	// Double per failure past the first; stop once the cap is reached so
	// the multiplication cannot overflow.
	for i := 1; i < cfg.ConsecutiveFailures && backoff < backoffCap; i++ {
		backoff *= 2
	}
	if backoff > backoffCap {
		backoff = backoffCap
	}
	if cfg.LastAttemptAt == nil {
		return true
	}
	return !now.Before(cfg.LastAttemptAt.Add(backoff))
}

// SyncOne runs one importer and records the outcome: success refreshes
// last_sync_at and clears the failure state, failure records the error and
// backs off the next attempt. It returns the number of targets imported.
func (s *SyncLoop) SyncOne(ctx context.Context, cfg *ent.ImporterConfig) (int, error) {
	s.mu.Lock()
	if s.running[cfg.ID] {
		s.mu.Unlock()
		return 0, ErrSyncRunning
	}
	s.running[cfg.ID] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.running, cfg.ID)
		s.mu.Unlock()
	}()

	now := time.Now()

	source, err := s.registry.Get(cfg.Provider.String(), json.RawMessage(cfg.Credentials))
	if err != nil {
		log.Printf("Importer sync: failed to create source for %s (id=%d): %v", cfg.Provider, cfg.ID, err)
		s.recordFailure(ctx, cfg, now, err)
		return 0, err
	}

	targets, fetchErr := source.Fetch(ctx)
	var partial *ZoneErrors
	if fetchErr != nil && !errors.As(fetchErr, &partial) {
		log.Printf("Importer sync: fetch failed for %s (id=%d): %v", cfg.Provider, cfg.ID, fetchErr)
		s.recordFailure(ctx, cfg, now, fetchErr)
		return 0, fetchErr
	}

	count := 0
	if len(targets) > 0 {
		res, err := s.storage.SyncTargets(ctx, targets)
		if err != nil {
			log.Printf("Importer sync: import failed for %s (id=%d): %v", cfg.Provider, cfg.ID, err)
			s.recordFailure(ctx, cfg, now, err)
			return 0, err
		}
		count = len(res.Added) + len(res.Existing)
		log.Printf("Importer sync: %s (id=%d) imported %d targets, left %d deleted ones deleted", cfg.Provider, cfg.ID, count, len(res.Deleted))
	}

	// Some zones failed: what loaded is imported, but the sync is a failure,
	// so last_sync_at stays and the backoff applies. Anything that removes
	// targets missing from the source must skip a sync like this (#71).
	if partial != nil {
		log.Printf("Importer sync: %s (id=%d) partial, %v", cfg.Provider, cfg.ID, partial)
		s.recordFailure(ctx, cfg, now, partial)
		return count, partial
	}

	update := s.client.ImporterConfig.UpdateOne(cfg).
		SetLastSyncAt(now).
		SetLastAttemptAt(now).
		ClearLastError().
		SetConsecutiveFailures(0)
	if err := update.Exec(ctx); err != nil {
		log.Printf("Importer sync: failed to update last_sync_at for %s (id=%d): %v", cfg.Provider, cfg.ID, err)
	}
	return count, nil
}

// recordFailure stores the failed attempt. last_sync_at is left alone, so
// the last successful sync stays visible.
func (s *SyncLoop) recordFailure(ctx context.Context, cfg *ent.ImporterConfig, now time.Time, err error) {
	msg := err.Error()
	if len(msg) > lastErrorLimit {
		msg = msg[:lastErrorLimit]
	}
	// Add, not Set: cfg may be stale, and the loop and the button race.
	update := s.client.ImporterConfig.UpdateOne(cfg).
		SetLastAttemptAt(now).
		SetLastError(msg).
		AddConsecutiveFailures(1)
	if err := update.Exec(ctx); err != nil {
		log.Printf("Importer sync: failed to record sync failure for %s (id=%d): %v", cfg.Provider, cfg.ID, err)
	}
}
