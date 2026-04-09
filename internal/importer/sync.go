package importer

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"perimeter/ent"
	"perimeter/ent/importerconfig"
	"perimeter/internal/storage"
)

// SyncLoop periodically checks enabled importers and runs them.
type SyncLoop struct {
	client   *ent.Client
	registry *Registry
	storage  *storage.EntStorage
}

func NewSyncLoop(client *ent.Client, registry *Registry, store *storage.EntStorage) *SyncLoop {
	return &SyncLoop{
		client:   client,
		registry: registry,
		storage:  store,
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
		interval := time.Duration(cfg.SyncIntervalSeconds) * time.Second
		if cfg.LastSyncAt != nil && now.Before(cfg.LastSyncAt.Add(interval)) {
			continue // Not due yet
		}

		source, err := s.registry.Get(cfg.Provider.String(), json.RawMessage(cfg.Credentials))
		if err != nil {
			log.Printf("Importer sync: failed to create source for %s (id=%d): %v", cfg.Provider, cfg.ID, err)
			continue
		}

		targets, err := source.Fetch(ctx)
		if err != nil {
			log.Printf("Importer sync: fetch failed for %s (id=%d): %v", cfg.Provider, cfg.ID, err)
			continue
		}

		if len(targets) > 0 {
			count, err := s.storage.ImportTargets(ctx, targets)
			if err != nil {
				log.Printf("Importer sync: import failed for %s (id=%d): %v", cfg.Provider, cfg.ID, err)
			} else {
				log.Printf("Importer sync: %s (id=%d) imported %d targets", cfg.Provider, cfg.ID, count)
			}
		}

		// Update last_sync_at
		s.client.ImporterConfig.UpdateOne(cfg).SetLastSyncAt(now).Exec(ctx)
	}
}
