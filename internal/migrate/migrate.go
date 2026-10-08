// Package migrate runs one-off data migrations in a fixed order, once each.
//
// Ent's auto-migration handles schema DDL. What it cannot do is rewrite rows,
// so every backfill lives here: one entry in the list below, applied in order,
// recorded in the data_migrations table so later boots skip it.
package migrate

import (
	"context"
	"fmt"
	"log"
	"time"

	"perimeter/ent"
	"perimeter/ent/datamigration"
	"perimeter/ent/schema"
	"perimeter/internal/storage"
)

// Migration is one named data migration.
//
// The ledger row is written only after Run returns nil, so a crash mid-run
// leaves no row and the next boot runs it again. Run must therefore be
// idempotent on its own — the ledger skips repeat work, it does not make
// unsafe work safe.
type Migration struct {
	Name string
	Run  func(context.Context, *ent.Client) error
}

// migrations run in slice order. Append only; never renumber or edit a name
// that has shipped, or it runs a second time on existing deployments.
var migrations = []Migration{
	{
		Name: "0001_collapse_scan_history",
		Run: func(ctx context.Context, client *ent.Client) error {
			return storage.NewEntStorage(client).CollapseScanHistory(ctx)
		},
	},
	{
		Name: "0002_target_reachability",
		Run: func(ctx context.Context, client *ent.Client) error {
			return storage.NewEntStorage(client).BackfillReachability(ctx)
		},
	},
	{
		Name: "0003_target_summary",
		Run: func(ctx context.Context, client *ent.Client) error {
			return storage.NewEntStorage(client).BackfillSummary(ctx)
		},
	},
}

// Run applies every migration that has not been applied yet. Call it after
// Ent auto-migration and before anything reads or writes scan data.
//
// ponytail: no lock, so two instances booting at once can both run a
// migration. Migrations are idempotent and the unique name means only one
// ledger row survives; add an advisory lock if this ever runs multi-instance.
func Run(ctx context.Context, client *ent.Client) error {
	return run(ctx, client, migrations)
}

func run(ctx context.Context, client *ent.Client, ms []Migration) error {
	for _, m := range ms {
		applied, err := client.DataMigration.Query().
			Where(datamigration.Name(m.Name)).
			Exist(ctx)
		if err != nil {
			return fmt.Errorf("migration %s: reading ledger: %w", m.Name, err)
		}
		if applied {
			continue
		}

		log.Printf("Migration %s: running", m.Name)
		started := time.Now()
		// Data migrations normalise every row, soft-deleted targets included.
		if err := m.Run(schema.SkipSoftDelete(ctx), client); err != nil {
			return fmt.Errorf("migration %s: %w", m.Name, err)
		}
		if err := client.DataMigration.Create().SetName(m.Name).Exec(ctx); err != nil {
			return fmt.Errorf("migration %s: recording: %w", m.Name, err)
		}
		log.Printf("Migration %s: done in %s", m.Name, time.Since(started).Round(time.Millisecond))
	}
	return nil
}
