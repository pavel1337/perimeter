package storage

import (
	"context"
	"slices"
	"time"

	"perimeter/ent"
	"perimeter/ent/target"
)

const (
	// deleteChunkSize caps the ids in one UPDATE, well under SQLite's
	// bound-parameter limit.
	deleteChunkSize = 1000
	// historyBatchSize caps the targets loaded per query, so eager-loaded
	// scan history stays bounded however many ids there are.
	historyBatchSize = 100
)

// TargetIDs returns the ids of every live target matching f, ascending.
func (s *EntStorage) TargetIDs(ctx context.Context, f TargetFilter) ([]int, error) {
	preds, err := targetPredicates(f)
	if err != nil {
		return nil, err
	}
	return s.client.Target.Query().
		Where(preds...).
		Order(ent.Asc(target.FieldID)).
		IDs(ctx)
}

// DeleteTargets soft-deletes the live targets among ids. The chunks run in one
// transaction, so the selection is deleted all or nothing.
func (s *EntStorage) DeleteTargets(ctx context.Context, ids []int) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	total := 0
	for chunk := range slices.Chunk(ids, deleteChunkSize) {
		n, err := tx.Target.Update().
			Where(target.IDIn(chunk...), target.DeletedAtIsNil()).
			SetDeletedAt(now).
			Save(ctx)
		if err != nil {
			return 0, rollback(tx, err)
		}
		total += n
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return total, nil
}

// EachTargetWithHistory calls fn for each live target among ids, in id order,
// loading them in batches like GetTarget. Duplicate ids are visited once.
func (s *EntStorage) EachTargetWithHistory(ctx context.Context, ids []int, fn func(*ent.Target) error) error {
	sorted := slices.Clone(ids)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)

	for batch := range slices.Chunk(sorted, historyBatchSize) {
		targets, err := withTargetHistory(s.client.Target.Query().Where(target.IDIn(batch...))).
			Order(ent.Asc(target.FieldID)).
			All(ctx)
		if err != nil {
			return err
		}
		for _, tg := range targets {
			if err := fn(tg); err != nil {
				return err
			}
		}
	}
	return nil
}
