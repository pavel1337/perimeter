package storage

import (
	"context"
	"errors"
	"time"

	"perimeter/ent"
	"perimeter/ent/cspscan"
	"perimeter/ent/schema"
	"perimeter/ent/sslscan"
	"perimeter/ent/target"
)

// ErrTargetNotFound is returned by the soft-delete operations when no target
// in the required state (live for delete, deleted for restore and purge) has
// the given id.
var ErrTargetNotFound = errors.New("target not found")

// DeleteTarget hides a live target by stamping deleted_at. Its scans are kept,
// so RestoreTarget brings the full history back.
func (s *EntStorage) DeleteTarget(ctx context.Context, id int) error {
	n, err := s.client.Target.Update().
		Where(target.ID(id), target.DeletedAtIsNil()).
		SetDeletedAt(time.Now()).
		Save(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrTargetNotFound
	}
	return nil
}

func (s *EntStorage) ListDeletedTargets(ctx context.Context) ([]*ent.Target, error) {
	return s.client.Target.Query().
		Where(target.DeletedAtNotNil()).
		Order(ent.Desc(target.FieldDeletedAt), ent.Desc(target.FieldID)).
		WithTags().
		All(schema.SkipSoftDelete(ctx))
}

func (s *EntStorage) CountDeletedTargets(ctx context.Context) (int, error) {
	return s.client.Target.Query().
		Where(target.DeletedAtNotNil()).
		Count(schema.SkipSoftDelete(ctx))
}

// RestoreTarget clears deleted_at and refreshes the summary: scans may have
// been written while the target was hidden, and those writes skipped it.
func (s *EntStorage) RestoreTarget(ctx context.Context, id int) error {
	n, err := s.client.Target.Update().
		Where(target.ID(id), target.DeletedAtNotNil()).
		ClearDeletedAt().
		Save(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrTargetNotFound
	}
	return refreshSummary(ctx, s.client, target.ID(id))
}

// PurgeTarget hard-deletes a soft-deleted target together with its SSL and CSP
// scans. The deleted check runs inside the transaction so it cannot race a
// restore.
func (s *EntStorage) PurgeTarget(ctx context.Context, id int) error {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return err
	}
	exists, err := tx.Target.Query().
		Where(target.ID(id), target.DeletedAtNotNil()).
		Exist(schema.SkipSoftDelete(ctx))
	if err != nil {
		return rollback(tx, err)
	}
	if !exists {
		return rollback(tx, ErrTargetNotFound)
	}

	_, err = tx.SSLScan.Delete().Where(sslscan.HasTargetWith(target.ID(id))).Exec(ctx)
	if err != nil {
		return rollback(tx, err)
	}
	_, err = tx.CSPScan.Delete().Where(cspscan.HasTargetWith(target.ID(id))).Exec(ctx)
	if err != nil {
		return rollback(tx, err)
	}

	// IPs are kept: they may be shared or rediscovered. M2M edges to IPs are
	// removed with the target.
	if err := tx.Target.DeleteOneID(id).Exec(ctx); err != nil {
		return rollback(tx, err)
	}

	return tx.Commit()
}
