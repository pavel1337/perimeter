package storage

import (
	"context"
	"fmt"
	"time"

	"perimeter/ent"
	entjob "perimeter/ent/job"
)

// CreateJob inserts a new pending job.
func (s *EntStorage) CreateJob(ctx context.Context, jobType entjob.Type, payload map[string]any) (*ent.Job, error) {
	return s.client.Job.Create().
		SetType(jobType).
		SetStatus(entjob.StatusPending).
		SetPayload(payload).
		Save(ctx)
}

// ClaimJob atomically claims the oldest pending job by setting it to in_progress.
// Returns nil if no pending jobs are available.
func (s *EntStorage) ClaimJob(ctx context.Context, timeout time.Duration) (*ent.Job, error) {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return nil, err
	}

	j, err := tx.Job.Query().
		Where(entjob.StatusEQ(entjob.StatusPending)).
		Order(ent.Asc(entjob.FieldCreateTime)).
		Limit(1).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			if rerr := tx.Rollback(); rerr != nil {
				return nil, fmt.Errorf("rollback: %w", rerr)
			}
			return nil, nil
		}
		return nil, rollback(tx, err)
	}

	now := time.Now()
	j, err = tx.Job.UpdateOne(j).
		SetStatus(entjob.StatusInProgress).
		SetStartedAt(now).
		SetTimeoutAt(now.Add(timeout)).
		Save(ctx)
	if err != nil {
		return nil, rollback(tx, err)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return j, nil
}

// CompleteJob marks a job as completed with a result.
func (s *EntStorage) CompleteJob(ctx context.Context, id int, result map[string]any) error {
	return s.client.Job.UpdateOneID(id).
		SetStatus(entjob.StatusCompleted).
		SetCompletedAt(time.Now()).
		SetResult(result).
		Exec(ctx)
}

// FailJob marks a job as failed with an error message.
func (s *EntStorage) FailJob(ctx context.Context, id int, errMsg string) error {
	return s.client.Job.UpdateOneID(id).
		SetStatus(entjob.StatusFailed).
		SetCompletedAt(time.Now()).
		SetError(errMsg).
		Exec(ctx)
}

// RecoverStaleJobs resets in_progress jobs that have exceeded their timeout back to pending.
func (s *EntStorage) RecoverStaleJobs(ctx context.Context) (int, error) {
	n, err := s.client.Job.Update().
		Where(
			entjob.StatusEQ(entjob.StatusInProgress),
			entjob.TimeoutAtLT(time.Now()),
		).
		SetStatus(entjob.StatusPending).
		ClearStartedAt().
		ClearTimeoutAt().
		Save(ctx)
	return n, err
}

// HasPendingJob checks if a pending or in-progress job already exists with the given type and a matching key in the payload.
func (s *EntStorage) HasPendingJob(ctx context.Context, jobType entjob.Type, key string, value string) (bool, error) {
	// Ent doesn't support JSON field queries portably across SQLite and Postgres,
	// so we query all pending/in-progress jobs of this type and check in Go.
	jobs, err := s.client.Job.Query().
		Where(
			entjob.TypeEQ(jobType),
			entjob.StatusIn(entjob.StatusPending, entjob.StatusInProgress),
		).
		All(ctx)
	if err != nil {
		return false, err
	}

	for _, j := range jobs {
		if v, ok := j.Payload[key]; ok {
			if fmt.Sprintf("%v", v) == value {
				return true, nil
			}
		}
	}

	return false, nil
}
