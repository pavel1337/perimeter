package scanner

import (
	"context"
	"time"

	"perimeter/ent"
	entjob "perimeter/ent/job"
	"perimeter/internal/storage"
)

// DBQueue implements Queue using the database-backed job table.
type DBQueue struct {
	storage     *storage.EntStorage
	jobTimeout  time.Duration
	pollInterval time.Duration
}

func NewDBQueue(s *storage.EntStorage, jobTimeout, pollInterval time.Duration) *DBQueue {
	return &DBQueue{
		storage:      s,
		jobTimeout:   jobTimeout,
		pollInterval: pollInterval,
	}
}

// Enqueue creates a pending job in the database.
// It uses the Job fields to determine the job type and payload.
func (q *DBQueue) Enqueue(ctx context.Context, job Job) error {
	var jobType entjob.Type
	switch job.Type {
	case JobTypeResolution:
		jobType = entjob.TypeResolve
	case JobTypePortScan:
		jobType = entjob.TypePortScan
	case JobTypeSSLScan:
		jobType = entjob.TypeSslScan
	case JobTypeCSPScan:
		jobType = entjob.TypeCspScan
	}

	payload := map[string]any{}
	if job.Input != "" {
		payload["input"] = job.Input
	}
	if job.Address != "" {
		payload["address"] = job.Address
	}

	_, err := q.storage.CreateJob(ctx, jobType, payload)
	return err
}

// Dequeue polls the database for the next pending job, claiming it atomically.
// Blocks until a job is available or context is cancelled.
func (q *DBQueue) Dequeue(ctx context.Context) (Job, error) {
	for {
		select {
		case <-ctx.Done():
			return Job{}, ctx.Err()
		default:
		}

		entJob, err := q.storage.ClaimJob(ctx, q.jobTimeout)
		if err != nil {
			return Job{}, err
		}
		if entJob != nil {
			return entJobToScannerJob(entJob), nil
		}

		// No jobs available, wait before polling again
		select {
		case <-time.After(q.pollInterval):
		case <-ctx.Done():
			return Job{}, ctx.Err()
		}
	}
}

func entJobToScannerJob(j *ent.Job) Job {
	var jobType JobType
	switch j.Type {
	case entjob.TypeResolve:
		jobType = JobTypeResolution
	case entjob.TypePortScan:
		jobType = JobTypePortScan
	case entjob.TypeSslScan:
		jobType = JobTypeSSLScan
	case entjob.TypeCspScan:
		jobType = JobTypeCSPScan
	}

	job := Job{
		Type: jobType,
		ID:   j.ID,
	}

	if v, ok := j.Payload["input"].(string); ok {
		job.Input = v
	}
	if v, ok := j.Payload["address"].(string); ok {
		job.Address = v
	}

	return job
}
