package scanner

import (
	"context"
)

type JobType string

const (
	JobTypeResolution JobType = "resolution"
	JobTypePortScan   JobType = "port_scan"
	JobTypeSSLScan    JobType = "ssl_scan"
	JobTypeCSPScan    JobType = "csp_scan"
)

type Job struct {
	ID      int     // Database job ID (0 for in-memory queue)
	Type    JobType
	Input   string // For Targets
	Address string // For IPs (PortScan)
}

// Queue defines the interface for a job queue.
type Queue interface {
	Enqueue(ctx context.Context, job Job) error
	Dequeue(ctx context.Context) (Job, error)
}

// InMemoryQueue implements Queue using a buffered channel.
type InMemoryQueue struct {
	jobs chan Job
}

func NewInMemoryQueue(bufferSize int) *InMemoryQueue {
	return &InMemoryQueue{
		jobs: make(chan Job, bufferSize),
	}
}

func (q *InMemoryQueue) Enqueue(ctx context.Context, job Job) error {
	select {
	case q.jobs <- job:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (q *InMemoryQueue) Dequeue(ctx context.Context) (Job, error) {
	select {
	case job := <-q.jobs:
		return job, nil
	case <-ctx.Done():
		return Job{}, ctx.Err()
	}
}
