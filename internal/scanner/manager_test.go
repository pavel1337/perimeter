package scanner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestResolveBackoff(t *testing.T) {
	base := time.Minute
	// fibonacci multiples of base: 1,1,2,3,5,8,...
	cases := map[int]time.Duration{
		0:   1 * time.Minute,
		1:   1 * time.Minute,
		2:   2 * time.Minute,
		3:   3 * time.Minute,
		4:   5 * time.Minute,
		5:   8 * time.Minute,
		100: time.Hour, // capped
	}
	for attempts, want := range cases {
		if got := resolveBackoff(attempts, base); got != want {
			t.Errorf("resolveBackoff(%d) = %v, want %v", attempts, got, want)
		}
	}
}

func TestFetchCSPHeadersUsesGETAfterRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		_, _ = io.WriteString(w, "ok")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	enforce, reportOnly, err := fetchCSPHeaders(*srv.Client(), u.Host)
	if err != nil {
		t.Fatalf("fetchCSPHeaders: %v", err)
	}
	if enforce != "default-src 'self'" {
		t.Fatalf("enforcing CSP = %q, want policy from GET /login", enforce)
	}
	if reportOnly != "" {
		t.Fatalf("report-only = %q, want empty", reportOnly)
	}
}

func TestFetchCSPHeadersReadsReportOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy-Report-Only", "default-src 'none'")
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	enforce, reportOnly, err := fetchCSPHeaders(*srv.Client(), u.Host)
	if err != nil {
		t.Fatalf("fetchCSPHeaders: %v", err)
	}
	if enforce != "" || reportOnly != "default-src 'none'" {
		t.Fatalf("got enforce=%q reportOnly=%q", enforce, reportOnly)
	}
}

// flakyQueue fails the first failUntil dequeues, then blocks until ctx is done.
type flakyQueue struct {
	failUntil int
	mu        sync.Mutex
	calls     int
	settled   chan struct{}
}

func (q *flakyQueue) Enqueue(context.Context, Job) error { return nil }

func (q *flakyQueue) Dequeue(ctx context.Context) (Job, error) {
	q.mu.Lock()
	q.calls++
	n := q.calls
	q.mu.Unlock()

	if n <= q.failUntil {
		return Job{}, errors.New("connection reset by peer")
	}
	close(q.settled)
	<-ctx.Done()
	return Job{}, ctx.Err()
}

// A transient queue error must not kill the worker; nothing restarts it, so
// scanning would silently stop after one hiccup.
func TestWorkerSurvivesQueueErrors(t *testing.T) {
	old := queueErrorBackoff
	queueErrorBackoff = time.Millisecond
	t.Cleanup(func() { queueErrorBackoff = old })

	q := &flakyQueue{failUntil: 3, settled: make(chan struct{})}
	m := &Manager{queue: q, inFlight: make(map[string]struct{})}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.runWorker(ctx, 0)

	select {
	case <-q.settled:
	case <-time.After(2 * time.Second):
		q.mu.Lock()
		defer q.mu.Unlock()
		t.Fatalf("worker stopped after %d dequeues, want it to keep polling", q.calls)
	}
}

// A cancelled context stops the worker rather than spinning on the error.
func TestWorkerStopsOnContextCancel(t *testing.T) {
	q := &flakyQueue{settled: make(chan struct{})}
	m := &Manager{queue: q, inFlight: make(map[string]struct{})}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.runWorker(ctx, 0); close(done) }()

	<-q.settled
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not stop after context cancel")
	}
}
