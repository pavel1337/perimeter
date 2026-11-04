package ssl

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fastTimings shortens every wait in the client for the test.
func fastTimings(t *testing.T) {
	t.Helper()
	oldPoll, oldTimeout, oldBackoff, oldCool := pollInterval, pollTimeout, overloadBackoff, newAssessmentCoolOff
	pollInterval, pollTimeout, overloadBackoff, newAssessmentCoolOff = 5*time.Millisecond, 5*time.Second, time.Millisecond, 0
	t.Cleanup(func() {
		pollInterval, pollTimeout, overloadBackoff, newAssessmentCoolOff = oldPoll, oldTimeout, oldBackoff, oldCool
	})
}

func fakeAPI(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	old := apiBaseURL
	apiBaseURL = ts.URL
	t.Cleanup(func() { apiBaseURL = old })
}

const readyB = `{"host": "example.com", "status": "READY", "endpoints": [{"grade": "B"}]}`

// A 429 when starting an assessment is backed off and retried, not a failed
// scan (issue #62).
func TestScanRetriesAfter429(t *testing.T) {
	fastTimings(t)
	var calls atomic.Int32
	fakeAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, "Too many new assessments too fast. Please slow down.")
			return
		}
		fmt.Fprint(w, readyB)
	})

	res, err := NewSSLLabsScanner("test@example.com").Scan("example.com", true)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Grade != "B" {
		t.Errorf("grade = %q, want B", res.Grade)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("API called %d times, want 2 (429, then 200)", n)
	}
}

// When SSL Labs keeps answering 429 the scan gives up after overloadAttempts
// with an error that says so, and becomes a failed check upstream.
func TestScanGivesUpAfterRepeated429(t *testing.T) {
	fastTimings(t)
	var calls atomic.Int32
	fakeAPI(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	})

	_, err := NewSSLLabsScanner("test@example.com").Scan("example.com", true)
	if !overloaded(err) {
		t.Fatalf("err = %v, want a 429 APIError", err)
	}
	if n := calls.Load(); n != overloadAttempts {
		t.Errorf("API called %d times, want %d", n, overloadAttempts)
	}
}

// A 429 or 529 while polling skips that tick instead of failing the scan.
func TestPollSkipsTickOn429(t *testing.T) {
	fastTimings(t)
	var polls atomic.Int32
	fakeAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("startNew") == "on" {
			fmt.Fprint(w, `{"host": "example.com", "status": "IN_PROGRESS"}`)
			return
		}
		switch polls.Add(1) {
		case 1:
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			w.WriteHeader(529)
		default:
			fmt.Fprint(w, readyB)
		}
	})

	res, err := NewSSLLabsScanner("test@example.com").Scan("example.com", true)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Grade != "B" {
		t.Errorf("grade = %q, want B", res.Grade)
	}
}

// Scans sharing one scanner never run more assessments at once than SSL Labs
// allows in X-Max-Assessments.
func TestScansRespectMaxAssessments(t *testing.T) {
	fastTimings(t)
	var running, peak atomic.Int32
	fakeAPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Max-Assessments", "2")
		if r.URL.Query().Get("startNew") == "on" {
			if n := running.Add(1); n > peak.Load() {
				peak.Store(n)
			}
			fmt.Fprint(w, `{"host": "example.com", "status": "IN_PROGRESS"}`)
			return
		}
		time.Sleep(20 * time.Millisecond)
		running.Add(-1)
		fmt.Fprint(w, readyB)
	})

	s := NewSSLLabsScanner("test@example.com")
	// Learn the limit (defaultMaxAssessments until the first response).
	if _, err := s.Scan("example.com", true); err != nil {
		t.Fatalf("first Scan: %v", err)
	}
	peak.Store(0)

	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Scan("example.com", true); err != nil {
				t.Errorf("Scan: %v", err)
			}
		}()
	}
	wg.Wait()
	if p := peak.Load(); p > 2 {
		t.Errorf("%d assessments ran at once, want at most 2", p)
	}
	if p := peak.Load(); p < 2 {
		t.Errorf("only %d assessment ran at once, want the limit of 2 used", p)
	}
}

// X-Current-Assessments beyond our own shrinks the limit, never below one.
func TestSlotsUpdateFromHeaders(t *testing.T) {
	a := newAssessmentSlots(1)
	h := http.Header{}
	h.Set("X-Max-Assessments", "5")
	h.Set("X-Current-Assessments", "3") // none of them ours
	a.update(h)
	if a.limit != 2 {
		t.Errorf("limit = %d, want 2", a.limit)
	}
	h.Set("X-Current-Assessments", "9")
	a.update(h)
	if a.limit != 1 {
		t.Errorf("limit = %d, want 1", a.limit)
	}
	a.update(http.Header{}) // no headers: unchanged
	if a.limit != 1 {
		t.Errorf("limit = %d after an empty header, want 1", a.limit)
	}
}
