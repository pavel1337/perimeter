package ssl

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestSSLLabsScanner_Scan(t *testing.T) {
	// Mock Server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify parameters
		if r.URL.Path != "/analyze" {
			t.Errorf("Expected path /analyze, got %s", r.URL.Path)
		}
		if r.Header.Get("email") == "" {
			t.Errorf("Expected email header")
		}

		// Mock Responses
		// 1. Initial Call (starts new)
		if r.URL.Query().Get("startNew") == "on" {
			fmt.Fprint(w, `{
				"host": "example.com",
				"status": "IN_PROGRESS",
				"statusMessage": "In progress"
			}`)
			return
		}

		// 2. Subsequent Calls (Polling)
		// We'll return READY immediately for the test to save time,
		// or simulation state transition if we wanted to be fancy.
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{
			"host": "example.com",
			"status": "READY",
			"endpoints": [
				{
					"grade": "A+",
					"details": {
						"protocols": [{"name": "TLS", "version": "1.2"}, {"name": "TLS", "version": "1.3"}],
						"poodle": false,
						"heartbleed": false
					}
				}
			],
			"certs": [
				{
					"subject": "CN=example.com",
					"issuerSubject": "CN=GTS CA 1C3,O=Google Trust Services LLC,C=US",
					"notAfter": 1700000000000
				}
			]
		}`)
	}))
	defer ts.Close()

	// Override API URL
	oldURL := apiBaseURL
	apiBaseURL = ts.URL
	defer func() { apiBaseURL = oldURL }()

	fastTimings(t)
	scanner := NewSSLLabsScanner("test@example.com")
	result, err := scanner.Scan("example.com", false)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result.Grade != "A+" {
		t.Errorf("Expected Grade A+, got %s", result.Grade)
	}
	if result.Status != "READY" {
		t.Errorf("Expected Status READY, got %s", result.Status)
	}
}

// A rescan (fresh) must ask SSL Labs for a new assessment, while an ordinary
// scan takes a recent cached one without startNew.
func TestSSLLabsScanner_FreshStartsNewAssessment(t *testing.T) {
	var mu sync.Mutex
	var startNew []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		startNew = append(startNew, r.URL.Query().Get("startNew"))
		mu.Unlock()
		// A READY assessment finished just now, so it is fresh enough to use.
		now := time.Now().UnixMilli()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"host": "example.com", "status": "READY", "testTime": %s, "endpoints": [{"grade": "B"}]}`,
			strconv.FormatInt(now, 10))
	}))
	defer ts.Close()

	oldURL := apiBaseURL
	apiBaseURL = ts.URL
	defer func() { apiBaseURL = oldURL }()

	scanner := NewSSLLabsScanner("test@example.com")

	if _, err := scanner.Scan("example.com", false); err != nil {
		t.Fatalf("cached scan failed: %v", err)
	}
	mu.Lock()
	if len(startNew) != 1 || startNew[0] != "" {
		t.Errorf("ordinary scan sent startNew=%v, want one lookup without startNew", startNew)
	}
	startNew = nil
	mu.Unlock()

	result, err := scanner.Scan("example.com", true)
	if err != nil {
		t.Fatalf("fresh scan failed: %v", err)
	}
	if result.Grade != "B" {
		t.Errorf("Expected Grade B, got %s", result.Grade)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(startNew) != 1 || startNew[0] != "on" {
		t.Errorf("fresh scan sent startNew=%v, want a single startNew=on request", startNew)
	}
}
