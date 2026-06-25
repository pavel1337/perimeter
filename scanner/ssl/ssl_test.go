package ssl

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
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

	scanner := NewSSLLabsScanner("test@example.com")
	result, err := scanner.Scan("example.com")
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
