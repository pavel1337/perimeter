package importer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func TestScannableName(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"www", true},
		{"api.eu", true},
		{"my-host_1", true}, // an underscore inside a label is not a service label
		{"*", false},
		{"*.apps", false},
		{"selector1._domainkey", false},
		{"_3f9c0a.www", false},
		{"_acme-challenge", false},
		{"_sip._tcp", false},
	} {
		if got := scannableName(tc.name, "example.com"); got != tc.want {
			t.Errorf("scannableName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The Gandi importer skips wildcards and underscore names even when they
// are CNAMEs (issue #72).
func TestGandiSkipsNonHosts(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/domain/domains", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]gandiDomain{{FQDN: "example.com"}})
	})
	mux.HandleFunc("/livedns/domains/example.com/records", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]gandiRecord{
			{Name: "www", Type: "A"},
			{Name: "*", Type: "A"},
			{Name: "*.apps", Type: "CNAME"},
			{Name: "selector1._domainkey", Type: "CNAME"},
			{Name: "_3f9c.www", Type: "CNAME"},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	src := &GandiSource{config: GandiConfig{APIKey: "k"}, client: &http.Client{Timeout: 5 * time.Second}, baseURL: srv.URL}

	got, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	slices.Sort(got)
	if want := []string{"example.com", "www.example.com"}; !slices.Equal(got, want) {
		t.Errorf("Fetch = %v, want %v", got, want)
	}
}
