package importer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"
	"time"
)

// fakeGandi serves one domain whose zone holds n A records named h000, h001,
// ..., paged the way Gandi pages them, with Total-Count set.
func fakeGandi(t *testing.T, n int, sendTotal bool) (*GandiSource, *int) {
	t.Helper()
	recordCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/domain/domains", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]gandiDomain{{FQDN: "example.com"}})
	})
	mux.HandleFunc("/livedns/domains/example.com/records", func(w http.ResponseWriter, r *http.Request) {
		recordCalls++
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		if page < 1 || per < 1 {
			t.Errorf("records request without paging: %s", r.URL.RawQuery)
			page, per = 1, n
		}
		var out []gandiRecord
		for i := (page - 1) * per; i < n && i < page*per; i++ {
			out = append(out, gandiRecord{Name: fmt.Sprintf("h%03d", i), Type: "A", Values: []string{"192.0.2.1"}})
		}
		if sendTotal {
			w.Header().Set("Total-Count", strconv.Itoa(n))
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &GandiSource{config: GandiConfig{APIKey: "k"}, client: &http.Client{Timeout: 5 * time.Second}, baseURL: srv.URL}, &recordCalls
}

// A zone bigger than one page is read to the end, so names late in the
// alphabet are imported (issue #60).
func TestGandiFetchReadsEveryRecordPage(t *testing.T) {
	for _, tc := range []struct {
		name      string
		n         int
		sendTotal bool
		calls     int
	}{
		{"two pages with Total-Count", 150, true, 2},
		{"two pages without Total-Count", 150, false, 2},
		{"exactly one full page with Total-Count", 100, true, 1},
		{"exactly one full page without Total-Count", 100, false, 2}, // needs the empty page to know
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, calls := fakeGandi(t, tc.n, tc.sendTotal)
			got, err := src.Fetch(context.Background())
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if len(got) != tc.n+1 { // the domain itself plus every record
				t.Errorf("got %d targets, want %d", len(got), tc.n+1)
			}
			last := fmt.Sprintf("h%03d.example.com", tc.n-1)
			if !slices.Contains(got, last) {
				t.Errorf("last record %s missing", last)
			}
			if *calls != tc.calls {
				t.Errorf("records endpoint called %d times, want %d", *calls, tc.calls)
			}
		})
	}
}
