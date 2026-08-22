package scanner

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
