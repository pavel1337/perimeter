package scanner

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"perimeter/scanner/csp"
)

func TestSameSite(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"example.com", "www.example.com", true},
		{"a.example.com", "B.Example.com", true},
		{"example.com", "login.example.net", false},
		{"shop.example.co.uk", "example.co.uk", true},
		{"one.co.uk", "two.co.uk", false},
		{"alice.github.io", "bob.github.io", false}, // github.io is a public suffix
		{"127.0.0.1", "127.0.0.1", true},
		{"127.0.0.1", "localhost", false},
	} {
		if got := sameSite(tc.a, tc.b); got != tc.want {
			t.Errorf("sameSite(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// A redirect to another site stops there: the target gets no findings and
// the other host is recorded (issue #70).
func TestFetchCSPStopsAtCrossSiteRedirect(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the other site was requested")
	}))
	t.Cleanup(other.Close)
	otherURL := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)

	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, otherURL+"/oauth/authorize?state=x", http.StatusFound)
	}))
	t.Cleanup(target.Close)
	client := *target.Client()
	client.CheckRedirect = cspCheckRedirect
	client.Timeout = 5 * time.Second

	p, err := fetchCSPHeaders(client, hostOf(t, target.URL))
	if err != nil {
		t.Fatalf("fetchCSPHeaders: %v", err)
	}
	if p.redirectHost != "localhost" || p.status != http.StatusFound {
		t.Errorf("got status %d redirect %q, want 302 to localhost", p.status, p.redirectHost)
	}
	if f, _ := evaluateCSP(p, csp.NewEvaluator(), "x"); len(f) != 0 {
		t.Errorf("findings %v, want none for a cross-site redirect", f)
	}
}

// A redirect within the site is followed and judged.
func TestFetchCSPFollowsSameSiteRedirect(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/app", http.StatusFound)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(target.Close)
	client := *target.Client()
	client.CheckRedirect = cspCheckRedirect

	p, err := fetchCSPHeaders(client, hostOf(t, target.URL))
	if err != nil {
		t.Fatalf("fetchCSPHeaders: %v", err)
	}
	if p.status != http.StatusOK || p.redirectHost != "" || p.enforce != "default-src 'self'" {
		t.Errorf("got %d redirect %q policy %q, want 200 from /app", p.status, p.redirectHost, p.enforce)
	}
}

// The redirect limit still applies under the custom policy.
func TestCSPCheckRedirectLimit(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"x", http.StatusFound)
	}))
	t.Cleanup(target.Close)
	client := *target.Client()
	client.CheckRedirect = cspCheckRedirect
	_, err := fetchCSPHeaders(client, hostOf(t, target.URL))
	if err == nil || probeErrorMessage(err) != "redirect loop" {
		t.Errorf("err = %v, want a redirect loop", err)
	}
}
