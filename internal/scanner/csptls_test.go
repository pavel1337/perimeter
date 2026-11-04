package scanner

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"
)

func hostOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func cspServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A certificate that isn't trusted is read without verifying it, and the
// problem is recorded instead of "no response" (issue #68).
func TestFetchCSPReadsUntrustedCertificate(t *testing.T) {
	srv := cspServer(t)
	client := http.Client{Timeout: 5 * time.Second} // does not trust the test CA
	p, err := fetchCSPHeaders(client, hostOf(t, srv.URL))
	if err != nil {
		t.Fatalf("fetchCSPHeaders: %v", err)
	}
	if p.enforce != "default-src 'self'" || p.status != http.StatusOK {
		t.Errorf("got %d %q, want 200 with the policy", p.status, p.enforce)
	}
	if p.tlsProblem != "certificate not trusted: self-signed or unknown issuer" {
		t.Errorf("tlsProblem = %q", p.tlsProblem)
	}
	if !strings.HasPrefix(p.finalURL, "https://") {
		t.Errorf("final URL %q, want https (no plain-HTTP fallback)", p.finalURL)
	}
}

func TestFetchCSPReadsNameMismatch(t *testing.T) {
	srv := cspServer(t)
	client := *srv.Client() // trusts the test CA, whose cert names 127.0.0.1 and example.com
	host := strings.Replace(hostOf(t, srv.URL), "127.0.0.1", "localhost", 1)
	p, err := fetchCSPHeaders(client, host)
	if err != nil {
		t.Fatalf("fetchCSPHeaders: %v", err)
	}
	if p.tlsProblem != "certificate not trusted: name mismatch" {
		t.Errorf("tlsProblem = %q, want name mismatch", p.tlsProblem)
	}
}

// A trusted certificate records no problem.
func TestFetchCSPTrustedCertificate(t *testing.T) {
	srv := cspServer(t)
	p, err := fetchCSPHeaders(*srv.Client(), hostOf(t, srv.URL))
	if err != nil || p.tlsProblem != "" {
		t.Errorf("got tlsProblem %q err %v, want none", p.tlsProblem, err)
	}
}

// A server speaking plain HTTP on the port falls back to HTTP, and the final
// URL shows it.
func TestFetchCSPFallsBackToPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	p, err := fetchCSPHeaders(*srv.Client(), hostOf(t, srv.URL))
	if err != nil {
		t.Fatalf("fetchCSPHeaders: %v", err)
	}
	if !strings.HasPrefix(p.finalURL, "http://") {
		t.Errorf("final URL %q, want http", p.finalURL)
	}
}

// A redirect loop has its own message instead of "no response".
func TestFetchCSPRedirectLoop(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"x", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	_, err := fetchCSPHeaders(*srv.Client(), hostOf(t, srv.URL))
	if err == nil {
		t.Fatal("want an error for a redirect loop")
	}
	if got := probeErrorMessage(err); got != "redirect loop" {
		t.Errorf("message = %q, want redirect loop", got)
	}
}

// Timeouts and resets are tried again; a missing name or a redirect loop is
// not (issue #69).
func TestCSPRetryable(t *testing.T) {
	if cspRetryable(&net.DNSError{Err: "no such host", IsNotFound: true}) {
		t.Error("NXDOMAIN retried")
	}
	if cspRetryable(errors.New(`Get "https://x/": stopped after 10 redirects`)) {
		t.Error("redirect loop retried")
	}
	if !cspRetryable(&net.OpError{Op: "read", Err: syscall.ECONNRESET}) {
		t.Error("connection reset not retried")
	}
	if !cspRetryable(&net.DNSError{Err: "i/o timeout", IsTimeout: true}) {
		t.Error("DNS timeout not retried")
	}
}
