package server

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The target page renders the CSP probe's status, final URL, TLS problem and
// plain-HTTP marker, and an error page as "no application served" (#67, #68).
func TestTargetPageShowsCSPProbeDetails(t *testing.T) {
	srv, client, token := authedServer(t)
	ctx := context.Background()
	tg, err := client.Target.Create().SetInput("csp.example").SetReachability("ok").Save(ctx)
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	now := time.Now()
	if _, err := client.CSPScan.Create().SetTarget(tg).SetScannedAt(now.Add(-time.Hour)).SetLastSeenAt(now.Add(-time.Hour)).
		SetCspHeader("default-src 'self'").SetStatusCode(200).SetFinalURL("https://csp.example/").
		SetTLSProblem("certificate not trusted: name mismatch").Save(ctx); err != nil {
		t.Fatalf("create csp scan: %v", err)
	}
	if _, err := client.CSPScan.Create().SetTarget(tg).SetScannedAt(now).SetLastSeenAt(now).
		SetCspHeader("").SetStatusCode(404).SetFinalURL("http://csp.example/").Save(ctx); err != nil {
		t.Fatalf("create csp scan: %v", err)
	}

	resp := send(t, srv, token, "GET", "/targets/"+strconv.Itoa(tg.ID), "", "")
	if resp.StatusCode != 200 {
		t.Fatalf("GET target page: status %d", resp.StatusCode)
	}
	for _, want := range []string{
		"no application served (404)",
		"404 http://csp.example/",
		"plain HTTP",
		"certificate not trusted: name mismatch",
		"200 https://csp.example/",
	} {
		if !strings.Contains(resp.Body, want) {
			t.Errorf("target page lacks %q", want)
		}
	}
}
