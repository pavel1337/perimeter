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

	sso, err := client.Target.Create().SetInput("sso.example").SetReachability("ok").Save(ctx)
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	if _, err := client.CSPScan.Create().SetTarget(sso).SetScannedAt(now).SetLastSeenAt(now).
		SetCspHeader("").SetStatusCode(302).SetFinalURL("https://sso.example/").SetRedirectHost("login.idp.example").Save(ctx); err != nil {
		t.Fatalf("create csp scan: %v", err)
	}
	if page := send(t, srv, token, "GET", "/targets/"+strconv.Itoa(sso.ID), "", ""); !strings.Contains(page.Body, "redirects to login.idp.example") {
		t.Errorf("target page lacks the redirect host (status %d)", page.StatusCode)
	}
	if dash := send(t, srv, token, "GET", "/", "", ""); !strings.Contains(dash.Body, "login.idp.example") {
		t.Errorf("dashboard lacks the redirect host (status %d)", dash.StatusCode)
	}

	if _, err := client.DNSChange.Create().SetTarget(tg).SetChangedAt(now).SetKind("changed").
		SetAdded([]string{"198.51.100.20"}).SetRemoved([]string{"192.0.2.10"}).Save(ctx); err != nil {
		t.Fatalf("create dns change: %v", err)
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
		"DNS moved from 192.0.2.10 to 198.51.100.20",
	} {
		if !strings.Contains(resp.Body, want) {
			t.Errorf("target page lacks %q", want)
		}
	}
}
