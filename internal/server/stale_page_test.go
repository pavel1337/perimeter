package server

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"perimeter/internal/service"
)

// A result last checked over two intervals ago is marked stale on the
// target page (issue #76).
func TestTargetPageMarksStaleResults(t *testing.T) {
	srv, client, token := authedServer(t)
	srv.SetSSLScanning(true)
	srv.SetScanIntervals(service.ScanIntervals{Ports: time.Hour, SSL: 12 * time.Hour, CSP: time.Hour})
	ctx := context.Background()
	tg, err := client.Target.Create().SetInput("stale.example").SetReachability("ok").Save(ctx)
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	old := time.Now().Add(-30 * time.Hour)
	if _, err := client.SSLScan.Create().SetTarget(tg).SetScannedAt(old).SetLastSeenAt(old).
		SetGrade("A").SetStatus("READY").Save(ctx); err != nil {
		t.Fatalf("create ssl scan: %v", err)
	}
	now := time.Now()
	if _, err := client.CSPScan.Create().SetTarget(tg).SetScannedAt(now).SetLastSeenAt(now).
		SetCspHeader("default-src 'self'").SetStatusCode(200).Save(ctx); err != nil {
		t.Fatalf("create csp scan: %v", err)
	}

	page := send(t, srv, token, "GET", "/targets/"+strconv.Itoa(tg.ID), "", "")
	if page.StatusCode != 200 {
		t.Fatalf("status %d", page.StatusCode)
	}
	ssl := page.Body[strings.Index(page.Body, "SSL History"):strings.Index(page.Body, "CSP History")]
	if !strings.Contains(ssl, ">stale<") {
		t.Error("the 30h-old SSL result is not marked stale")
	}
	csp := page.Body[strings.Index(page.Body, "CSP History"):]
	if strings.Contains(csp[:200], ">stale<") {
		t.Error("the fresh CSP result is marked stale")
	}
}
