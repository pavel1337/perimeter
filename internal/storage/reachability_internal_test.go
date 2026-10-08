package storage

import (
	"context"
	"testing"
	"time"

	"perimeter/ent/cspscan"
	"perimeter/ent/target"
	"perimeter/scanner/csp"
)

func TestBackfillReachability(t *testing.T) {
	client := newBackfillClient(t)
	s := NewEntStorage(client)
	ctx := context.Background()
	now := time.Now()

	mk := func(input string, isIP bool) int {
		t.Helper()
		tg, err := client.Target.Create().SetInput(input).SetIsIP(isIP).Save(ctx)
		if err != nil {
			t.Fatalf("create target: %v", err)
		}
		return tg.ID
	}
	ipFor := func(targetID int, addr string, ports ...int) {
		t.Helper()
		i, err := client.IP.Create().SetAddress(addr).AddTargetIDs(targetID).Save(ctx)
		if err != nil {
			t.Fatalf("create ip: %v", err)
		}
		if ports == nil { // never scanned
			return
		}
		legacyPortScan(t, client, i, now, ports...)
	}
	cspScan := func(targetID int, at time.Time, header string, findings ...csp.Finding) {
		t.Helper()
		if err := client.CSPScan.Create().SetTargetID(targetID).SetScannedAt(at).
			SetCspHeader(header).SetFindings(findings).Exec(ctx); err != nil {
			t.Fatalf("create csp scan: %v", err)
		}
	}
	legacyDown := csp.Finding{Description: "Target Unreachable", Severity: csp.SeverityInfo}
	noHeader := csp.Finding{Description: "No Content-Security-Policy header found.", Severity: csp.SeverityHigh}

	fresh := mk("fresh.example", false)

	gone := mk("gone.example", false)
	if err := client.Target.UpdateOneID(gone).SetResolveError("no such host (NXDOMAIN)").Exec(ctx); err != nil {
		t.Fatal(err)
	}

	resolved := mk("resolved.example", false)
	ipFor(resolved, "10.0.0.1")

	// Was down, came back: the newest scan decides.
	recovered := mk("recovered.example", false)
	ipFor(recovered, "10.0.0.2")
	cspScan(recovered, now.Add(-time.Hour), "", legacyDown)
	cspScan(recovered, now, "", noHeader)

	down := mk("down.example", false)
	ipFor(down, "10.0.0.3")
	cspScan(down, now, "", legacyDown)

	quietIP := mk("10.0.0.4", true)
	ipFor(quietIP, "10.0.0.4", []int{}...) // scanned, nothing open

	openIP := mk("10.0.0.5", true)
	ipFor(openIP, "10.0.0.5", 22)

	// No HTTP, but SMTP answers.
	mail := mk("mail.example", false)
	ipFor(mail, "10.0.0.6", 25)
	cspScan(mail, now, "", legacyDown)

	// Ports scanned with nothing open, HTTP not probed yet.
	quiet := mk("quiet.example", false)
	ipFor(quiet, "10.0.0.7", []int{}...)

	for range 2 { // idempotent
		if err := s.BackfillReachability(ctx); err != nil {
			t.Fatalf("BackfillReachability: %v", err)
		}
	}

	want := map[int]target.Reachability{
		fresh:     target.ReachabilityPending,
		gone:      target.ReachabilityUnresolved,
		resolved:  target.ReachabilityPending,
		recovered: target.ReachabilityOk,
		down:      target.ReachabilityUnreachable,
		quietIP:   target.ReachabilityUnreachable,
		openIP:    target.ReachabilityOk,
		mail:      target.ReachabilityOk,
		quiet:     target.ReachabilityPending,
	}
	for id, w := range want {
		tg := client.Target.GetX(ctx, id)
		if tg.Reachability != w {
			t.Errorf("%s: reachability = %s, want %s", tg.Input, tg.Reachability, w)
		}
	}

	// The magic finding is gone; real findings are untouched.
	scans := client.CSPScan.Query().Order(cspscan.ByID()).AllX(ctx)
	for _, sc := range scans {
		if isLegacyUnreachable(sc.Findings) {
			t.Errorf("scan %d still carries the legacy finding", sc.ID)
		}
	}
	if scans[0].ProbeError != legacyProbeError || len(scans[0].Findings) != 0 {
		t.Errorf("converted row: probe_error=%q findings=%v", scans[0].ProbeError, scans[0].Findings)
	}
	if scans[1].ProbeError != "" || len(scans[1].Findings) != 1 {
		t.Errorf("real finding row changed: probe_error=%q findings=%v", scans[1].ProbeError, scans[1].Findings)
	}
}
