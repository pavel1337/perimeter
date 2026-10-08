package storage

import (
	"context"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/scanner/csp"
)

func TestGradeRanks(t *testing.T) {
	tests := []struct {
		grade string
		want  int
	}{
		{"A+", 8},
		{"A", 7},
		{"A-", 6},
		{"B", 5},
		{"C", 4},
		{"D", 3},
		{"E", 2},
		{"F", 1},
		{"T", 1},
		{"M", 1},
		{"-", 0},
		{"", 0},
		{"Z", 0},
	}
	for _, tc := range tests {
		if got := gradeRanks[tc.grade]; got != tc.want {
			t.Errorf("gradeRanks[%q] = %d, want %d", tc.grade, got, tc.want)
		}
	}

	// Best-first: each grade must rank strictly above the next.
	order := []string{"A+", "A", "A-", "B", "C", "D", "E", "F"}
	for i := 1; i < len(order); i++ {
		hi, lo := gradeRanks[order[i-1]], gradeRanks[order[i]]
		if hi <= lo {
			t.Errorf("rank(%s) = %d, want > rank(%s) = %d", order[i-1], hi, order[i], lo)
		}
	}
}

func TestBackfillSummary(t *testing.T) {
	client := newBackfillClient(t)
	s := NewEntStorage(client)
	ctx := context.Background()
	base := time.Now().Truncate(time.Second)
	older := base.Add(-time.Hour)
	expiry := base.Add(90 * 24 * time.Hour).Truncate(time.Second)

	mk := func(input string) int {
		t.Helper()
		tg, err := client.Target.Create().SetInput(input).Save(ctx)
		if err != nil {
			t.Fatalf("create target: %v", err)
		}
		return tg.ID
	}
	addIP := func(targetID int, addr string) *ent.IP {
		t.Helper()
		i, err := client.IP.Create().SetAddress(addr).AddTargetIDs(targetID).Save(ctx)
		if err != nil {
			t.Fatalf("create ip: %v", err)
		}
		return i
	}
	sslScan := func(targetID int, at time.Time, grade string, exp time.Time) {
		t.Helper()
		if err := client.SSLScan.Create().SetTargetID(targetID).SetScannedAt(at).
			SetGrade(grade).SetStatus("ready").SetCertExpiry(exp).Exec(ctx); err != nil {
			t.Fatalf("create ssl scan: %v", err)
		}
	}
	cspScan := func(targetID int, at time.Time, probeErr string, findings ...csp.Finding) {
		t.Helper()
		c := client.CSPScan.Create().SetTargetID(targetID).SetScannedAt(at).
			SetCspHeader("").SetFindings(findings)
		if probeErr != "" {
			c.SetProbeError(probeErr)
		}
		if err := c.Exec(ctx); err != nil {
			t.Fatalf("create csp scan: %v", err)
		}
	}

	// Two IPs, each with a big old port scan and a smaller newer one.
	// Only the newer scans count: 2 + 2 = 4.
	ports := mk("ports.example")
	for _, addr := range []string{"10.1.0.1", "10.1.0.2"} {
		i := addIP(ports, addr)
		legacyPortScan(t, client, i, older, 22, 80, 443, 8080, 8443)
		legacyPortScan(t, client, i, base, 22, 443) // newer; fewer ports
	}
	// Newest SSL grade B with expiry; older A+ must be ignored.
	ssl := mk("ssl.example")
	sslScan(ssl, older, "A+", expiry.Add(time.Hour))
	sslScan(ssl, base, "B", expiry)

	// Newest SSL scan has no certificate expiry.
	noExp := mk("noexp.example")
	sslScan(noExp, base, "A", time.Time{})

	// Newest CSP scan has three findings.
	csp3 := mk("csp3.example")
	cspScan(csp3, base, "", csp.Finding{Description: "a"}, csp.Finding{Description: "b"}, csp.Finding{Description: "c"})

	// Newest CSP probe failed; the older scan had findings but must not count.
	cspErr := mk("csperr.example")
	cspScan(cspErr, older, "", csp.Finding{Description: "old"})
	cspScan(cspErr, base, "timed out")

	// Nothing scanned at all.
	fresh := mk("fresh.example")

	for range 2 { // idempotent
		if err := s.BackfillSummary(ctx); err != nil {
			t.Fatalf("BackfillSummary: %v", err)
		}
	}

	// Every column, for every target, after the backfill.
	check := func(id int, name string, wantGrade string, wantRank int, wantExp *time.Time, wantCSP *int, wantPorts int) {
		t.Helper()
		tg := client.Target.GetX(ctx, id)
		if tg.LatestSslGrade != wantGrade {
			t.Errorf("%s: latest_ssl_grade = %q, want %q", name, tg.LatestSslGrade, wantGrade)
		}
		if tg.LatestSslGradeRank != wantRank {
			t.Errorf("%s: latest_ssl_grade_rank = %d, want %d", name, tg.LatestSslGradeRank, wantRank)
		}
		switch {
		case wantExp == nil && tg.LatestCertExpiry != nil:
			t.Errorf("%s: latest_cert_expiry = %v, want nil", name, *tg.LatestCertExpiry)
		case wantExp != nil && (tg.LatestCertExpiry == nil || !tg.LatestCertExpiry.Equal(*wantExp)):
			t.Errorf("%s: latest_cert_expiry = %v, want %v", name, tg.LatestCertExpiry, *wantExp)
		}
		switch {
		case wantCSP == nil && tg.LatestCspFindingCount != nil:
			t.Errorf("%s: latest_csp_finding_count = %d, want nil", name, *tg.LatestCspFindingCount)
		case wantCSP != nil && (tg.LatestCspFindingCount == nil || *tg.LatestCspFindingCount != *wantCSP):
			t.Errorf("%s: latest_csp_finding_count = %v, want %d", name, tg.LatestCspFindingCount, *wantCSP)
		}
		if tg.OpenPortCount != wantPorts {
			t.Errorf("%s: open_port_count = %d, want %d", name, tg.OpenPortCount, wantPorts)
		}
	}

	three := 3
	check(ports, "ports", "", 0, nil, nil, 4)
	check(ssl, "ssl", "B", 5, &expiry, nil, 0)
	check(noExp, "noexp", "A", 7, nil, nil, 0)
	check(csp3, "csp3", "", 0, nil, &three, 0)
	check(cspErr, "cspErr", "", 0, nil, nil, 0)
	check(fresh, "fresh", "", 0, nil, nil, 0)

	// The summary is a cache: corrupting it must be repaired by a rerun.
	if err := client.Target.UpdateOneID(ssl).SetOpenPortCount(99).SetLatestSslGradeRank(0).Exec(ctx); err != nil {
		t.Fatalf("corrupt target: %v", err)
	}
	if err := s.BackfillSummary(ctx); err != nil {
		t.Fatalf("BackfillSummary after corruption: %v", err)
	}
	check(ssl, "ssl after corruption", "B", 5, &expiry, nil, 0)
	check(ports, "ports after corruption", "", 0, nil, nil, 4)
}
