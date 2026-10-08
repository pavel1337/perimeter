package server

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"perimeter/ent"
	"perimeter/internal/auth"
)

func intPtr(n int) *int { return &n }

func timePtr(t time.Time) *time.Time { return &t }

func TestDashboardStats(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	const window = 30 * 24 * time.Hour

	tests := []struct {
		name                       string
		targets                    []*ent.Target
		wantPorts, wantExp, wantCS int
	}{
		{
			name:    "no targets",
			targets: nil,
		},
		{
			name:    "nil pointers and zero ports count as nothing",
			targets: []*ent.Target{{}},
		},
		{
			name: "expired cert is not expiring",
			targets: []*ent.Target{
				{LatestCertExpiry: timePtr(now.Add(-time.Hour))},
			},
		},
		{
			name: "cert expiring exactly now is not expiring",
			targets: []*ent.Target{
				{LatestCertExpiry: timePtr(now)},
			},
		},
		{
			name: "cert outside window is not expiring",
			targets: []*ent.Target{
				{LatestCertExpiry: timePtr(now.Add(window + time.Hour))},
			},
		},
		{
			name: "cert exactly at window edge is not expiring",
			targets: []*ent.Target{
				{LatestCertExpiry: timePtr(now.Add(window))},
			},
		},
		{
			name: "cert inside window is expiring",
			targets: []*ent.Target{
				{LatestCertExpiry: timePtr(now.Add(window - time.Hour))},
			},
			wantExp: 1,
		},
		{
			name: "zero CSP count is not an issue, positive is",
			targets: []*ent.Target{
				{LatestCspFindingCount: intPtr(0)},
				{LatestCspFindingCount: intPtr(3)},
				{LatestCspFindingCount: nil},
			},
			wantCS: 1,
		},
		{
			name: "port counts are summed across targets",
			targets: []*ent.Target{
				{OpenPortCount: 2},
				{OpenPortCount: 0},
				{OpenPortCount: 5},
			},
			wantPorts: 7,
		},
		{
			name: "all three counters together",
			targets: []*ent.Target{
				{OpenPortCount: 4, LatestCertExpiry: timePtr(now.Add(24 * time.Hour)), LatestCspFindingCount: intPtr(1)},
				{OpenPortCount: 1, LatestCertExpiry: timePtr(now.Add(-24 * time.Hour)), LatestCspFindingCount: intPtr(0)},
				{OpenPortCount: 0, LatestCertExpiry: nil, LatestCspFindingCount: nil},
			},
			wantPorts: 5,
			wantExp:   1,
			wantCS:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports, exp, cs := dashboardStats(tt.targets, window, now)
			if ports != tt.wantPorts || exp != tt.wantExp || cs != tt.wantCS {
				t.Errorf("dashboardStats() = (%d, %d, %d), want (%d, %d, %d)",
					ports, exp, cs, tt.wantPorts, tt.wantExp, tt.wantCS)
			}
		})
	}
}

// renderIndexCertCells renders views/index with the real template funcs
// (via New) and returns the Cert Expiry cell body for each target row.
func renderIndexCertCells(t *testing.T, targets []*ent.Target) []string {
	t.Helper()
	// Zero-value auth: setupRoutes only needs OIDCEnabled to answer false.
	srv := New(nil, &auth.Auth{}, nil, nil, nil, os.DirFS("../.."), 30*24*time.Hour)

	var buf bytes.Buffer
	// Same keys handleIndex passes; the stats come from the function under test.
	ports, expiring, csp := dashboardStats(targets, srv.certExpiryWindow, time.Now())
	data := fiber.Map{
		"Title":          "Perimeter Dashboard",
		"Targets":        targets,
		"Tags":           []*ent.Tag{},
		"States":         reachabilityStates,
		"TotalTargets":   len(targets),
		"TotalOpenPorts": ports,
		"ExpiringCerts":  expiring,
		"CSPIssues":      csp,
		"CertExpiryDays": int(srv.certExpiryWindow.Hours() / 24),
	}
	if err := srv.app.Config().Views.Render(&buf, "views/index", data, "views/layouts/main"); err != nil {
		t.Fatalf("render index: %v", err)
	}
	// Fiber's html engine writes template execution errors into the output
	// instead of returning them, so check for them explicitly.
	if strings.Contains(buf.String(), "template: views/") {
		t.Fatalf("template execution error in output:\n%s", buf.String())
	}
	return certCellBodies(t, buf.String())
}

var certCellRe = regexp.MustCompile(`(?s)<td>\s*(.*?)\s*</td>`)

// certCellBodies pulls the Cert Expiry column out of each target row. Column
// 5 (0-based 4) is the cert cell; the rows are identified by the Delete form.
func certCellBodies(t *testing.T, html string) []string {
	t.Helper()
	var out []string
	for _, row := range strings.Split(html, "<tr>")[1:] {
		if !strings.Contains(row, `action="/targets/`) {
			continue
		}
		tds := certCellRe.FindAllStringSubmatch(row, -1)
		if len(tds) < 5 {
			t.Fatalf("expected at least 5 cells in row, got %d", len(tds))
		}
		out = append(out, strings.Join(strings.Fields(tds[4][1]), " "))
	}
	return out
}

func TestIndexCertExpiryCell(t *testing.T) {
	now := time.Now()
	targets := []*ent.Target{
		{ID: 1, Input: "unknown.example", Reachability: "ok", LatestCertExpiry: nil,
			Edges: ent.TargetEdges{SslScans: []*ent.SSLScan{{}}}},
		{ID: 2, Input: "soon.example", Reachability: "ok",
			LatestCertExpiry: timePtr(now.Add(10*24*time.Hour + time.Hour))},
		{ID: 3, Input: "far.example", Reachability: "ok",
			LatestCertExpiry: timePtr(now.Add(100*24*time.Hour + time.Hour))},
		{ID: 4, Input: "gone.example", Reachability: "ok",
			LatestCertExpiry: timePtr(now.Add(-48 * time.Hour))},
	}
	cells := renderIndexCertCells(t, targets)
	if len(cells) != len(targets) {
		t.Fatalf("got %d cert cells, want %d", len(cells), len(targets))
	}

	if cells[0] != "<span class=\"text-muted\">—</span>" {
		t.Errorf("nil expiry with scans: want em dash, got %q", cells[0])
	}
	if !strings.Contains(cells[1], "badge-red") || !strings.Contains(cells[1], "> 10d </span>") {
		t.Errorf("expiring cert: want red 10d badge, got %q", cells[1])
	}
	if strings.Contains(cells[2], "badge-red") || !strings.Contains(cells[2], "text-muted") || !strings.Contains(cells[2], " 100d </span>") {
		t.Errorf("far cert: want muted, non-red badge, got %q", cells[2])
	}
	if !strings.Contains(cells[3], "expired") || !strings.Contains(cells[3], "badge-red") {
		t.Errorf("expired cert: want red expired badge, got %q", cells[3])
	}
}
