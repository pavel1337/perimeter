package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"perimeter/ent"
	"perimeter/internal/auth"
	"perimeter/internal/storage"
)

func timePtr(t time.Time) *time.Time { return &t }

// renderIndexCertCells renders the dashboard through handleIndex, with the
// real template funcs (via New), and returns the Cert Expiry cell body for
// each target row.
func renderIndexCertCells(t *testing.T, targets []*ent.Target) []string {
	t.Helper()
	fs := &fakeStore{targets: targets, stats: storage.TargetStats{Total: len(targets)}}
	srv := New(fs, &auth.Auth{}, newTestClient(t), nil, nil, os.DirFS("../.."), 30*24*time.Hour, 50)
	// Mount the handler on a bare app: the authed route needs a session.
	app := fiber.New(fiber.Config{Views: srv.app.Config().Views})
	app.Get("/", srv.handleIndex)

	resp, err := app.Test(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /: status %d, body:\n%s", resp.StatusCode, body)
	}
	// Fiber's html engine writes template execution errors into the output
	// instead of returning them, so check for them explicitly.
	if strings.Contains(string(body), "template: views/") {
		t.Fatalf("template execution error in output:\n%s", body)
	}
	return certCellBodies(t, string(body))
}

var certCellRe = regexp.MustCompile(`(?s)<td>\s*(.*?)\s*</td>`)

// certCellBodies pulls the Cert Expiry column out of each target row. Column
// 6 (0-based 5) is the cert cell, after the bulk-select checkbox column; the
// rows are identified by the Delete form.
func certCellBodies(t *testing.T, html string) []string {
	t.Helper()
	var out []string
	for _, row := range strings.Split(html, "<tr>")[1:] {
		if !strings.Contains(row, `action="/targets/`) {
			continue
		}
		tds := certCellRe.FindAllStringSubmatch(row, -1)
		if len(tds) < 6 {
			t.Fatalf("expected at least 6 cells in row, got %d", len(tds))
		}
		out = append(out, strings.Join(strings.Fields(tds[5][1]), " "))
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
