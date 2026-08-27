package storage

import (
	"context"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/ent/enttest"
	"perimeter/ent/ip"
	"perimeter/ent/portscan"
)

func newBackfillClient(t *testing.T) *ent.Client {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:collapse?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	t.Cleanup(func() { client.Close() })
	return client
}

// legacyPortScan writes a row in the pre-issue-#4 shape: one sample, no period,
// check_count left at its zero default.
func legacyPortScan(t *testing.T, client *ent.Client, i *ent.IP, at time.Time, ports ...int) {
	t.Helper()
	ctx := context.Background()
	scan, err := client.PortScan.Create().SetIP(i).SetScannedAt(at).Save(ctx)
	if err != nil {
		t.Fatalf("create port scan: %v", err)
	}
	for _, p := range ports {
		if _, err := client.Port.Create().SetScan(scan).SetNumber(p).Save(ctx); err != nil {
			t.Fatalf("create port: %v", err)
		}
	}
}

func TestCollapseScanHistoryBackfill(t *testing.T) {
	client := newBackfillClient(t)
	s := NewEntStorage(client)
	ctx := context.Background()

	i, err := client.IP.Create().SetAddress("1.2.3.4").Save(ctx)
	if err != nil {
		t.Fatalf("create ip: %v", err)
	}

	base := time.Now().Add(-10 * time.Hour).Truncate(time.Second)
	runs := [][]int{{80, 443}, {80, 443}, {80, 443, 8080}, {80, 443, 8080}, {80, 443}}
	for n, ports := range runs {
		legacyPortScan(t, client, i, base.Add(time.Duration(n)*time.Hour), ports...)
	}

	if err := s.CollapseScanHistory(ctx); err != nil {
		t.Fatalf("CollapseScanHistory: %v", err)
	}

	scans, err := client.PortScan.Query().
		Where(portscan.HasIPWith(ip.IDEQ(i.ID))).
		Order(ent.Asc(portscan.FieldScannedAt)).
		WithPorts().
		All(ctx)
	if err != nil {
		t.Fatalf("query scans: %v", err)
	}
	if len(scans) != 3 {
		t.Fatalf("expected 3 rows after collapse, got %d", len(scans))
	}

	want := []struct {
		ports    []int
		count    int
		lastSeen time.Time
	}{
		{[]int{80, 443}, 2, base.Add(1 * time.Hour)},
		{[]int{80, 443, 8080}, 2, base.Add(3 * time.Hour)},
		{[]int{80, 443}, 1, base.Add(4 * time.Hour)},
	}
	for n, w := range want {
		got := scans[n]
		if !samePorts(scanPorts(got), w.ports) {
			t.Errorf("row %d: ports %v, want %v", n, scanPorts(got), w.ports)
		}
		if got.CheckCount != w.count {
			t.Errorf("row %d: check_count %d, want %d", n, got.CheckCount, w.count)
		}
		if !got.LastSeenAt.Equal(w.lastSeen) {
			t.Errorf("row %d: last_seen_at %v, want %v", n, got.LastSeenAt, w.lastSeen)
		}
	}

	// Orphaned Port rows must go with the scans they belonged to.
	ports, err := client.Port.Query().Count(ctx)
	if err != nil {
		t.Fatalf("count ports: %v", err)
	}
	if ports != 7 {
		t.Errorf("expected 7 port rows, got %d", ports)
	}

	// Second boot is a no-op: nothing carries check_count = 0 any more.
	if err := s.CollapseScanHistory(ctx); err != nil {
		t.Fatalf("second CollapseScanHistory: %v", err)
	}
	again, err := client.PortScan.Query().
		Where(portscan.HasIPWith(ip.IDEQ(i.ID))).
		Order(ent.Asc(portscan.FieldScannedAt)).
		All(ctx)
	if err != nil {
		t.Fatalf("query scans: %v", err)
	}
	if len(again) != 3 {
		t.Fatalf("second run changed row count: %d", len(again))
	}
	for n, got := range again {
		if got.CheckCount != want[n].count {
			t.Errorf("second run row %d: check_count %d, want %d", n, got.CheckCount, want[n].count)
		}
	}
}
