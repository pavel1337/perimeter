package server

import (
	"slices"
	"testing"

	"perimeter/ent"
)

func portScanWith(numbers ...int) *ent.PortScan {
	scan := &ent.PortScan{}
	for _, n := range numbers {
		scan.Edges.Ports = append(scan.Edges.Ports, &ent.Port{Number: n})
	}
	return scan
}

func TestPortDelta(t *testing.T) {
	added, removed := portDelta([]int{22, 80, 3306}, []int{80, 22, 8080})
	if !slices.Equal(added, []int{8080}) {
		t.Errorf("added = %v, want [8080]", added)
	}
	if !slices.Equal(removed, []int{3306}) {
		t.Errorf("removed = %v, want [3306]", removed)
	}

	added, removed = portDelta([]int{80}, []int{80})
	if len(added) != 0 || len(removed) != 0 {
		t.Errorf("unchanged set produced %v / %v", added, removed)
	}
}

func TestDiffPortScansDropsLookaheadRow(t *testing.T) {
	// Newest first, one row past a full page.
	items := make([]*ent.PortScan, 0, scanPageSize+1)
	for range scanPageSize {
		items = append(items, portScanWith(80, 443))
	}
	items = append(items, portScanWith(80))

	views := diffPortScans(items)
	if len(views) != scanPageSize {
		t.Fatalf("got %d rows, want %d", len(views), scanPageSize)
	}
	last := views[len(views)-1]
	if !slices.Equal(last.Added, []int{443}) {
		t.Errorf("oldest row on page: added %v, want [443]", last.Added)
	}
	if len(views[0].Added) != 0 || len(views[0].Removed) != 0 {
		t.Errorf("unchanged row got a diff: %v / %v", views[0].Added, views[0].Removed)
	}
}
