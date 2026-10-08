package storage

import (
	"context"
	"slices"
	"testing"
	"time"

	"perimeter/ent/target"
)

// Tags have no write API in storage, so these tests create them through the
// ent client and then check the tag filter in ListTargets and TargetStats.
func TestListTargetsTagFilter(t *testing.T) {
	client := newBackfillClient(t)
	s := NewEntStorage(client)
	ctx := context.Background()

	for _, in := range []string{"t1.test", "t2.test", "t3.test"} {
		if _, err := s.ImportTargets(ctx, []string{in}); err != nil {
			t.Fatalf("ImportTargets: %v", err)
		}
	}
	// t1 answers an HTTP probe, t2 has no response, t3 has no response.
	if err := s.SaveCSPScan(ctx, "t1.test", "", nil); err != nil {
		t.Fatalf("SaveCSPScan: %v", err)
	}
	if err := s.SaveCSPUnreachable(ctx, "t2.test", "refused"); err != nil {
		t.Fatalf("SaveCSPUnreachable: %v", err)
	}
	if err := s.SaveCSPUnreachable(ctx, "t3.test", "refused"); err != nil {
		t.Fatalf("SaveCSPUnreachable: %v", err)
	}

	prod, err := client.Tag.Create().SetName("prod").Save(ctx)
	if err != nil {
		t.Fatalf("create tag prod: %v", err)
	}
	dev, err := client.Tag.Create().SetName("dev").Save(ctx)
	if err != nil {
		t.Fatalf("create tag dev: %v", err)
	}
	link := func(input string, tagIDs ...int) {
		t.Helper()
		tg, err := client.Target.Query().Where(target.Input(input)).Only(ctx)
		if err != nil {
			t.Fatalf("find %s: %v", input, err)
		}
		if _, err := client.Target.UpdateOne(tg).AddTagIDs(tagIDs...).Save(ctx); err != nil {
			t.Fatalf("tag %s: %v", input, err)
		}
	}
	link("t1.test", prod.ID)
	link("t2.test", dev.ID)
	link("t3.test", prod.ID, dev.ID)

	inputs := func(f TargetFilter) []string {
		t.Helper()
		ts, err := s.ListTargets(ctx, f, TargetSort{}, 0, 0)
		if err != nil {
			t.Fatalf("ListTargets(%+v): %v", f, err)
		}
		out := []string{}
		for _, tg := range ts {
			out = append(out, tg.Input)
		}
		return out
	}
	check := func(name string, got, want []string) {
		t.Helper()
		if !slices.Equal(got, want) {
			t.Errorf("%s: got %v, want %v", name, got, want)
		}
	}

	check("tag prod", inputs(TargetFilter{Tag: "prod"}), []string{"t1.test", "t3.test"})
	check("tag dev", inputs(TargetFilter{Tag: "dev"}), []string{"t2.test", "t3.test"})
	check("tag missing", inputs(TargetFilter{Tag: "missing"}), []string{})
	check("tag prod + unreachable",
		inputs(TargetFilter{Tag: "prod", States: []target.Reachability{target.ReachabilityUnreachable}}),
		[]string{"t3.test"})

	stats, err := s.TargetStats(ctx, TargetFilter{Tag: "prod"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("TargetStats: %v", err)
	}
	if stats.Total != 2 {
		t.Errorf("stats.Total for tag prod = %d, want 2", stats.Total)
	}
}
