package storage

import (
	"context"
	"fmt"
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

// TestStateCounts checks the per-state counts the dashboard's state filter
// links render: one GROUP BY reachability query, f.States ignored, states
// with zero matches still present in the result.
func TestStateCounts(t *testing.T) {
	client := newBackfillClient(t)
	s := NewEntStorage(client)
	ctx := context.Background()

	for _, in := range []string{"ok1.test", "ok2.test", "dark.test", "lost.test", "wait.test"} {
		if _, err := s.ImportTargets(ctx, []string{in}); err != nil {
			t.Fatalf("ImportTargets: %v", err)
		}
	}
	// ok1/ok2 answered a port scan; dark is down; lost did not resolve; wait
	// has not been checked yet.
	for i, in := range []string{"ok1.test", "ok2.test"} {
		addr := fmt.Sprintf("10.2.0.%d", i+1)
		if err := s.SaveIPs(ctx, in, []string{addr}, time.Hour); err != nil {
			t.Fatalf("SaveIPs %s: %v", in, err)
		}
		if err := s.SavePortScan(ctx, addr, []int{80}); err != nil {
			t.Fatalf("SavePortScan %s: %v", in, err)
		}
	}
	if err := s.SaveCSPUnreachable(ctx, "dark.test", "refused"); err != nil {
		t.Fatalf("SaveCSPUnreachable: %v", err)
	}
	if err := s.RecordResolveFailure(ctx, "lost.test", ResolveFailure{Message: "no A record"}); err != nil {
		t.Fatalf("RecordResolveFailure: %v", err)
	}

	prod, err := client.Tag.Create().SetName("prod").Save(ctx)
	if err != nil {
		t.Fatalf("create tag prod: %v", err)
	}
	for _, in := range []string{"ok1.test", "dark.test"} {
		tg, err := client.Target.Query().Where(target.Input(in)).Only(ctx)
		if err != nil {
			t.Fatalf("find %s: %v", in, err)
		}
		if _, err := client.Target.UpdateOne(tg).AddTagIDs(prod.ID).Save(ctx); err != nil {
			t.Fatalf("tag %s: %v", in, err)
		}
	}

	all := map[target.Reachability]int{
		target.ReachabilityOk: 2, target.ReachabilityUnreachable: 1,
		target.ReachabilityUnresolved: 1, target.ReachabilityPending: 1,
	}
	check := func(name string, f TargetFilter, want map[target.Reachability]int) {
		t.Helper()
		got, err := s.StateCounts(ctx, f)
		if err != nil {
			t.Fatalf("StateCounts(%+v): %v", f, err)
		}
		if len(got) != len(want) {
			t.Fatalf("%s: got %v, want %v", name, got, want)
		}
		for st, n := range want {
			if got[st] != n {
				t.Errorf("%s: state %s = %d, want %d", name, st, got[st], n)
			}
		}
	}
	check("no filter", TargetFilter{}, all)
	// The state filter must be ignored so every state link keeps its count.
	check("state filter ignored", TargetFilter{States: []target.Reachability{target.ReachabilityOk}}, all)
	// Other filters still apply.
	check("tag filter applies", TargetFilter{Tag: "prod"}, map[target.Reachability]int{
		target.ReachabilityOk: 1, target.ReachabilityUnreachable: 1,
		target.ReachabilityUnresolved: 0, target.ReachabilityPending: 0,
	})

	if _, err := s.StateCounts(ctx, TargetFilter{CSP: "bogus"}); err == nil {
		t.Error("StateCounts(bogus csp): want error")
	}
}
