package service_test

import (
	"testing"

	"perimeter/ent/target"
	"perimeter/internal/service"
)

// Deleted targets keep their last state, and states can filter them:
// states ok lists those that still answered when deleted (#77).
func TestListDeletedByState(t *testing.T) {
	f := newFixture(t)
	f.target("live.example")
	f.target("dead.example")
	_, err := f.client.Target.Update().Where(target.Input("live.example")).SetReachability(target.ReachabilityOk).Save(f.ctx)
	f.must(err)
	for _, in := range []string{"live.example", "dead.example"} {
		f.must(f.st.DeleteTarget(f.ctx, f.id(in)))
	}

	page, err := f.svc.ListTargets(f.ctx, service.TargetQuery{Deleted: true, States: []string{"ok"}})
	f.must(err)
	if page.Total != 1 || page.Items[0].Input != "live.example" || page.Items[0].Reachability != "ok" {
		t.Errorf("deleted, states=ok = %+v, want live.example", page.Items)
	}
	if _, err := f.svc.ListTargets(f.ctx, service.TargetQuery{Deleted: true, States: []string{"nope"}}); err == nil {
		t.Error("unknown state accepted")
	}
}
