package scanner

import (
	"context"
	"database/sql"
	"net"
	"slices"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/ent/enttest"
	"perimeter/ent/target"
	"perimeter/internal/storage"

	sqlite "modernc.org/sqlite"
)

// modernc.org/sqlite registers as "sqlite"; ent opens "sqlite3", so alias it.
func init() { sql.Register("sqlite3", &sqlite.Driver{}) }

type dnsAnswer struct {
	ips []net.IP
	err error
}

// lookupScript returns a fake lookupIP that replays answers in order.
func lookupScript(t *testing.T, answers ...dnsAnswer) func(context.Context, string, string) ([]net.IP, error) {
	t.Helper()
	calls := 0
	return func(_ context.Context, _, _ string) ([]net.IP, error) {
		if calls >= len(answers) {
			t.Fatalf("lookup called more than the %d scripted answers", len(answers))
		}
		a := answers[calls]
		calls++
		return a.ips, a.err
	}
}

// newManagerForTest builds a real storage (per-test DSN) and a manager whose
// lookup is scripted with answers.
func newManagerForTest(t *testing.T, answers ...dnsAnswer) (*Manager, *storage.EntStorage) {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:"+t.Name()+"?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	t.Cleanup(func() { client.Close() })
	st := storage.NewEntStorage(client)
	m := NewManager(st, ScannerConfig{}, nil)
	m.lookupIP = lookupScript(t, answers...)
	return m, st
}

// targetByInput returns the live target with the given input.
func targetByInput(t *testing.T, st *storage.EntStorage, input string) *ent.Target {
	t.Helper()
	targets, err := st.GetTargets(context.Background())
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	for _, tg := range targets {
		if tg.Input == input {
			return tg
		}
	}
	t.Fatalf("target %s not found", input)
	return nil
}

// linkedAddresses returns the sorted addresses linked to id.
func linkedAddresses(t *testing.T, st *storage.EntStorage, id int) []string {
	t.Helper()
	tg, err := st.GetTarget(context.Background(), id)
	if err != nil {
		t.Fatalf("GetTarget(%d): %v", id, err)
	}
	var addrs []string
	for _, i := range tg.Edges.Ips {
		addrs = append(addrs, i.Address)
	}
	slices.Sort(addrs)
	return addrs
}

// assertNear reports a failure unless got is within tol of want.
func assertNear(t *testing.T, name string, got *time.Time, want time.Time, tol time.Duration) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s: nil, want about %v", name, want)
	}
	if d := got.Sub(want); d < -tol || d > tol {
		t.Errorf("%s = %v, want about %v (±%v)", name, *got, want, tol)
	}
}

func TestResolutionFollowsMovedRecord(t *testing.T) {
	m, st := newManagerForTest(t,
		dnsAnswer{ips: []net.IP{net.ParseIP("192.0.2.1")}},
		dnsAnswer{ips: []net.IP{net.ParseIP("192.0.2.2")}},
	)
	ctx := context.Background()
	if _, err := st.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}

	m.processResolution(ctx, Job{Type: JobTypeResolution, Input: "example.com"})
	m.processResolution(ctx, Job{Type: JobTypeResolution, Input: "example.com"})

	tg := targetByInput(t, st, "example.com")
	if got := linkedAddresses(t, st, tg.ID); !slices.Equal(got, []string{"192.0.2.2"}) {
		t.Errorf("linked = %v, want only the moved record [192.0.2.2]", got)
	}
	assertNear(t, "next_resolve_at", tg.NextResolveAt, time.Now().Add(time.Hour), time.Minute)
}

func TestResolutionNXDOMAINAfterSuccess(t *testing.T) {
	m, st := newManagerForTest(t,
		dnsAnswer{ips: []net.IP{net.ParseIP("192.0.2.1")}},
		dnsAnswer{err: &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true}},
	)
	ctx := context.Background()
	if _, err := st.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}

	m.processResolution(ctx, Job{Type: JobTypeResolution, Input: "example.com"})
	m.processResolution(ctx, Job{Type: JobTypeResolution, Input: "example.com"})

	tg := targetByInput(t, st, "example.com")
	if got := linkedAddresses(t, st, tg.ID); len(got) != 0 {
		t.Errorf("linked = %v, want none after NXDOMAIN", got)
	}
	if got := tg.Reachability; got != target.ReachabilityUnresolved {
		t.Errorf("reachability = %s, want unresolved", got)
	}
	if tg.ResolveError != "no such host (NXDOMAIN)" {
		t.Errorf("resolve_error = %q, want %q", tg.ResolveError, "no such host (NXDOMAIN)")
	}
	assertNear(t, "next_resolve_at", tg.NextResolveAt, time.Now().Add(resolveBackoff(1, time.Minute)), time.Minute)
}

func TestResolutionTimeoutKeepsIPs(t *testing.T) {
	m, st := newManagerForTest(t,
		dnsAnswer{ips: []net.IP{net.ParseIP("192.0.2.1")}},
		dnsAnswer{err: &net.DNSError{Err: "i/o timeout", Name: "example.com", IsTimeout: true}},
	)
	ctx := context.Background()
	if _, err := st.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}

	m.processResolution(ctx, Job{Type: JobTypeResolution, Input: "example.com"})
	m.processResolution(ctx, Job{Type: JobTypeResolution, Input: "example.com"})

	tg := targetByInput(t, st, "example.com")
	if got := linkedAddresses(t, st, tg.ID); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("linked = %v, want the IP kept on timeout", got)
	}
	if tg.ResolveError != "DNS timeout" {
		t.Errorf("resolve_error = %q, want %q", tg.ResolveError, "DNS timeout")
	}
	if tg.ResolveAttempts != 1 {
		t.Errorf("resolve_attempts = %d, want 1", tg.ResolveAttempts)
	}
}

func TestResolutionEmptyAnswerIsNameGone(t *testing.T) {
	m, st := newManagerForTest(t,
		dnsAnswer{ips: []net.IP{net.ParseIP("192.0.2.1")}},
		dnsAnswer{ips: []net.IP{}},
	)
	ctx := context.Background()
	if _, err := st.ImportTargets(ctx, []string{"example.com"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}

	m.processResolution(ctx, Job{Type: JobTypeResolution, Input: "example.com"})
	m.processResolution(ctx, Job{Type: JobTypeResolution, Input: "example.com"})

	tg := targetByInput(t, st, "example.com")
	if got := linkedAddresses(t, st, tg.ID); len(got) != 0 {
		t.Errorf("linked = %v, want none after an empty answer", got)
	}
	if got := tg.Reachability; got != target.ReachabilityUnresolved {
		t.Errorf("reachability = %s, want unresolved", got)
	}
}
