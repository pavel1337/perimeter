package storage_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/internal/storage"
	"perimeter/scanner/csp"
)

var allRescan = storage.RescanKinds{SSL: true, CSP: true, Ports: true}

// rescanTarget loads a live target with its IPs.
func rescanTarget(t *testing.T, s *storage.EntStorage, id int) *ent.Target {
	t.Helper()
	tg, err := s.GetTarget(context.Background(), id)
	if err != nil {
		t.Fatalf("GetTarget(%d): %v", id, err)
	}
	return tg
}

// ipFlag reports the rescan_pending flag of the IP with the given address.
func ipFlag(t *testing.T, tg *ent.Target, address string) bool {
	t.Helper()
	for _, i := range tg.Edges.Ips {
		if i.Address == address {
			return i.RescanPending
		}
	}
	t.Fatalf("target %s has no IP %s", tg.Input, address)
	return false
}

func TestRequestRescanFlagsTargetAndIPs(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	id := importHosts(t, s, "r", 1)[0]
	if err := s.SaveIPs(ctx, mustTargetInput(t, s, id), []string{"192.0.2.1", "192.0.2.2"}, time.Hour); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}

	now := time.Now()
	res, err := s.RequestRescan(ctx, []int{id}, now, 10*time.Minute, allRescan)
	if err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}
	if want := []int{id}; !slices.Equal(res.Queued, want) || len(res.CoolingDown) != 0 || len(res.NotFound) != 0 {
		t.Fatalf("RequestRescan = %+v, want Queued %v only", res, want)
	}

	tg := rescanTarget(t, s, id)
	if !tg.SslRescanPending || !tg.CspRescanPending {
		t.Errorf("ssl/csp pending = %v/%v, want both true", tg.SslRescanPending, tg.CspRescanPending)
	}
	if tg.RescanRequestedAt == nil || tg.RescanRequestedAt.Sub(now).Abs() > time.Second {
		t.Errorf("rescan_requested_at = %v, want about %v", tg.RescanRequestedAt, now)
	}
	if !ipFlag(t, tg, "192.0.2.1") || !ipFlag(t, tg, "192.0.2.2") {
		t.Errorf("IPs of the target not flagged for a port rescan")
	}
}

func TestRequestRescanKindsAndIPTargets(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	if _, err := s.ImportTargets(ctx, []string{"kinds.example", "198.51.100.7"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	all, err := s.GetTargets(ctx)
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	var domain, addr int
	for _, tg := range all {
		if tg.Input == "kinds.example" {
			domain = tg.ID
		} else {
			addr = tg.ID
		}
	}
	if err := s.SaveIPs(ctx, "kinds.example", []string{"192.0.2.10"}, time.Hour); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}

	// SSL is off (no SSL Labs email), so its flag must not be set: nothing
	// would clear it.
	res, err := s.RequestRescan(ctx, []int{domain, addr}, time.Now(), time.Minute, storage.RescanKinds{CSP: true, Ports: true})
	if err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}
	if !slices.Equal(res.Queued, []int{domain, addr}) && !slices.Equal(res.Queued, []int{addr, domain}) {
		t.Fatalf("Queued = %v, want both targets", res.Queued)
	}

	dom := rescanTarget(t, s, domain)
	if dom.SslRescanPending {
		t.Errorf("ssl flag set although SSL was not requested")
	}
	if !dom.CspRescanPending || !ipFlag(t, dom, "192.0.2.10") {
		t.Errorf("CSP or port flag missing on a domain target")
	}

	// An IP target is never SSL or CSP scanned, only its ports.
	ipTarget := rescanTarget(t, s, addr)
	if ipTarget.SslRescanPending || ipTarget.CspRescanPending {
		t.Errorf("IP target got ssl/csp flags: %v/%v", ipTarget.SslRescanPending, ipTarget.CspRescanPending)
	}
	if ipTarget.RescanRequestedAt == nil {
		t.Errorf("IP target has no rescan_requested_at")
	}
}

func TestRequestRescanCooldown(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	ids := importHosts(t, s, "c", 2)
	a, b := ids[0], ids[1]

	now := time.Now()
	if _, err := s.RequestRescan(ctx, []int{a}, now, 10*time.Minute, allRescan); err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}

	// a asked for a minute ago is cooling down; b is queued.
	res, err := s.RequestRescan(ctx, []int{a, b}, now.Add(time.Minute), 10*time.Minute, allRescan)
	if err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}
	if !slices.Equal(res.Queued, []int{b}) {
		t.Errorf("Queued = %v, want [%d]", res.Queued, b)
	}
	if len(res.CoolingDown) != 1 || res.CoolingDown[0].ID != a {
		t.Fatalf("CoolingDown = %+v, want target %d", res.CoolingDown, a)
	}
	if want := now.Add(10 * time.Minute); res.CoolingDown[0].RetryAt.Sub(want).Abs() > time.Second {
		t.Errorf("RetryAt = %v, want about %v", res.CoolingDown[0].RetryAt, want)
	}

	// A cooling-down request does not move rescan_requested_at.
	if tg := rescanTarget(t, s, a); tg.RescanRequestedAt.Sub(now).Abs() > time.Second {
		t.Errorf("rescan_requested_at moved to %v by a refused request", tg.RescanRequestedAt)
	}

	// Once the cooldown has passed, the same target is queued again.
	res, err = s.RequestRescan(ctx, []int{a}, now.Add(10*time.Minute), 10*time.Minute, allRescan)
	if err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}
	if !slices.Equal(res.Queued, []int{a}) || len(res.CoolingDown) != 0 {
		t.Errorf("after cooldown: %+v, want queued", res)
	}
}

func TestRequestRescanNotFound(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	ids := importHosts(t, s, "nf", 2)
	mustDelete(t, s, ids[1])

	const unknown = 99999
	res, err := s.RequestRescan(ctx, []int{ids[0], ids[1], unknown}, time.Now(), time.Minute, allRescan)
	if err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}
	if !slices.Equal(res.Queued, []int{ids[0]}) {
		t.Errorf("Queued = %v, want [%d]", res.Queued, ids[0])
	}
	if want := []int{ids[1], unknown}; !slices.Equal(res.NotFound, want) {
		t.Errorf("NotFound = %v, want %v (deleted and unknown)", res.NotFound, want)
	}
}

func TestGetOldestOutdatedTargetPrefersRescanRequests(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	ids := importHosts(t, s, "p", 3)

	// Never scanned, so every target is outdated; whichever comes first now
	// is the baseline. Ask for a rescan of another one.
	base, err := s.GetOldestOutdatedTarget(ctx, storage.ScanTypeSSL, time.Hour)
	if err != nil || base == nil {
		t.Fatalf("GetOldestOutdatedTarget: %v", err)
	}
	other := ids[0]
	if other == base.ID {
		other = ids[1]
	}
	if _, err := s.RequestRescan(ctx, []int{other}, time.Now(), time.Minute, allRescan); err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}

	for _, typ := range []storage.ScanType{storage.ScanTypeSSL, storage.ScanTypeCSP} {
		got, err := s.GetOldestOutdatedTarget(ctx, typ, time.Hour)
		if err != nil || got == nil {
			t.Fatalf("GetOldestOutdatedTarget(%s): %v", typ, err)
		}
		if got.ID != other {
			t.Errorf("GetOldestOutdatedTarget(%s) = %d, want the rescan request %d", typ, got.ID, other)
		}
	}
}

func TestGetOldestOutdatedTargetOldestRequestFirst(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	ids := importHosts(t, s, "q", 2)
	first, second := ids[0], ids[1]

	now := time.Now()
	if _, err := s.RequestRescan(ctx, []int{second}, now, time.Minute, allRescan); err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}
	if _, err := s.RequestRescan(ctx, []int{first}, now.Add(time.Second), time.Minute, allRescan); err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}
	got, err := s.GetOldestOutdatedTarget(ctx, storage.ScanTypeSSL, time.Hour)
	if err != nil || got == nil {
		t.Fatalf("GetOldestOutdatedTarget: %v", err)
	}
	if got.ID != second {
		t.Errorf("got %d, want %d: the earlier request goes first", got.ID, second)
	}
}

func TestGetOutdatedIPsPrefersRescanRequests(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	if _, err := s.ImportTargets(ctx, []string{"ports.example", "other.example"}); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	if err := s.SaveIPs(ctx, "ports.example", []string{"192.0.2.20", "192.0.2.21"}, time.Hour); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}
	if err := s.SaveIPs(ctx, "other.example", []string{"198.51.100.1"}, time.Hour); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}
	// ports.example's IPs are freshly scanned: not outdated, so only a rescan
	// brings them back. 198.51.100.1 was never scanned.
	for _, addr := range []string{"192.0.2.20", "192.0.2.21"} {
		if err := s.SavePortScan(ctx, addr, []int{80}); err != nil {
			t.Fatalf("SavePortScan: %v", err)
		}
	}
	ips, err := s.GetOutdatedIPs(ctx, 10, time.Hour)
	if err != nil {
		t.Fatalf("GetOutdatedIPs: %v", err)
	}
	if len(ips) != 1 || ips[0].Address != "198.51.100.1" {
		t.Fatalf("before rescan got %d IPs, want only 198.51.100.1", len(ips))
	}

	id := idOf(t, s, "ports.example")
	if _, err := s.RequestRescan(ctx, []int{id}, time.Now(), time.Minute, storage.RescanKinds{Ports: true}); err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}
	ips, err = s.GetOutdatedIPs(ctx, 10, time.Hour)
	if err != nil {
		t.Fatalf("GetOutdatedIPs: %v", err)
	}
	if len(ips) != 3 {
		t.Fatalf("after rescan got %d IPs, want 3", len(ips))
	}
	// The requested IPs come first, the never-scanned one last.
	if ips[2].Address != "198.51.100.1" {
		t.Errorf("last IP = %s, want the unrequested 198.51.100.1", ips[2].Address)
	}
}

func TestStoredResultsClearRescanFlags(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	id := importHosts(t, s, "clear", 1)[0]
	input := mustTargetInput(t, s, id)
	if err := s.SaveIPs(ctx, input, []string{"192.0.2.30", "192.0.2.31"}, time.Hour); err != nil {
		t.Fatalf("SaveIPs: %v", err)
	}

	now := time.Now()
	if _, err := s.RequestRescan(ctx, []int{id}, now, time.Minute, allRescan); err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}

	if err := s.SaveSSLScan(ctx, input, storage.SSLResult{Grade: "A", Status: "READY"}); err != nil {
		t.Fatalf("SaveSSLScan: %v", err)
	}
	tg := rescanTarget(t, s, id)
	if tg.SslRescanPending {
		t.Errorf("SaveSSLScan left ssl_rescan_pending set")
	}
	if !tg.CspRescanPending {
		t.Errorf("SaveSSLScan cleared the CSP flag")
	}

	if err := s.SaveCSPScan(ctx, input, "default-src 'self'", []csp.Finding{}); err != nil {
		t.Fatalf("SaveCSPScan: %v", err)
	}
	if tg = rescanTarget(t, s, id); tg.CspRescanPending {
		t.Errorf("SaveCSPScan left csp_rescan_pending set")
	}

	if err := s.SavePortScan(ctx, "192.0.2.30", []int{443}); err != nil {
		t.Fatalf("SavePortScan: %v", err)
	}
	tg = rescanTarget(t, s, id)
	if ipFlag(t, tg, "192.0.2.30") {
		t.Errorf("SavePortScan left rescan_pending set on its IP")
	}
	if !ipFlag(t, tg, "192.0.2.31") {
		t.Errorf("SavePortScan cleared the flag of another IP")
	}

	// The unreachable paths clear their flags too. Requests are a minute
	// apart from the first, so use a later time to get past the cooldown.
	later := now.Add(2 * time.Minute)
	if _, err := s.RequestRescan(ctx, []int{id}, later, time.Minute, allRescan); err != nil {
		t.Fatalf("RequestRescan: %v", err)
	}
	if err := s.SaveCSPUnreachable(ctx, input, "no response"); err != nil {
		t.Fatalf("SaveCSPUnreachable: %v", err)
	}
	if err := s.SavePortScanError(ctx, "192.0.2.31", "timed out"); err != nil {
		t.Fatalf("SavePortScanError: %v", err)
	}
	tg = rescanTarget(t, s, id)
	if tg.CspRescanPending || ipFlag(t, tg, "192.0.2.31") {
		t.Errorf("unreachable results left flags set: csp=%v ip=%v", tg.CspRescanPending, ipFlag(t, tg, "192.0.2.31"))
	}
	if !tg.SslRescanPending {
		t.Errorf("a CSP result cleared the SSL flag")
	}
}
