package service_test

import (
	"strings"
	"testing"
	"time"

	"perimeter/internal/service"
	"perimeter/internal/storage"
)

func dnsFeed(t *testing.T, f *fixture) []string {
	t.Helper()
	got, _, err := f.svc.ChangesSince(f.ctx, time.Time{}, 0)
	f.must(err)
	var out []string
	for _, c := range got {
		if c.Kind == service.ChangeDNSChanged {
			out = append(out, c.Summary)
		}
	}
	return out
}

// Re-resolves that change something show up in the feed and the history
// (issue #74); a CDN rotating some of its IPs only in the history.
func TestDNSChanges(t *testing.T) {
	f := newFixture(t)
	f.target("app.example.com")
	in := "app.example.com"
	gone := storage.ResolveFailure{Message: "no such host (NXDOMAIN)", NameGone: true}

	f.must(f.st.SaveIPs(f.ctx, in, []string{"192.0.2.10", "192.0.2.11"}, time.Hour)) // first lookup: no change
	f.must(f.st.SaveIPs(f.ctx, in, []string{"192.0.2.10", "192.0.2.12"}, time.Hour)) // rotation, one kept
	f.must(f.st.SaveIPs(f.ctx, in, []string{"198.51.100.20"}, time.Hour))            // moved
	f.must(f.st.RecordResolveFailure(f.ctx, in, gone))                               // gone
	f.must(f.st.SaveIPs(f.ctx, in, []string{"198.51.100.20"}, time.Hour))            // back

	want := []string{
		"app.example.com: DNS moved from 192.0.2.10, 192.0.2.12 to 198.51.100.20",
		"app.example.com: name no longer resolves (was 198.51.100.20)",
		"app.example.com: resolves again, to 198.51.100.20",
	}
	got := dnsFeed(t, f)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("feed:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	page, err := f.svc.TargetHistory(f.ctx, f.id(in), 0, 0)
	f.must(err)
	var dns []string
	for _, e := range page.Items {
		if e.Kind == "dns" {
			dns = append(dns, e.Summary)
		}
	}
	if len(dns) != 4 || dns[3] != "DNS moved from 192.0.2.11 to 192.0.2.12" {
		t.Errorf("history dns entries = %q, want 4 with the rotation oldest", dns)
	}
}

// A name that never resolved and then does is a first lookup, not "back".
func TestDNSFirstResolveAfterFailures(t *testing.T) {
	f := newFixture(t)
	f.target("new.example.com")
	f.must(f.st.RecordResolveFailure(f.ctx, "new.example.com", storage.ResolveFailure{Message: "no such host", NameGone: true}))
	f.must(f.st.SaveIPs(f.ctx, "new.example.com", []string{"192.0.2.1"}, time.Hour))
	if got := dnsFeed(t, f); len(got) != 0 {
		t.Errorf("feed = %q, want nothing for a first lookup", got)
	}
}
