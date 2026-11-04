package service_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	sqlite "modernc.org/sqlite"

	"perimeter/ent"
	"perimeter/ent/enttest"
	"perimeter/ent/tag"
	"perimeter/ent/target"
	"perimeter/internal/service"
	"perimeter/internal/storage"
	"perimeter/scanner/csp"
)

// ent opens the "sqlite3" driver name; modernc registers itself as "sqlite".
func init() { sql.Register("sqlite3", &sqlite.Driver{}) }

const testWindow = 30 * 24 * time.Hour

// fixture seeds data through the storage write API, so the summary columns
// and the collapse logic are the ones production uses.
type fixture struct {
	t      *testing.T
	ctx    context.Context
	client *ent.Client
	st     *storage.EntStorage
	svc    *service.Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	t.Cleanup(func() { client.Close() })
	st := storage.NewEntStorage(client)
	return &fixture{
		t:      t,
		ctx:    context.Background(),
		client: client,
		st:     st,
		svc:    service.New(st, client, testWindow),
	}
}

func (f *fixture) must(err error) {
	f.t.Helper()
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) target(input string) {
	f.t.Helper()
	_, err := f.st.ImportTargets(f.ctx, []string{input})
	f.must(err)
}

func (f *fixture) id(input string) int {
	f.t.Helper()
	id, err := f.client.Target.Query().Where(target.Input(input)).OnlyID(f.ctx)
	f.must(err)
	return id
}

func (f *fixture) ip(input, addr string) {
	f.t.Helper()
	f.must(f.st.SaveIPs(f.ctx, input, []string{addr}, time.Hour))
}

func (f *fixture) ports(addr string, ports ...int) {
	f.t.Helper()
	f.must(f.st.SavePortScan(f.ctx, addr, ports))
}

func (f *fixture) ssl(input, grade string, expiry time.Time) {
	f.t.Helper()
	f.must(f.st.SaveSSLScan(f.ctx, input, storage.SSLResult{
		Grade:      grade,
		Status:     "READY",
		CertIssuer: "Test CA",
		CertExpiry: expiry,
	}))
}

func (f *fixture) csp(input string, findings int) {
	f.t.Helper()
	f.must(f.st.SaveCSPScan(f.ctx, input, "default-src 'self'", make([]csp.Finding, findings)))
}

func (f *fixture) tag(input, name string) {
	f.t.Helper()
	tid, err := f.client.Tag.Query().Where(tag.Name(name)).OnlyID(f.ctx)
	if ent.IsNotFound(err) {
		tg, cerr := f.client.Tag.Create().SetName(name).SetColor("#123456").Save(f.ctx)
		f.must(cerr)
		tid = tg.ID
	} else {
		f.must(err)
	}
	f.must(f.client.Target.UpdateOneID(f.id(input)).AddTagIDs(tid).Exec(f.ctx))
}

func (f *fixture) list(q service.TargetQuery) []string {
	f.t.Helper()
	page, err := f.svc.ListTargets(f.ctx, q)
	f.must(err)
	names := []string{}
	for _, s := range page.Items {
		names = append(names, s.Input)
	}
	return names
}

func assertNames(t *testing.T, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestListTargetsFiltersAndSort(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().Add(100 * 24 * time.Hour)
	f.target("example.com")
	f.ip("example.com", "10.0.0.1")
	f.ports("10.0.0.1", 22, 443)
	f.ssl("example.com", "A", exp)
	f.tag("example.com", "prod")
	f.target("mail.example.org")
	f.ip("mail.example.org", "10.0.0.2")
	f.ports("10.0.0.2")
	f.ssl("mail.example.org", "C", exp)
	f.target("other.net")

	tests := []struct {
		name string
		q    service.TargetQuery
		want []string
	}{
		{"no filter sorts by input", service.TargetQuery{}, []string{"example.com", "mail.example.org", "other.net"}},
		{"search is case-insensitive", service.TargetQuery{Search: "EXAMPLE"}, []string{"example.com", "mail.example.org"}},
		{"tag", service.TargetQuery{Tag: "prod"}, []string{"example.com"}},
		{"state ok", service.TargetQuery{States: []string{"ok"}}, []string{"example.com"}},
		{"ssl below B", service.TargetQuery{SSLBelow: "B"}, []string{"mail.example.org"}},
		{"ssl grade A", service.TargetQuery{SSLGrade: "A"}, []string{"example.com"}},
		{"port 443", service.TargetQuery{Port: 443}, []string{"example.com"}},
		{"sort ssl best first", service.TargetQuery{Sort: "ssl"}, []string{"example.com", "mail.example.org", "other.net"}},
		{"sort input descending", service.TargetQuery{Sort: "target", Desc: true}, []string{"other.net", "mail.example.org", "example.com"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertNames(t, f.list(tc.q), tc.want)
		})
	}
}

func TestListTargetsInvalidArguments(t *testing.T) {
	f := newFixture(t)
	f.target("example.com")
	tests := []struct {
		name string
		q    service.TargetQuery
	}{
		{"unknown state", service.TargetQuery{States: []string{"bogus"}}},
		{"unknown grade", service.TargetQuery{SSLGrade: "Z"}},
		{"unknown ssl_below", service.TargetQuery{SSLBelow: "Q"}},
		{"unknown csp", service.TargetQuery{CSP: "maybe"}},
		{"unknown sort", service.TargetQuery{Sort: "nope"}},
		{"port out of range", service.TargetQuery{Port: 70000}},
		{"negative expiry window", service.TargetQuery{ExpiringWithinDays: -1}},
		{"negative offset", service.TargetQuery{Offset: -1}},
		{"deleted with a grade", service.TargetQuery{Deleted: true, SSLGrade: "A"}},
		{"deleted with a sort", service.TargetQuery{Deleted: true, Sort: "ssl"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.svc.ListTargets(f.ctx, tc.q)
			if !service.IsInvalid(err) {
				t.Errorf("err = %v, want an invalid-argument error", err)
			}
		})
	}
	if service.IsInvalid(errors.New("plain")) {
		t.Error("IsInvalid(plain error) = true")
	}
}

func TestListTargetsPaging(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"t1.test", "t2.test", "t3.test", "t4.test", "t5.test"} {
		f.target(name)
	}

	page, err := f.svc.ListTargets(f.ctx, service.TargetQuery{Limit: 2})
	f.must(err)
	if page.Total != 5 || len(page.Items) != 2 || page.NextOffset == nil || *page.NextOffset != 2 {
		t.Fatalf("page 1 = %+v", page)
	}
	page, err = f.svc.ListTargets(f.ctx, service.TargetQuery{Limit: 2, Offset: 2})
	f.must(err)
	if len(page.Items) != 2 || page.Items[0].Input != "t3.test" || page.NextOffset == nil || *page.NextOffset != 4 {
		t.Fatalf("page 2 = %+v", page)
	}
	page, err = f.svc.ListTargets(f.ctx, service.TargetQuery{Limit: 2, Offset: 4})
	f.must(err)
	if len(page.Items) != 1 || page.Items[0].Input != "t5.test" || page.NextOffset != nil {
		t.Fatalf("last page = %+v", page)
	}
	page, err = f.svc.ListTargets(f.ctx, service.TargetQuery{Offset: 9})
	f.must(err)
	if len(page.Items) != 0 || page.Total != 5 || page.NextOffset != nil {
		t.Fatalf("past the end = %+v", page)
	}
	// The default is 50 and the cap is 200; both still return everything here.
	for _, limit := range []int{0, 500} {
		page, err = f.svc.ListTargets(f.ctx, service.TargetQuery{Limit: limit})
		f.must(err)
		if len(page.Items) != 5 {
			t.Errorf("limit %d returned %d items", limit, len(page.Items))
		}
	}
}

func TestListTargetsDeleted(t *testing.T) {
	f := newFixture(t)
	f.target("keep.test")
	f.target("gone.test")
	f.must(f.st.DeleteTarget(f.ctx, f.id("gone.test")))

	assertNames(t, f.list(service.TargetQuery{}), []string{"keep.test"})

	page, err := f.svc.ListTargets(f.ctx, service.TargetQuery{Deleted: true})
	f.must(err)
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].Input != "gone.test" || page.Items[0].DeletedAt == nil {
		t.Fatalf("deleted list = %+v", page)
	}
	page, err = f.svc.ListTargets(f.ctx, service.TargetQuery{Deleted: true, Search: "nope"})
	f.must(err)
	if page.Total != 0 || len(page.Items) != 0 {
		t.Errorf("deleted search matched nothing but got %+v", page)
	}
}

func TestGetTarget(t *testing.T) {
	f := newFixture(t)
	f.target("example.com")
	f.ip("example.com", "10.0.0.1")
	f.ports("10.0.0.1", 22, 443)
	f.ssl("example.com", "A", time.Now().Add(100*24*time.Hour+12*time.Hour))
	f.csp("example.com", 2)
	f.tag("example.com", "prod")
	id := f.id("example.com")

	d, err := f.svc.GetTarget(f.ctx, id)
	f.must(err)
	if d.Input != "example.com" || d.Reachability != "ok" || d.OpenPorts != 2 {
		t.Errorf("summary = %+v", d.TargetSummary)
	}
	if !slices.Equal(d.Tags, []string{"prod"}) {
		t.Errorf("tags = %v", d.Tags)
	}
	if d.CertDaysLeft == nil || *d.CertDaysLeft != 100 {
		t.Errorf("cert_days_left = %v, want 100", d.CertDaysLeft)
	}
	if len(d.IPs) != 1 || d.IPs[0].Address != "10.0.0.1" || !slices.Equal(d.IPs[0].OpenPorts, []int{22, 443}) {
		t.Errorf("ips = %+v", d.IPs)
	}
	if d.SSL == nil || d.SSL.Grade != "A" || d.SSL.Status != "READY" || d.SSL.CertIssuer != "Test CA" {
		t.Errorf("ssl = %+v", d.SSL)
	}
	if d.CSP == nil || len(d.CSP.Findings) != 2 || d.CSP.Header != "default-src 'self'" {
		t.Errorf("csp = %+v", d.CSP)
	}

	if _, err := f.svc.GetTarget(f.ctx, 999999); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("missing target: err = %v, want ErrNotFound", err)
	}
	f.must(f.st.DeleteTarget(f.ctx, id))
	if _, err := f.svc.GetTarget(f.ctx, id); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("soft-deleted target: err = %v, want ErrNotFound", err)
	}
}

func TestTargetJSONShape(t *testing.T) {
	f := newFixture(t)
	f.target("bare.test")
	f.target("tagged.test")
	f.ssl("tagged.test", "B", time.Now().Add(-time.Hour))
	f.tag("tagged.test", "prod")

	page, err := f.svc.ListTargets(f.ctx, service.TargetQuery{})
	f.must(err)
	raw, err := json.Marshal(page)
	f.must(err)
	s := string(raw)
	for _, want := range []string{`"items":`, `"total":2`, `"tags":[]`, `"tags":["prod"]`, `"is_ip":false`, `"ssl_grade":"B"`, `"open_ports":0`, `"cert_days_left":0`} {
		if !strings.Contains(s, want) {
			t.Errorf("json %s lacks %s", s, want)
		}
	}
	for _, unwanted := range []string{"deleted_at", "next_offset", "csp_findings"} {
		if strings.Contains(s, unwanted) {
			t.Errorf("json %s should omit %s", s, unwanted)
		}
	}
}

func TestTargetHistory(t *testing.T) {
	f := newFixture(t)
	f.target("h.test")
	f.ip("h.test", "10.0.0.9")
	// Written oldest first; the history is read newest first.
	f.ssl("h.test", "A", time.Now().Add(10*24*time.Hour))
	f.ssl("h.test", "C", time.Now().Add(10*24*time.Hour))
	f.ssl("h.test", "B", time.Now().Add(10*24*time.Hour))
	f.csp("h.test", 1)
	f.ports("10.0.0.9", 443)
	f.ports("10.0.0.9", 22, 443)
	f.must(f.st.SavePortScanError(f.ctx, "10.0.0.9", "no answer"))
	id := f.id("h.test")

	wantSummaries := []string{
		"unreachable", "ports 22,443", "ports 443",
		"CSP 1 finding",
		"grade C → B", "grade A → C", "grade A",
	}
	page, err := f.svc.TargetHistory(f.ctx, id, 3, 0)
	f.must(err)
	if page.Total != 7 || page.NextOffset == nil || *page.NextOffset != 3 {
		t.Fatalf("page 1 = %+v", page)
	}
	if got := summaries(page.Items); !slices.Equal(got, wantSummaries[:3]) {
		t.Errorf("page 1 summaries = %v, want %v", got, wantSummaries[:3])
	}
	if page.Items[0].Kind != "ports" || page.Items[0].IP != "10.0.0.9" || page.Items[0].Error != "no answer" {
		t.Errorf("error row = %+v", page.Items[0])
	}
	if page.Items[1].Kind != "ports" || !slices.Equal(page.Items[1].Ports, []int{22, 443}) {
		t.Errorf("ports row = %+v", page.Items[1])
	}

	page, err = f.svc.TargetHistory(f.ctx, id, 3, 3)
	f.must(err)
	if got := summaries(page.Items); !slices.Equal(got, wantSummaries[3:6]) {
		t.Errorf("page 2 summaries = %v, want %v", got, wantSummaries[3:6])
	}
	if page.Items[0].Kind != "csp" || page.Items[0].FindingsCount == nil || *page.Items[0].FindingsCount != 1 {
		t.Errorf("csp row = %+v", page.Items[0])
	}
	if page.NextOffset == nil || *page.NextOffset != 6 {
		t.Errorf("page 2 next = %v", page.NextOffset)
	}

	page, err = f.svc.TargetHistory(f.ctx, id, 3, 6)
	f.must(err)
	if got := summaries(page.Items); !slices.Equal(got, wantSummaries[6:]) || page.NextOffset != nil {
		t.Errorf("last page = %v next %v", got, page.NextOffset)
	}

	page, err = f.svc.TargetHistory(f.ctx, id, 3, 7)
	f.must(err)
	if len(page.Items) != 0 || page.Total != 7 || page.NextOffset != nil {
		t.Errorf("past the end = %+v", page)
	}

	if _, err := f.svc.TargetHistory(f.ctx, 999999, 10, 0); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("missing target: err = %v", err)
	}
}

func summaries(entries []service.HistoryEntry) []string {
	out := []string{}
	for _, e := range entries {
		out = append(out, e.Summary)
	}
	return out
}

func TestSummary(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	day := func(d int) time.Time { return now.Add(time.Duration(d) * 24 * time.Hour) }

	f.target("a.test")
	f.ip("a.test", "10.0.0.1")
	f.ports("10.0.0.1", 22, 443)
	f.ssl("a.test", "A", day(10))
	f.csp("a.test", 2)

	f.target("b.test")
	f.ip("b.test", "10.0.0.2")
	f.ports("10.0.0.2", 80)
	f.ssl("b.test", "C", day(400))

	f.target("c.test")
	f.ssl("c.test", "", day(-5))

	f.target("d.test")

	f.target("e.test")
	f.ssl("e.test", "B", day(5))

	f.target("x.test")
	f.ssl("x.test", "F", day(1))
	f.must(f.st.DeleteTarget(f.ctx, f.id("x.test")))

	s, err := f.svc.Summary(f.ctx, now)
	f.must(err)
	tot := s.Totals
	if tot.Targets != 5 {
		t.Errorf("targets = %d, want 5 (the deleted one is not counted)", tot.Targets)
	}
	if tot.ByReachability["ok"] != 2 || tot.ByReachability["pending"] != 3 || tot.ByReachability["unreachable"] != 0 {
		t.Errorf("by_reachability = %v", tot.ByReachability)
	}
	if tot.OpenPorts != 3 {
		t.Errorf("open_ports = %d, want 3", tot.OpenPorts)
	}
	if tot.CSPIssues != 1 {
		t.Errorf("csp_issues = %d, want 1", tot.CSPIssues)
	}
	if tot.ExpiringCerts != 2 {
		t.Errorf("expiring_certs = %d, want 2 (a and e)", tot.ExpiringCerts)
	}
	if tot.ExpiredCerts != 1 {
		t.Errorf("expired_certs = %d, want 1 (c)", tot.ExpiredCerts)
	}
	if tot.WeakSSL != 1 {
		t.Errorf("weak_ssl = %d, want 1 (b, grade C)", tot.WeakSSL)
	}

	var names []string
	for _, e := range s.Expiring {
		names = append(names, e.Input)
	}
	assertNames(t, names, []string{"e.test", "a.test"})

	var kinds []string
	for _, c := range s.RecentChanges {
		if c.Target == "x.test" && c.Kind == service.ChangeTargetDeleted {
			kinds = append(kinds, c.Kind)
		}
	}
	if len(kinds) != 1 {
		t.Errorf("recent changes lack the deletion of x.test: %+v", s.RecentChanges)
	}
}

func TestSummaryCountsUnscannedSSL(t *testing.T) {
	f := newFixture(t)
	f.target("scanned.test")
	f.ssl("scanned.test", "A", time.Now().Add(10*24*time.Hour))
	f.target("bare.test")
	f.target("gone.test")
	f.must(f.st.DeleteTarget(f.ctx, f.id("gone.test")))

	s, err := f.svc.Summary(f.ctx, time.Now())
	f.must(err)
	if s.Totals.SSLUnscanned != 1 {
		t.Errorf("ssl_unscanned = %d, want 1 (bare.test, not the deleted one)", s.Totals.SSLUnscanned)
	}
}

func TestSummaryRecentChangesAreNewestFirstAndCapped(t *testing.T) {
	f := newFixture(t)
	for i := range 25 {
		f.target(strings.Repeat("a", i+1) + ".test")
	}
	s, err := f.svc.Summary(f.ctx, time.Now())
	f.must(err)
	if len(s.RecentChanges) != 20 {
		t.Fatalf("recent changes = %d, want 20", len(s.RecentChanges))
	}
	for i := 1; i < len(s.RecentChanges); i++ {
		if s.RecentChanges[i].At.After(s.RecentChanges[i-1].At) {
			t.Fatalf("recent changes not newest first at %d", i)
		}
	}
}

func TestListTags(t *testing.T) {
	f := newFixture(t)
	f.target("a.test")
	f.target("b.test")
	f.tag("a.test", "prod")
	f.tag("b.test", "prod")
	f.tag("b.test", "lab")
	f.must(f.st.DeleteTarget(f.ctx, f.id("b.test")))

	tags, err := f.svc.ListTags(f.ctx)
	f.must(err)
	if len(tags) != 2 || tags[0].Name != "lab" || tags[1].Name != "prod" {
		t.Fatalf("tags = %+v, want lab then prod", tags)
	}
	if tags[0].TargetCount != 0 || tags[1].TargetCount != 1 {
		t.Errorf("target counts = %d, %d; deleted targets must not count", tags[0].TargetCount, tags[1].TargetCount)
	}
}
