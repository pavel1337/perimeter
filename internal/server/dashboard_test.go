package server

import (
	"context"
	"database/sql"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	sqlite "modernc.org/sqlite"

	"perimeter/ent"
	"perimeter/ent/enttest"
	"perimeter/ent/target"
	"perimeter/internal/auth"
	"perimeter/internal/storage"
)

// ent opens the "sqlite3" driver name; modernc registers itself as "sqlite".
func init() { sql.Register("sqlite3", &sqlite.Driver{}) }

func newTestClient(t *testing.T) *ent.Client {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	t.Cleanup(func() { client.Close() })
	return client
}

// fakeStore embeds storage.Storage so only the methods the dashboard calls
// need implementing; any other call panics on the nil interface.
type fakeStore struct {
	storage.Storage

	targets []*ent.Target
	stats   storage.TargetStats

	statsFilter storage.TargetFilter
	statsCalls  int

	listFilter storage.TargetFilter
	listSort   storage.TargetSort
	limit      int
	offset     int
	listCalls  int

	deleted int
}

func (f *fakeStore) CountDeletedTargets(_ context.Context) (int, error) {
	return f.deleted, nil
}

func (f *fakeStore) TargetStats(_ context.Context, filter storage.TargetFilter, _ time.Time, _ time.Duration) (storage.TargetStats, error) {
	f.statsCalls++
	f.statsFilter = filter
	return f.stats, nil
}

func (f *fakeStore) ListTargets(_ context.Context, filter storage.TargetFilter, sort storage.TargetSort, limit, offset int) ([]*ent.Target, error) {
	f.listCalls++
	f.listFilter = filter
	f.listSort = sort
	f.limit = limit
	f.offset = offset
	return f.targets, nil
}

func qv(kv ...string) url.Values {
	v := url.Values{}
	for i := 0; i < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

func TestParseDashboardQuery(t *testing.T) {
	defaultSort := storage.TargetSort{Field: storage.SortTarget}

	tests := []struct {
		name       string
		q          url.Values
		wantFilter storage.TargetFilter
		wantSort   storage.TargetSort
	}{
		{name: "no params", q: url.Values{}, wantSort: defaultSort},
		{name: "empty values count as absent", q: qv("state", "", "csp", "", "sort", "", "dir", ""), wantSort: defaultSort},
		{name: "state", q: qv("state", "ok"), wantFilter: storage.TargetFilter{States: []target.Reachability{target.ReachabilityOk}}, wantSort: defaultSort},
		{name: "state pending", q: qv("state", "pending"), wantFilter: storage.TargetFilter{States: []target.Reachability{target.ReachabilityPending}}, wantSort: defaultSort},
		{name: "tag", q: qv("tag", "prod"), wantFilter: storage.TargetFilter{Tag: "prod"}, wantSort: defaultSort},
		{name: "csp issues", q: qv("csp", "issues"), wantFilter: storage.TargetFilter{CSP: "issues"}, wantSort: defaultSort},
		{name: "csp ok", q: qv("csp", "ok"), wantFilter: storage.TargetFilter{CSP: "ok"}, wantSort: defaultSort},
		{name: "csp none", q: qv("csp", "none"), wantFilter: storage.TargetFilter{CSP: "none"}, wantSort: defaultSort},
		{name: "ssl exact", q: qv("ssl", "A+"), wantFilter: storage.TargetFilter{SSLGrade: "A+"}, wantSort: defaultSort},
		{name: "ssl_below", q: qv("ssl_below", "B"), wantFilter: storage.TargetFilter{SSLBelow: "B"}, wantSort: defaultSort},
		{name: "port low bound", q: qv("port", "1"), wantFilter: storage.TargetFilter{Port: 1}, wantSort: defaultSort},
		{name: "port high bound", q: qv("port", "65535"), wantFilter: storage.TargetFilter{Port: 65535}, wantSort: defaultSort},
		{name: "expiring days to duration", q: qv("expiring", "7"), wantFilter: storage.TargetFilter{ExpiringWithin: 7 * 24 * time.Hour}, wantSort: defaultSort},
		{name: "sort field asc by default", q: qv("sort", "ports"), wantSort: storage.TargetSort{Field: storage.SortPorts}},
		{name: "sort desc", q: qv("sort", "expiry", "dir", "desc"), wantSort: storage.TargetSort{Field: storage.SortExpiry, Desc: true}},
		{name: "dir asc explicit", q: qv("sort", "csp", "dir", "asc"), wantSort: storage.TargetSort{Field: storage.SortCSP}},
		{name: "all params together", q: qv("state", "unreachable", "tag", "x", "csp", "issues", "ssl", "A", "ssl_below", "C",
			"port", "443", "expiring", "30", "sort", "ssl", "dir", "desc"),
			wantFilter: storage.TargetFilter{
				States: []target.Reachability{target.ReachabilityUnreachable}, Tag: "x", CSP: "issues",
				SSLGrade: "A", SSLBelow: "C", Port: 443, ExpiringWithin: 30 * 24 * time.Hour,
			},
			wantSort: storage.TargetSort{Field: storage.SortSSL, Desc: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, s, err := parseDashboardQuery(tt.q)
			if err != nil {
				t.Fatalf("parseDashboardQuery(%v): unexpected error %v", tt.q, err)
			}
			if !reflect.DeepEqual(f, tt.wantFilter) {
				t.Errorf("filter = %+v, want %+v", f, tt.wantFilter)
			}
			if s != tt.wantSort {
				t.Errorf("sort = %+v, want %+v", s, tt.wantSort)
			}
		})
	}

	invalid := []struct {
		name string
		q    url.Values
	}{
		{"unknown state", qv("state", "bogus")},
		{"state is case sensitive", qv("state", "OK")},
		{"unknown csp", qv("csp", "maybe")},
		{"unknown ssl grade", qv("ssl", "Z")},
		{"ssl dash not a grade", qv("ssl", "-")},
		{"unknown ssl_below grade", qv("ssl_below", "Q")},
		{"port zero", qv("port", "0")},
		{"port above range", qv("port", "65536")},
		{"port negative", qv("port", "-1")},
		{"port not a number", qv("port", "http")},
		{"port fractional", qv("port", "80.5")},
		{"expiring zero", qv("expiring", "0")},
		{"expiring negative", qv("expiring", "-3")},
		{"expiring not a number", qv("expiring", "soon")},
		{"expiring too large to convert", qv("expiring", "100001")},
		{"unknown sort field", qv("sort", "name")},
		{"sort field case sensitive", qv("sort", "CSP")},
		{"unknown dir", qv("dir", "sideways")},
		{"dir case sensitive", qv("dir", "DESC")},
	}
	for _, tt := range invalid {
		t.Run("invalid/"+tt.name, func(t *testing.T) {
			if _, _, err := parseDashboardQuery(tt.q); err == nil {
				t.Errorf("parseDashboardQuery(%v): want error", tt.q)
			}
		})
	}
}

func TestWithQuery(t *testing.T) {
	tests := []struct {
		name string
		q    url.Values
		kv   []string
		want string
	}{
		{name: "empty query and no pairs", q: url.Values{}, want: "/"},
		{name: "set on empty query", q: url.Values{}, kv: []string{"state", "ok"}, want: "/?state=ok"},
		{name: "keeps other params", q: qv("tag", "prod"), kv: []string{"state", "ok"}, want: "/?state=ok&tag=prod"},
		{name: "overwrites existing key", q: qv("state", "ok", "tag", "prod"), kv: []string{"state", "pending"}, want: "/?state=pending&tag=prod"},
		{name: "empty value deletes key", q: qv("state", "ok", "tag", "prod"), kv: []string{"state", ""}, want: "/?tag=prod"},
		{name: "empty value on only key gives bare path", q: qv("state", "ok"), kv: []string{"state", ""}, want: "/"},
		{name: "page dropped when not set", q: qv("page", "3", "tag", "prod"), kv: []string{"sort", "csp"}, want: "/?sort=csp&tag=prod"},
		{name: "page kept when set", q: qv("page", "3", "tag", "prod"), kv: []string{"page", "4"}, want: "/?page=4&tag=prod"},
		{name: "page can be set alongside others", q: qv("page", "3"), kv: []string{"page", "2", "dir", "desc"}, want: "/?dir=desc&page=2"},
		{name: "values are escaped", q: url.Values{}, kv: []string{"tag", "a b&c"}, want: "/?tag=a+b%26c"},
		{name: "multiple pairs in one call", q: url.Values{}, kv: []string{"sort", "ssl", "dir", "asc"}, want: "/?dir=asc&sort=ssl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := url.Values{}
			for k, v := range tt.q {
				before[k] = append([]string(nil), v...)
			}
			got, err := withQuery(tt.q, tt.kv...)
			if err != nil {
				t.Fatalf("withQuery: %v", err)
			}
			if got != tt.want {
				t.Errorf("withQuery() = %q, want %q", got, tt.want)
			}
			if !reflect.DeepEqual(before, tt.q) {
				t.Errorf("withQuery mutated its query: %v -> %v", before, tt.q)
			}
		})
	}

	if _, err := withQuery(url.Values{}, "state"); err == nil {
		t.Error("withQuery with an odd number of arguments: want error")
	}
}

func TestSortHeaders(t *testing.T) {
	q := qv("tag", "prod", "page", "4")
	headers, err := sortHeaders(q, storage.TargetSort{Field: storage.SortCSP, Desc: true})
	if err != nil {
		t.Fatal(err)
	}
	// Active column: clicking toggles to asc and shows the desc arrow.
	if got := headers[storage.SortCSP]; got.URL != "/?dir=asc&sort=csp&tag=prod" || got.Arrow != " ▼" {
		t.Errorf("active csp header = %+v", got)
	}
	// Inactive column: sorts asc, no arrow, page reset.
	if got := headers[storage.SortPorts]; got.URL != "/?dir=asc&sort=ports&tag=prod" || got.Arrow != "" {
		t.Errorf("inactive ports header = %+v", got)
	}

	headers, err = sortHeaders(qv("sort", "ssl"), storage.TargetSort{Field: storage.SortSSL})
	if err != nil {
		t.Fatal(err)
	}
	if got := headers[storage.SortSSL]; got.URL != "/?dir=desc&sort=ssl" || got.Arrow != " ▲" {
		t.Errorf("active ssl header = %+v", got)
	}
}

// dashboardGet runs handleIndex against fake for the given query string.
func dashboardGet(t *testing.T, fake *fakeStore, pageSize int, rawQuery string) (int, string) {
	t.Helper()
	srv := New(fake, &auth.Auth{}, newTestClient(t), nil, nil, os.DirFS("../.."), 30*24*time.Hour, pageSize)
	app := fiber.New(fiber.Config{Views: srv.app.Config().Views})
	app.Get("/", srv.handleIndex)

	resp, err := app.Test(httptest.NewRequest("GET", "/?"+rawQuery, nil))
	if err != nil {
		t.Fatalf("GET /?%s: %v", rawQuery, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body)
}

func TestHandleIndexPassesFilterSortAndPaging(t *testing.T) {
	fake := &fakeStore{
		targets: []*ent.Target{{ID: 1, Input: "a.example"}, {ID: 2, Input: "b.example"}},
		// 120 matching targets at a page size of 50: three pages.
		stats: storage.TargetStats{Total: 120, OpenPorts: 7, ExpiringCerts: 2, CSPIssues: 5},
	}
	_, body := dashboardGet(t, fake, 50,
		"state=ok&tag=prod&csp=issues&ssl=A&ssl_below=B&port=443&expiring=7&sort=ports&dir=desc&page=3")

	wantFilter := storage.TargetFilter{
		States: []target.Reachability{target.ReachabilityOk}, Tag: "prod", CSP: "issues",
		SSLGrade: "A", SSLBelow: "B", Port: 443, ExpiringWithin: 7 * 24 * time.Hour,
	}
	wantSort := storage.TargetSort{Field: storage.SortPorts, Desc: true}
	if !reflect.DeepEqual(fake.listFilter, wantFilter) || fake.listSort != wantSort {
		t.Errorf("ListTargets got filter %+v sort %+v, want %+v %+v", fake.listFilter, fake.listSort, wantFilter, wantSort)
	}
	if !reflect.DeepEqual(fake.statsFilter, wantFilter) {
		t.Errorf("TargetStats got filter %+v, want %+v", fake.statsFilter, wantFilter)
	}
	if fake.limit != 50 || fake.offset != 100 {
		t.Errorf("ListTargets limit=%d offset=%d, want limit=50 offset=100", fake.limit, fake.offset)
	}
	if fake.statsCalls != 1 || fake.listCalls != 1 {
		t.Errorf("stats calls=%d list calls=%d, want 1 and 1", fake.statsCalls, fake.listCalls)
	}

	// Stat cards come from TargetStats (120 targets), not from the two rows.
	if !strings.Contains(body, `font-weight: 600;">120</div>`) {
		t.Errorf("targets card does not show the stats total of 120")
	}
	// The Target header keeps every other param and resets the page. Links
	// are HTML-escaped in the body, so match the escaped form.
	if !strings.Contains(body, "/?csp=issues&amp;dir=asc&amp;expiring=7&amp;port=443&amp;sort=target&amp;ssl=A&amp;ssl_below=B&amp;state=ok&amp;tag=prod") {
		t.Errorf("Target sort header does not keep the current filters; body:\n%s", body)
	}
	if !strings.Contains(body, `name="ssl_below"`) || !strings.Contains(body, `value="443"`) {
		t.Errorf("filter form not rendered with current values")
	}
}

func TestHandleIndexPageClampAndOffset(t *testing.T) {
	tests := []struct {
		name       string
		rawQuery   string
		total      int
		pageSize   int
		wantOffset int
		wantLimit  int
	}{
		{name: "first page", rawQuery: "", total: 120, pageSize: 50, wantOffset: 0, wantLimit: 50},
		{name: "second page", rawQuery: "page=2", total: 120, pageSize: 50, wantOffset: 50, wantLimit: 50},
		{name: "page past the end clamps to last", rawQuery: "page=99", total: 120, pageSize: 50, wantOffset: 100, wantLimit: 50},
		{name: "no matches stays on page one", rawQuery: "page=5", total: 0, pageSize: 50, wantOffset: 0, wantLimit: 50},
		{name: "garbage page is page one", rawQuery: "page=abc", total: 120, pageSize: 50, wantOffset: 0, wantLimit: 50},
		{name: "configured page size", rawQuery: "page=2", total: 25, pageSize: 10, wantOffset: 10, wantLimit: 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeStore{stats: storage.TargetStats{Total: tt.total}}
			status, _ := dashboardGet(t, fake, tt.pageSize, tt.rawQuery)
			if status != 200 {
				t.Fatalf("status %d, want 200", status)
			}
			if fake.offset != tt.wantOffset || fake.limit != tt.wantLimit {
				t.Errorf("limit=%d offset=%d, want limit=%d offset=%d", fake.limit, fake.offset, tt.wantLimit, tt.wantOffset)
			}
		})
	}
}

func TestHandleIndexDefaults(t *testing.T) {
	fake := &fakeStore{}
	dashboardGet(t, fake, 50, "")
	if !reflect.DeepEqual(fake.listFilter, storage.TargetFilter{}) {
		t.Errorf("default filter = %+v, want zero", fake.listFilter)
	}
	if fake.listSort != (storage.TargetSort{Field: storage.SortTarget}) {
		t.Errorf("default sort = %+v, want target asc", fake.listSort)
	}
}

func TestHandleIndexInvalidParamsAre400(t *testing.T) {
	for _, raw := range []string{
		"state=bogus", "csp=maybe", "ssl=Z", "ssl_below=Q", "port=0", "port=70000",
		"port=abc", "expiring=0", "expiring=-1", "sort=name", "dir=up",
	} {
		t.Run(raw, func(t *testing.T) {
			fake := &fakeStore{}
			status, _ := dashboardGet(t, fake, 50, raw)
			if status != 400 {
				t.Errorf("status %d, want 400", status)
			}
			if fake.statsCalls != 0 || fake.listCalls != 0 {
				t.Errorf("storage called for an invalid request: stats=%d list=%d", fake.statsCalls, fake.listCalls)
			}
		})
	}
}

func TestNewDefaultsPageSize(t *testing.T) {
	srv := New(&fakeStore{}, &auth.Auth{}, nil, nil, nil, os.DirFS("../.."), time.Hour, 0)
	if srv.dashboardPageSize != defaultDashboardPageSize {
		t.Errorf("dashboardPageSize = %d, want %d", srv.dashboardPageSize, defaultDashboardPageSize)
	}
}
