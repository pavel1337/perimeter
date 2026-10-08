package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"perimeter/ent"
	"perimeter/ent/target"
	"perimeter/internal/auth"
)

// response is what the tests read from a reply. The body is read and closed
// inside send.
type response struct {
	StatusCode int
	Header     http.Header
	Body       string
}

// send runs one request through the real router with the admin session.
// contentType and body are optional; a non-empty body is sent as given.
func send(t *testing.T, srv *Server, token, method, path, contentType, body string) response {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: token})
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return response{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(b)}
}

// postForm sends a urlencoded form POST, the way a browser submits the
// dashboard's bulk toolbar.
func postForm(t *testing.T, srv *Server, token, path string, form url.Values) response {
	t.Helper()
	return send(t, srv, token, "POST", path, "application/x-www-form-urlencoded", form.Encode())
}

// idsForm returns a form with the ids values set, in order.
func idsForm(ids ...int) url.Values {
	form := url.Values{}
	for _, id := range ids {
		form.Add("ids", strconv.Itoa(id))
	}
	return form
}

// setReachability moves a target into the given reachability state.
func setReachability(t *testing.T, client *ent.Client, id int, state string) {
	t.Helper()
	if _, err := client.Target.UpdateOneID(id).SetReachability(target.Reachability(state)).Save(context.Background()); err != nil {
		t.Fatalf("set reachability: %v", err)
	}
}

// bulkExportJSON posts a bulk export and decodes the JSON array it returns.
func bulkExportJSON(t *testing.T, srv *Server, token string, form url.Values) []exportData {
	t.Helper()
	form.Set("format", "json")
	resp := postForm(t, srv, token, "/targets/bulk/export", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bulk export json: status %d, body:\n%s", resp.StatusCode, resp.Body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q, want application/json", ct)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Disposition"), "attachment; filename=perimeter-targets-") ||
		!strings.HasSuffix(resp.Header.Get("Content-Disposition"), ".json") {
		t.Errorf("Content-Disposition %q", resp.Header.Get("Content-Disposition"))
	}
	var items []exportData
	if err := json.Unmarshal([]byte(resp.Body), &items); err != nil {
		t.Fatalf("bulk export is not a JSON array: %v\n%s", err, resp.Body)
	}
	return items
}

// inputs returns the target inputs of exported items, sorted.
func inputs(items []exportData) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Target)
	}
	slices.Sort(out)
	return out
}

func TestBulkExportJSONSelectedIDs(t *testing.T) {
	srv, client, token := authedServer(t)
	exportFixture(t, client, "a.example.com")
	ids := importTargets(t, client, "b.example.com", "c.example.com")

	items := bulkExportJSON(t, srv, token, idsForm(ids["b.example.com"], ids["c.example.com"]))
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2", len(items))
	}
	want := []string{"b.example.com", "c.example.com"}
	if got := inputs(items); !slices.Equal(got, want) {
		t.Errorf("targets %v, want %v", got, want)
	}
}

func TestBulkExportJSONEmptyTargetHasNoScans(t *testing.T) {
	srv, client, token := authedServer(t)
	aID := exportFixture(t, client, "a.example.com")
	ids := importTargets(t, client, "b.example.com")

	items := bulkExportJSON(t, srv, token, idsForm(aID, ids["b.example.com"]))
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2", len(items))
	}
	for _, it := range items {
		if it.Target == "b.example.com" && (len(it.IPs) != 0 || len(it.SSL) != 0 || len(it.CSP) != 0) {
			t.Errorf("target without history exported scans: %+v", it)
		}
	}
}

func TestBulkExportCSV(t *testing.T) {
	srv, client, token := authedServer(t)
	aID := exportFixture(t, client, "a.example.com")
	ids := importTargets(t, client, "b.example.com")

	form := idsForm(aID, ids["b.example.com"])
	form.Set("format", "csv")
	resp := postForm(t, srv, token, "/targets/bulk/export", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bulk export csv: status %d, body:\n%s", resp.StatusCode, resp.Body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/csv" {
		t.Errorf("Content-Type %q, want text/csv", ct)
	}
	if !strings.HasSuffix(resp.Header.Get("Content-Disposition"), ".csv") {
		t.Errorf("Content-Disposition %q", resp.Header.Get("Content-Disposition"))
	}

	lines := strings.Split(strings.TrimSpace(resp.Body), "\n")
	if lines[0] != "target,type,timestamp,detail,value" {
		t.Fatalf("header %q", lines[0])
	}
	rows := lines[1:]
	if len(rows) != 5 {
		t.Fatalf("got %d data rows, want 5 (the fixture's rows):\n%s", len(rows), resp.Body)
	}
	for _, row := range rows {
		if !strings.HasPrefix(row, "a.example.com,") {
			t.Errorf("row %q does not start with its target input", row)
		}
	}
}

func TestBulkExportAllMatchesFilter(t *testing.T) {
	srv, client, token := authedServer(t)
	ids := importTargets(t, client, "a.example.com", "b.example.com", "c.example.com")
	setReachability(t, client, ids["a.example.com"], "unreachable")
	setReachability(t, client, ids["b.example.com"], "unreachable")
	setReachability(t, client, ids["c.example.com"], "ok")
	if _, err := client.Tag.Create().SetName("prod").AddTargetIDs(ids["c.example.com"]).Save(context.Background()); err != nil {
		t.Fatalf("create tag: %v", err)
	}

	form := url.Values{"all": {"1"}, "state": {"unreachable"}}
	items := bulkExportJSON(t, srv, token, form)
	if want := []string{"a.example.com", "b.example.com"}; !slices.Equal(inputs(items), want) {
		t.Errorf("state=unreachable exported %v, want %v", inputs(items), want)
	}

	form = url.Values{"all": {"1"}, "tag": {"prod"}}
	items = bulkExportJSON(t, srv, token, form)
	if want := []string{"c.example.com"}; !slices.Equal(inputs(items), want) {
		t.Errorf("tag=prod exported %v, want %v", inputs(items), want)
	}

	// An ids value next to all=1 is ignored: the filter decides.
	form = url.Values{"all": {"1"}, "state": {"unreachable"}, "ids": {strconv.Itoa(ids["c.example.com"])}}
	items = bulkExportJSON(t, srv, token, form)
	if want := []string{"a.example.com", "b.example.com"}; !slices.Equal(inputs(items), want) {
		t.Errorf("all=1 with ids exported %v, want %v", inputs(items), want)
	}
}

func TestBulkRequestsWithBadSelectionAre400(t *testing.T) {
	srv, client, token := authedServer(t)
	ids := importTargets(t, client, "a.example.com")
	setReachability(t, client, ids["a.example.com"], "ok")

	cases := []struct {
		name string
		path string
		form url.Values
		want string
	}{
		{"no ids", "/targets/bulk/export", url.Values{"format": {"json"}}, "No targets selected"},
		{"no ids delete", "/targets/bulk/delete", url.Values{}, "No targets selected"},
		{"bad id", "/targets/bulk/export", url.Values{"ids": {"abc"}}, "Invalid target ID"},
		{"zero id", "/targets/bulk/export", url.Values{"ids": {"0"}}, "Invalid target ID"},
		{"bad id among good", "/targets/bulk/delete", url.Values{"ids": {strconv.Itoa(ids["a.example.com"]), "x"}}, "Invalid target ID"},
		{"invalid state with all", "/targets/bulk/export", url.Values{"all": {"1"}, "state": {"bogus"}}, "invalid state"},
		{"invalid sort with all", "/targets/bulk/delete", url.Values{"all": {"1"}, "sort": {"nope"}}, "invalid sort"},
		{"all matches nothing", "/targets/bulk/export", url.Values{"all": {"1"}, "state": {"unresolved"}}, "No targets selected"},
		{"format xml", "/targets/bulk/export", url.Values{"format": {"xml"}, "ids": {strconv.Itoa(ids["a.example.com"])}}, "Invalid format"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := postForm(t, srv, token, tc.path, tc.form)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status %d, want 400; body:\n%s", resp.StatusCode, resp.Body)
			}
			if !strings.Contains(resp.Body, tc.want) {
				t.Errorf("body %q, want it to contain %q", resp.Body, tc.want)
			}
		})
	}

	// Nothing was deleted by the rejected requests.
	if n, err := client.Target.Query().Count(context.Background()); err != nil || n != 1 {
		t.Errorf("target count %d (err %v) after rejected requests, want 1", n, err)
	}
}

func TestBulkDeleteWithoutConfirmRendersConfirmation(t *testing.T) {
	srv, client, token := authedServer(t)
	ids := importTargets(t, client, "a.example.com", "b.example.com", "c.example.com")
	a, b := ids["a.example.com"], ids["b.example.com"]

	resp := postForm(t, srv, token, "/targets/bulk/delete", idsForm(a, b))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, body:\n%s", resp.StatusCode, resp.Body)
	}
	if strings.Contains(resp.Body, "template: views/") {
		t.Fatalf("template error in output:\n%s", resp.Body)
	}
	if !strings.Contains(resp.Body, "Delete 2 targets?") {
		t.Errorf("confirmation heading with count missing")
	}
	for _, id := range []int{a, b} {
		if !strings.Contains(resp.Body, `name="ids" value="`+strconv.Itoa(id)+`"`) {
			t.Errorf("hidden ids input for %d missing", id)
		}
	}
	if !strings.Contains(resp.Body, `name="confirm" value="1"`) {
		t.Errorf("confirm input missing")
	}
	if !strings.Contains(resp.Body, `action="/targets/bulk/delete"`) || !strings.Contains(resp.Body, "btn-danger") {
		t.Errorf("confirm form or danger button missing")
	}
	if !strings.Contains(resp.Body, `href="/"`) {
		t.Errorf("cancel link missing")
	}
	if !strings.Contains(resp.Body, "a.example.com") || !strings.Contains(resp.Body, "b.example.com") {
		t.Errorf("confirmation does not name the targets")
	}

	if n, err := client.Target.Query().Count(context.Background()); err != nil || n != 3 {
		t.Errorf("target count %d (err %v) after unconfirmed delete, want 3", n, err)
	}
}

func TestBulkDeleteConfirmedDeletes(t *testing.T) {
	srv, client, token := authedServer(t)
	ids := importTargets(t, client, "a.example.com", "b.example.com", "c.example.com")

	form := idsForm(ids["a.example.com"], ids["b.example.com"])
	form.Set("confirm", "1")
	resp := postForm(t, srv, token, "/targets/bulk/delete", form)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("status %d location %q, want 302 to /", resp.StatusCode, resp.Header.Get("Location"))
	}

	dash := send(t, srv, token, "GET", "/", "", "")
	if strings.Contains(dash.Body, "a.example.com</strong>") || strings.Contains(dash.Body, "b.example.com</strong>") {
		t.Errorf("deleted targets still on the dashboard")
	}
	if !strings.Contains(dash.Body, "c.example.com</strong>") {
		t.Errorf("unselected target missing from the dashboard")
	}
	if !strings.Contains(dash.Body, "Deleted targets (2)") {
		t.Errorf("dashboard missing the Deleted targets (2) link")
	}
	deleted := send(t, srv, token, "GET", "/targets/deleted", "", "")
	if !strings.Contains(deleted.Body, "a.example.com") || !strings.Contains(deleted.Body, "b.example.com") {
		t.Errorf("deleted targets not listed on /targets/deleted")
	}
}

func TestBulkDeleteAllConfirmationListsResolvedIDs(t *testing.T) {
	srv, client, token := authedServer(t)
	ids := importTargets(t, client, "a.example.com", "b.example.com", "c.example.com")
	setReachability(t, client, ids["a.example.com"], "unreachable")
	setReachability(t, client, ids["b.example.com"], "unreachable")
	setReachability(t, client, ids["c.example.com"], "ok")

	resp := postForm(t, srv, token, "/targets/bulk/delete", url.Values{"all": {"1"}, "state": {"unreachable"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, body:\n%s", resp.StatusCode, resp.Body)
	}
	if !strings.Contains(resp.Body, "Delete 2 targets?") {
		t.Errorf("confirmation count wrong")
	}
	if strings.Contains(resp.Body, `name="all"`) {
		t.Errorf("confirmation form carries all, so it would not delete what the user saw")
	}
	for _, in := range []string{"a.example.com", "b.example.com"} {
		if !strings.Contains(resp.Body, `name="ids" value="`+strconv.Itoa(ids[in])+`"`) {
			t.Errorf("resolved id for %s missing from confirmation", in)
		}
	}
	if strings.Contains(resp.Body, `name="ids" value="`+strconv.Itoa(ids["c.example.com"])+`"`) {
		t.Errorf("target outside the filter listed in confirmation")
	}
}

func TestBulkDeletePreviewCapsAt20(t *testing.T) {
	srv, client, token := authedServer(t)
	var names []string
	for i := range 23 {
		names = append(names, fmt.Sprintf("host%02d.example.com", i))
	}
	importTargets(t, client, names...)
	resp := postForm(t, srv, token, "/targets/bulk/delete", url.Values{"all": {"1"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, body:\n%s", resp.StatusCode, resp.Body)
	}
	if !strings.Contains(resp.Body, "…and 3 more") {
		t.Errorf("preview does not say how many more")
	}
}

func TestDashboardRendersBulkToolbar(t *testing.T) {
	srv, client, token := authedServer(t)
	ids := importTargets(t, client, "a.example.com", "b.example.com")
	setReachability(t, client, ids["a.example.com"], "pending")
	setReachability(t, client, ids["b.example.com"], "pending")

	resp := send(t, srv, token, "GET", "/?state=pending", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /: status %d", resp.StatusCode)
	}
	for _, want := range []string{
		`<form id="bulk" method="POST" action="/targets/bulk/delete"`,
		`formaction="/targets/bulk/export"`,
		`name="format" value="json"`,
		`name="format" value="csv"`,
		`Delete selected`,
		`<input type="hidden" name="all" id="bulk-all" value="">`,
		`name="ids" value="` + strconv.Itoa(ids["a.example.com"]) + `" form="bulk"`,
		`name="ids" value="` + strconv.Itoa(ids["b.example.com"]) + `" form="bulk"`,
		`id="bulk-select-page"`,
	} {
		if !strings.Contains(resp.Body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	// The filter travels with the bulk form so all=1 can resolve it.
	toolbar := resp.Body[strings.Index(resp.Body, `<form id="bulk"`):]
	toolbar = toolbar[:strings.Index(toolbar, "</form>")]
	if !strings.Contains(toolbar, `<input type="hidden" name="state" value="pending">`) {
		t.Errorf("toolbar does not carry the state filter")
	}
}

func TestDashboardSelectAllMatchingLine(t *testing.T) {
	srv, client, token := authedServer(t)
	importTargets(t, client, "a.example.com", "b.example.com", "c.example.com")
	srv.dashboardPageSize = 2

	resp := send(t, srv, token, "GET", "/", "", "")
	if !strings.Contains(resp.Body, `data-total="3"`) || !strings.Contains(resp.Body, "Select all 3 matching targets") {
		t.Errorf("select-all line missing when matches exceed the page")
	}

	srv.dashboardPageSize = 50
	resp = send(t, srv, token, "GET", "/", "", "")
	if strings.Contains(resp.Body, `id="bulk-select-all"`) {
		t.Errorf("select-all line rendered when everything fits on one page")
	}
}

func TestDashboardEmptyStateColspan(t *testing.T) {
	srv, _, token := authedServer(t)
	resp := send(t, srv, token, "GET", "/", "", "")
	if !strings.Contains(resp.Body, `<td colspan="7"`) {
		t.Errorf("empty-state row colspan is not 7")
	}
	if strings.Contains(resp.Body, `id="bulk"`) {
		t.Errorf("bulk toolbar shown with no targets")
	}
}
