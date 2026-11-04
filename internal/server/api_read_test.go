package server

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	apidocs "perimeter/api"
	"perimeter/ent"
	"perimeter/ent/apitoken"
	"perimeter/internal/storage"
	"perimeter/scanner/csp"

	"github.com/gofiber/fiber/v2"
)

// makeAPIToken makes a token for the user with this email.
func makeAPIToken(t *testing.T, srv *Server, client *ent.Client, email string, scope apitoken.Scope) string {
	t.Helper()
	raw, _, err := srv.auth.CreateAPIToken(t.Context(), userByEmail(t, client, email), "test", scope, nil)
	if err != nil {
		t.Fatalf("CreateAPIToken for %s: %v", email, err)
	}
	return raw
}

// getAPI sends a GET with the bearer token and checks the status. When out is
// not nil the body is decoded into it. It returns the raw body.
func getAPI(t *testing.T, srv *Server, raw, path string, want int, out any) string {
	t.Helper()
	resp := apiCall(t, srv, "GET", path, bearer(raw))
	if resp.StatusCode != want {
		t.Fatalf("GET %s: status %d, want %d; body %s", path, resp.StatusCode, want, resp.Body)
	}
	if out != nil {
		if err := json.Unmarshal([]byte(resp.Body), out); err != nil {
			t.Fatalf("GET %s: decode: %v\n%s", path, err, resp.Body)
		}
	}
	return resp.Body
}

// seedReadData gives three targets. a.example.com has SSL grade A expiring in
// 10 days, two CSP findings and the tag prod. b.example.com has grade C and
// port 22 and 443 open on its address. c.example.com has no scans.
func seedReadData(t *testing.T, client *ent.Client) map[string]int {
	t.Helper()
	ctx := context.Background()
	st := storage.NewEntStorage(client)
	ids := importTargets(t, client, "a.example.com", "b.example.com", "c.example.com")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(st.SaveSSLScan(ctx, "a.example.com", storage.SSLResult{
		Grade: "A", Status: "READY", CertIssuer: "Test CA", CertExpiry: time.Now().Add(10 * 24 * time.Hour),
	}))
	must(st.SaveSSLScan(ctx, "b.example.com", storage.SSLResult{
		Grade: "C", Status: "READY", CertIssuer: "Test CA", CertExpiry: time.Now().Add(200 * 24 * time.Hour),
	}))
	must(st.SaveCSPScan(ctx, "a.example.com", "default-src 'self'", make([]csp.Finding, 2)))
	must(st.SaveIPs(ctx, "b.example.com", []string{"192.0.2.10"}, time.Hour))
	must(st.SavePortScan(ctx, "192.0.2.10", []int{22, 443}))
	must(client.Target.UpdateOneID(ids["a.example.com"]).AddTagIDs(createTags(t, client, "prod")...).Exec(ctx))
	return ids
}

// listReply is the part of a target list the tests read.
type listReply struct {
	Items []struct {
		ID    int    `json:"id"`
		Input string `json:"input"`
	} `json:"items"`
	Total      int    `json:"total"`
	NextCursor string `json:"next_cursor"`
}

// inputs returns the input names of a list reply, in order.
func (l listReply) inputs() []string {
	out := []string{}
	for _, it := range l.Items {
		out = append(out, it.Input)
	}
	return out
}

func TestAPIListTargetsFilters(t *testing.T) {
	srv, client, _ := roleServer(t)
	seedReadData(t, client)
	raw := makeAPIToken(t, srv, client, "member@test.com", apitoken.ScopeRead)

	cases := []struct {
		query string
		want  []string
	}{
		{"", []string{"a.example.com", "b.example.com", "c.example.com"}},
		{"ssl_below=B", []string{"b.example.com"}},
		{"ssl_grade=A", []string{"a.example.com"}},
		{"tag=prod", []string{"a.example.com"}},
		{"csp=issues", []string{"a.example.com"}},
		{"expiring_within_days=30", []string{"a.example.com"}},
		{"q=B.EXAMPLE", []string{"b.example.com"}},
		{"state=pending,ok", []string{"a.example.com", "b.example.com", "c.example.com"}},
		{"state=ok&state=unresolved", []string{"a.example.com", "b.example.com"}},
		{"state=unreachable", []string{}},
		{"port=443", []string{"b.example.com"}},
		{"sort=target&order=desc", []string{"c.example.com", "b.example.com", "a.example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			var got listReply
			getAPI(t, srv, raw, "/api/v1/targets?"+tc.query, http.StatusOK, &got)
			if strings.Join(got.inputs(), ",") != strings.Join(tc.want, ",") {
				t.Errorf("got %v, want %v", got.inputs(), tc.want)
			}
			if got.Total != len(tc.want) {
				t.Errorf("total %d, want %d", got.Total, len(tc.want))
			}
		})
	}
}

func TestAPIListTargetsPagesWithCursor(t *testing.T) {
	srv, client, _ := roleServer(t)
	seedReadData(t, client)
	raw := makeAPIToken(t, srv, client, "member@test.com", apitoken.ScopeRead)

	var first listReply
	getAPI(t, srv, raw, "/api/v1/targets?sort=target&limit=2", http.StatusOK, &first)
	if strings.Join(first.inputs(), ",") != "a.example.com,b.example.com" || first.Total != 3 {
		t.Fatalf("first page %v total %d", first.inputs(), first.Total)
	}
	if first.NextCursor == "" {
		t.Fatal("first page has no next_cursor")
	}

	var second listReply
	getAPI(t, srv, raw, "/api/v1/targets?sort=target&limit=2&cursor="+first.NextCursor, http.StatusOK, &second)
	if strings.Join(second.inputs(), ",") != "c.example.com" || second.Total != 3 {
		t.Fatalf("second page %v total %d", second.inputs(), second.Total)
	}
	if second.NextCursor != "" {
		t.Errorf("last page has next_cursor %q", second.NextCursor)
	}
}

func TestAPIListTargetsDeleted(t *testing.T) {
	srv, client, _ := roleServer(t)
	ids := seedReadData(t, client)
	raw := makeAPIToken(t, srv, client, "member@test.com", apitoken.ScopeRead)
	if err := storage.NewEntStorage(client).DeleteTarget(t.Context(), ids["c.example.com"]); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}

	var live listReply
	getAPI(t, srv, raw, "/api/v1/targets", http.StatusOK, &live)
	if strings.Join(live.inputs(), ",") != "a.example.com,b.example.com" {
		t.Errorf("live list %v, want without the deleted target", live.inputs())
	}

	body := getAPI(t, srv, raw, "/api/v1/targets?deleted=true", http.StatusOK, &live)
	if strings.Join(live.inputs(), ",") != "c.example.com" {
		t.Errorf("deleted list %v, want c.example.com", live.inputs())
	}
	if !strings.Contains(body, `"deleted_at"`) {
		t.Errorf("deleted entry has no deleted_at: %s", body)
	}

	getAPI(t, srv, raw, "/api/v1/targets?deleted=true&tag=prod", http.StatusBadRequest, nil)
}

func TestAPIListTargetsEmptyPageIsArray(t *testing.T) {
	srv, client, _ := roleServer(t)
	raw := makeAPIToken(t, srv, client, "member@test.com", apitoken.ScopeRead)
	body := getAPI(t, srv, raw, "/api/v1/targets", http.StatusOK, nil)
	if !strings.Contains(body, `"items":[]`) {
		t.Errorf("empty list body %s, want items as an array", body)
	}
}

func TestAPIReadBadParametersAre400(t *testing.T) {
	srv, client, _ := roleServer(t)
	ids := seedReadData(t, client)
	raw := makeAPIToken(t, srv, client, "member@test.com", apitoken.ScopeRead)
	id := strconv.Itoa(ids["a.example.com"])

	cases := []struct {
		path, field string
	}{
		{"/api/v1/targets?ssl_grade=Z", "ssl_grade"},
		{"/api/v1/targets?ssl_below=Z", "ssl_below"},
		{"/api/v1/targets?state=bogus", "state"},
		{"/api/v1/targets?csp=maybe", "csp"},
		{"/api/v1/targets?sort=bogus", "sort"},
		{"/api/v1/targets?order=sideways", "order"},
		{"/api/v1/targets?port=99999", "port"},
		{"/api/v1/targets?port=abc", "port"},
		{"/api/v1/targets?expiring_within_days=-1", "expiring_within_days"},
		{"/api/v1/targets?deleted=maybe", "deleted"},
		{"/api/v1/targets?limit=0", "limit"},
		{"/api/v1/targets?limit=many", "limit"},
		{"/api/v1/targets?cursor=!!!", "cursor"},
		{"/api/v1/targets?cursor=" + encodeCursor(-1), "cursor"},
		{"/api/v1/targets/abc", "id"},
		{"/api/v1/targets/0", "id"},
		{"/api/v1/targets/" + id + "/history?cursor=!!!", "cursor"},
		{"/api/v1/changes", "since"},
		{"/api/v1/changes?since=yesterday", "since"},
		{"/api/v1/changes?since=2026-01-01T00:00:00Z&limit=0", "limit"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			resp := apiCall(t, srv, "GET", tc.path, bearer(raw))
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status %d, want 400; body %s", resp.StatusCode, resp.Body)
			}
			if code := apiErrorBodyCode(t, resp.Body); code != "invalid_request" {
				t.Errorf("error code %q, want invalid_request", code)
			}
			var out struct {
				Error struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(resp.Body), &out); err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(out.Error.Message, tc.field+":") {
				t.Errorf("message %q does not name field %q", out.Error.Message, tc.field)
			}
		})
	}
}

func TestAPIGetTarget(t *testing.T) {
	srv, client, _ := roleServer(t)
	ids := seedReadData(t, client)
	raw := makeAPIToken(t, srv, client, "viewer@test.com", apitoken.ScopeRead)

	var a struct {
		Input string   `json:"input"`
		Tags  []string `json:"tags"`
		SSL   struct {
			Grade string `json:"grade"`
		} `json:"ssl"`
		CSP struct {
			Findings []json.RawMessage `json:"findings"`
		} `json:"csp"`
	}
	getAPI(t, srv, raw, "/api/v1/targets/"+strconv.Itoa(ids["a.example.com"]), http.StatusOK, &a)
	if a.Input != "a.example.com" || len(a.Tags) != 1 || a.Tags[0] != "prod" {
		t.Errorf("target a: %+v", a)
	}
	if a.SSL.Grade != "A" || len(a.CSP.Findings) != 2 {
		t.Errorf("target a scans: ssl %q, csp findings %d", a.SSL.Grade, len(a.CSP.Findings))
	}

	var b struct {
		IPs []struct {
			Address   string `json:"address"`
			OpenPorts []int  `json:"open_ports"`
		} `json:"ips"`
	}
	getAPI(t, srv, raw, "/api/v1/targets/"+strconv.Itoa(ids["b.example.com"]), http.StatusOK, &b)
	if len(b.IPs) != 1 || b.IPs[0].Address != "192.0.2.10" || len(b.IPs[0].OpenPorts) != 2 {
		t.Errorf("target b ips: %+v", b.IPs)
	}

	getAPI(t, srv, raw, "/api/v1/targets/99999", http.StatusNotFound, nil)

	if err := storage.NewEntStorage(client).DeleteTarget(t.Context(), ids["a.example.com"]); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}
	resp := apiCall(t, srv, "GET", "/api/v1/targets/"+strconv.Itoa(ids["a.example.com"]), bearer(raw))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("soft-deleted target: status %d, want 404", resp.StatusCode)
	}
	if code := apiErrorBodyCode(t, resp.Body); code != "not_found" {
		t.Errorf("error code %q, want not_found", code)
	}
}

// historyReply is the part of a history page the tests read.
type historyReply struct {
	Items []struct {
		Kind    string `json:"kind"`
		Summary string `json:"summary"`
	} `json:"items"`
	Total      int    `json:"total"`
	NextCursor string `json:"next_cursor"`
}

func TestAPITargetHistoryPages(t *testing.T) {
	srv, client, _ := roleServer(t)
	ids := seedReadData(t, client)
	raw := makeAPIToken(t, srv, client, "member@test.com", apitoken.ScopeRead)
	path := "/api/v1/targets/" + strconv.Itoa(ids["a.example.com"]) + "/history"

	var all historyReply
	getAPI(t, srv, raw, path, http.StatusOK, &all)
	kinds := map[string]bool{}
	for _, it := range all.Items {
		kinds[it.Kind] = true
	}
	if all.Total != 2 || !kinds["ssl"] || !kinds["csp"] {
		t.Fatalf("history: total %d kinds %v", all.Total, kinds)
	}

	var page1, page2 historyReply
	getAPI(t, srv, raw, path+"?limit=1", http.StatusOK, &page1)
	if len(page1.Items) != 1 || page1.NextCursor == "" {
		t.Fatalf("page 1: %+v", page1)
	}
	getAPI(t, srv, raw, path+"?limit=1&cursor="+page1.NextCursor, http.StatusOK, &page2)
	if len(page2.Items) != 1 || page2.NextCursor != "" || page2.Items[0].Kind == page1.Items[0].Kind {
		t.Errorf("page 2: %+v after %+v", page2, page1)
	}
	if page2.Total != 2 {
		t.Errorf("page 2 total %d, want 2", page2.Total)
	}

	getAPI(t, srv, raw, "/api/v1/targets/99999/history", http.StatusNotFound, nil)
}

func TestAPIListTags(t *testing.T) {
	srv, client, _ := roleServer(t)
	seedReadData(t, client)
	raw := makeAPIToken(t, srv, client, "viewer@test.com", apitoken.ScopeRead)

	var out struct {
		Items []struct {
			Name        string `json:"name"`
			TargetCount int    `json:"target_count"`
		} `json:"items"`
	}
	getAPI(t, srv, raw, "/api/v1/tags", http.StatusOK, &out)
	if len(out.Items) != 1 || out.Items[0].Name != "prod" || out.Items[0].TargetCount != 1 {
		t.Errorf("tags: %+v", out.Items)
	}
}

func TestAPISummary(t *testing.T) {
	srv, client, _ := roleServer(t)
	seedReadData(t, client)
	raw := makeAPIToken(t, srv, client, "viewer@test.com", apitoken.ScopeRead)

	var out struct {
		Totals struct {
			Targets        int            `json:"targets"`
			ByReachability map[string]int `json:"by_reachability"`
			CSPIssues      int            `json:"csp_issues"`
			ExpiringCerts  int            `json:"expiring_certs"`
			WeakSSL        int            `json:"weak_ssl"`
		} `json:"totals"`
		Expiring []struct {
			Input string `json:"input"`
		} `json:"expiring"`
		RecentChanges []struct {
			Kind string `json:"kind"`
		} `json:"recent_changes"`
	}
	getAPI(t, srv, raw, "/api/v1/summary", http.StatusOK, &out)
	if out.Totals.Targets != 3 || out.Totals.WeakSSL != 1 || out.Totals.CSPIssues != 1 || out.Totals.ExpiringCerts != 1 {
		t.Errorf("totals: %+v", out.Totals)
	}
	if out.Totals.ByReachability == nil {
		t.Error("by_reachability is missing")
	}
	if len(out.Expiring) != 1 || out.Expiring[0].Input != "a.example.com" {
		t.Errorf("expiring: %+v", out.Expiring)
	}
	if len(out.RecentChanges) == 0 {
		t.Error("recent_changes is empty, but every target was just added")
	}
}

// changeReply is the part of a change feed the tests read.
type changeReply struct {
	Items []struct {
		At       time.Time `json:"at"`
		TargetID int       `json:"target_id"`
		Kind     string    `json:"kind"`
	} `json:"items"`
	Truncated bool      `json:"truncated"`
	Until     time.Time `json:"until"`
}

func TestAPIChangesPollWithUntil(t *testing.T) {
	srv, client, _ := roleServer(t)
	seedReadData(t, client)
	raw := makeAPIToken(t, srv, client, "member@test.com", apitoken.ScopeRead)
	const epoch = "/api/v1/changes?since=2000-01-01T00:00:00Z"

	var full changeReply
	getAPI(t, srv, raw, epoch, http.StatusOK, &full)
	if len(full.Items) < 3 || full.Truncated {
		t.Fatalf("full feed: %d items, truncated %v", len(full.Items), full.Truncated)
	}
	last := full.Items[len(full.Items)-1].At
	if !full.Until.Equal(last) {
		t.Errorf("until %v, want the last item's time %v", full.Until, last)
	}

	// Polling with until as since returns nothing new.
	var none changeReply
	body := getAPI(t, srv, raw, "/api/v1/changes?since="+full.Until.UTC().Format(time.RFC3339Nano), http.StatusOK, &none)
	if len(none.Items) != 0 || !strings.Contains(body, `"items":[]`) {
		t.Errorf("poll after the last change: %s", body)
	}

	// Walking the feed one change at a time reaches the same changes.
	since := "2000-01-01T00:00:00Z"
	var walked []time.Time
	for i := 0; i < len(full.Items)+1; i++ {
		var page changeReply
		getAPI(t, srv, raw, "/api/v1/changes?limit=1&since="+since, http.StatusOK, &page)
		for _, it := range page.Items {
			walked = append(walked, it.At)
		}
		if !page.Truncated {
			break
		}
		since = page.Until.UTC().Format(time.RFC3339Nano)
	}
	if len(walked) != len(full.Items) {
		t.Fatalf("walked %d changes, want %d", len(walked), len(full.Items))
	}
	for i, at := range walked {
		if !at.Equal(full.Items[i].At) {
			t.Errorf("change %d at %v, want %v", i, at, full.Items[i].At)
		}
	}
}

func TestAPIChangesEmptyUntilIsSince(t *testing.T) {
	srv, client, _ := roleServer(t)
	seedReadData(t, client)
	raw := makeAPIToken(t, srv, client, "member@test.com", apitoken.ScopeRead)

	const future = "2999-01-01T00:00:00Z"
	var out changeReply
	body := getAPI(t, srv, raw, "/api/v1/changes?since="+future, http.StatusOK, &out)
	if !strings.Contains(body, `"items":[]`) || !strings.Contains(body, `"truncated":false`) {
		t.Errorf("empty feed body %s", body)
	}
	if !out.Until.Equal(time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("until %v, want the since time", out.Until)
	}
}

func TestAPIReadRoutesAcceptAnyScopeAndRole(t *testing.T) {
	srv, client, _ := roleServer(t)
	ids := seedReadData(t, client)
	id := strconv.Itoa(ids["a.example.com"])
	paths := []string{
		"/api/v1/me",
		"/api/v1/targets",
		"/api/v1/targets/" + id,
		"/api/v1/targets/" + id + "/history",
		"/api/v1/tags",
		"/api/v1/summary",
		"/api/v1/changes?since=2000-01-01T00:00:00Z",
	}
	tokens := map[string]string{
		"viewer read":  makeAPIToken(t, srv, client, "viewer@test.com", apitoken.ScopeRead),
		"member read":  makeAPIToken(t, srv, client, "member@test.com", apitoken.ScopeRead),
		"member write": makeAPIToken(t, srv, client, "member@test.com", apitoken.ScopeWrite),
	}
	for name, raw := range tokens {
		for _, p := range paths {
			t.Run(name+" "+p, func(t *testing.T) {
				getAPI(t, srv, raw, p, http.StatusOK, nil)
			})
		}
	}
}

func TestOpenAPIIsServedWithoutToken(t *testing.T) {
	srv, _, _ := roleServer(t)
	resp := apiCall(t, srv, "GET", "/api/v1/openapi.yaml", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200 without a token; body %s", resp.StatusCode, resp.Body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/yaml") {
		t.Errorf("content type %q, want application/yaml", ct)
	}
	if !strings.Contains(resp.Body, "openapi: 3.1") {
		t.Errorf("body is not an OpenAPI 3.1 document:\n%.200s", resp.Body)
	}
	if resp.Body != string(apidocs.OpenAPI) {
		t.Error("body differs from the embedded spec")
	}
}

// pathParam matches a Fiber route parameter such as :id.
var pathParam = regexp.MustCompile(`:([A-Za-z_]+)`)

// documentsOperation reports whether the spec has an operation for method under
// path. Path keys sit at two spaces of indent and operations at four.
func documentsOperation(spec, path, method string) bool {
	in := false
	for _, line := range strings.Split(spec, "\n") {
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") {
			in = line == "  "+path+":"
			continue
		}
		if in && line == "    "+strings.ToLower(method)+":" {
			return true
		}
	}
	return false
}

func TestOpenAPIDocumentsEveryAPIRoute(t *testing.T) {
	srv, _, _ := roleServer(t)
	spec := string(apidocs.OpenAPI)
	checked := 0
	for _, r := range srv.app.GetRoutes() {
		// The group's middleware (token check, JSON 404) is listed under the
		// bare prefix, once per method. HEAD is the copy Fiber adds to each GET.
		if !strings.HasPrefix(r.Path, "/api/v1") || r.Path == "/api/v1" || r.Method == fiber.MethodHead {
			continue
		}
		checked++
		path := pathParam.ReplaceAllString(r.Path, "{$1}")
		if !documentsOperation(spec, path, r.Method) {
			t.Errorf("%s %s is not documented in api/openapi.yaml as %s %s", r.Method, r.Path, strings.ToLower(r.Method), path)
		}
	}
	if checked < 8 {
		t.Fatalf("only %d /api/v1 routes checked; the route list is missing", checked)
	}
}
