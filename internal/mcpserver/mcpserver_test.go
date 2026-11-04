package mcpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	sqlite "modernc.org/sqlite"

	"perimeter/ent"
	"perimeter/ent/apitoken"
	"perimeter/ent/auditevent"
	"perimeter/ent/enttest"
	"perimeter/ent/schema"
	"perimeter/ent/tag"
	"perimeter/ent/target"
	"perimeter/ent/user"
	"perimeter/internal/auth"
	"perimeter/internal/service"
	"perimeter/internal/storage"
	"perimeter/scanner/csp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ent opens the "sqlite3" driver name; modernc registers itself as "sqlite".
func init() { sql.Register("sqlite3", &sqlite.Driver{}) }

// readTools and writeTools are the tool names a caller sees.
var (
	readTools  = []string{"changes_since", "find_issues", "get_target", "list_tags", "list_targets", "summary", "target_history"}
	writeTools = []string{"add_targets", "delete_target", "rescan", "restore_target", "set_tags"}
)

// fixture is a real SQLite database with an auth and service stack on top.
type fixture struct {
	t      *testing.T
	ctx    context.Context
	client *ent.Client
	st     *storage.EntStorage
	auth   *auth.Auth
	h      *Handler
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	t.Cleanup(func() { client.Close() })
	a, err := auth.New(ctx, auth.Config{SessionMaxAge: time.Hour}, client)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	st := storage.NewEntStorage(client)
	svc := service.New(st, client, 30*24*time.Hour)
	svc.SetRescanConfig(10*time.Minute, true)
	return &fixture{t: t, ctx: ctx, client: client, st: st, auth: a, h: New(svc, a, "test")}
}

func (f *fixture) must(err error) {
	f.t.Helper()
	if err != nil {
		f.t.Fatal(err)
	}
}

// token makes a user with the role and an API token of the scope. It returns
// the raw token and the user.
func (f *fixture) token(email string, role user.Role, scope apitoken.Scope) (string, *ent.User) {
	f.t.Helper()
	u, err := f.client.User.Create().SetEmail(email).SetName(email).SetRole(role).SetConfirmed(true).Save(f.ctx)
	f.must(err)
	raw, _, err := f.auth.CreateAPIToken(f.ctx, u, "agent", scope, nil)
	f.must(err)
	return raw, u
}

// connect links an MCP client to the server the fixture handler serves, in memory.
func (f *fixture) connect(raw string) *mcp.ClientSession {
	return f.session(f.h, raw)
}

// connectOffSSL links to a server whose service has SSL scanning off, as a
// server without SSL Labs credentials would: no SetRescanConfig, and the
// field defaults to false.
func (f *fixture) connectOffSSL(raw string) *mcp.ClientSession {
	f.t.Helper()
	return f.session(New(service.New(f.st, f.client, 30*24*time.Hour), f.auth, "test"), raw)
}

// session links an MCP client to the server the handler serves, in memory.
func (f *fixture) session(h *Handler, raw string) *mcp.ClientSession {
	f.t.Helper()
	u, tok, err := f.auth.ValidateAPIToken(f.ctx, raw)
	f.must(err)
	srv := h.newServer(u, tok)
	ct, stp := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(f.ctx, stp, nil)
	f.must(err)
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(f.ctx, ct, nil)
	f.must(err)
	f.t.Cleanup(func() {
		cs.Close()
		ss.Close()
	})
	return cs
}

// seed loads four targets with scans: a healthy one, a weak SSL grade with
// CSP findings, an expired certificate, and a name that does not resolve.
func (f *fixture) seed() {
	f.t.Helper()
	_, err := f.st.ImportTargets(f.ctx, []string{"example.com", "mail.example.org", "expired.test", "gone.example"})
	f.must(err)

	f.must(f.st.SaveIPs(f.ctx, "example.com", []string{"10.0.0.1"}, time.Hour))
	f.must(f.st.SavePortScan(f.ctx, "10.0.0.1", []int{22, 443}))
	f.must(f.st.SaveSSLScan(f.ctx, "example.com", storage.SSLResult{
		Grade: "A", Status: "READY", CertIssuer: "Test CA", CertExpiry: time.Now().Add(100 * 24 * time.Hour),
	}))
	f.tag("example.com", "prod")

	f.must(f.st.SaveIPs(f.ctx, "mail.example.org", []string{"10.0.0.2"}, time.Hour))
	f.must(f.st.SavePortScan(f.ctx, "10.0.0.2", nil))
	f.must(f.st.SaveSSLScan(f.ctx, "mail.example.org", storage.SSLResult{
		Grade: "C", Status: "READY", CertIssuer: "Test CA", CertExpiry: time.Now().Add(5 * 24 * time.Hour),
	}))
	f.must(f.st.SaveCSPScan(f.ctx, "mail.example.org", "default-src 'self'", []csp.Finding{
		{Type: csp.TypeScriptUnsafeInline, Severity: csp.SeverityHigh, Directive: "script-src", Value: "'unsafe-inline'", Description: "inline script allowed"},
		{Type: csp.TypeMissingDirectives, Severity: csp.SeverityInfo, Description: "no default-src"},
	}))

	f.must(f.st.SaveSSLScan(f.ctx, "expired.test", storage.SSLResult{
		Grade: "F", Status: "READY", CertIssuer: "Test CA", CertExpiry: time.Now().Add(-3 * 24 * time.Hour),
	}))

	f.must(f.st.RecordResolveFailure(f.ctx, "gone.example", storage.ResolveFailure{Message: "no such host"}))
}

// tag creates a tag if needed and attaches it to the target.
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

// id returns the id of the target with the input, deleted or not.
func (f *fixture) id(input string) int {
	f.t.Helper()
	id, err := f.client.Target.Query().Where(target.Input(input)).OnlyID(schema.SkipSoftDelete(f.ctx))
	f.must(err)
	return id
}

// call runs a tool. A protocol error fails the test; a tool error comes back
// as a result with IsError set.
func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", name, err)
	}
	return res
}

// text joins the text content of a result.
func text(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// decode reads the structured content of a result into out.
func decode(t *testing.T, res *mcp.CallToolResult, out any) {
	t.Helper()
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("decode structured content %s: %v", raw, err)
	}
}

// toolNames lists the tools a client sees, sorted.
func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	slices.Sort(names)
	return names
}

// wantErr asserts a tool error whose text names the parameter.
func wantErr(t *testing.T, res *mcp.CallToolResult, param string) {
	t.Helper()
	if !res.IsError {
		t.Fatalf("IsError false, want a tool error mentioning %q; text %q", param, text(res))
	}
	if !strings.Contains(text(res), param) {
		t.Errorf("error text %q does not name %q", text(res), param)
	}
}

func TestToolListFollowsTokenScopeAndRole(t *testing.T) {
	f := newFixture(t)
	viewerRead, _ := f.token("viewer@test.com", user.RoleViewer, apitoken.ScopeRead)
	memberRead, _ := f.token("member-read@test.com", user.RoleMember, apitoken.ScopeRead)
	memberWrite, _ := f.token("member@test.com", user.RoleMember, apitoken.ScopeWrite)
	adminWrite, _ := f.token("admin@test.com", user.RoleAdmin, apitoken.ScopeWrite)

	all := slices.Concat(readTools, writeTools)
	slices.Sort(all)
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"viewer read token", viewerRead, readTools},
		{"member read token", memberRead, readTools},
		{"member write token", memberWrite, all},
		{"admin write token", adminWrite, all},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := f.connect(tc.raw)
			if got := toolNames(t, cs); !slices.Equal(got, tc.want) {
				t.Errorf("tools = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestToolAnnotationsMarkReadAndWrite(t *testing.T) {
	f := newFixture(t)
	raw, _ := f.token("admin@test.com", user.RoleAdmin, apitoken.ScopeWrite)
	cs := f.connect(raw)
	res, err := cs.ListTools(context.Background(), nil)
	f.must(err)
	for _, tl := range res.Tools {
		if tl.Annotations == nil {
			t.Errorf("%s: no annotations", tl.Name)
			continue
		}
		isRead := slices.Contains(readTools, tl.Name)
		if tl.Annotations.ReadOnlyHint != isRead {
			t.Errorf("%s: ReadOnlyHint = %v, want %v", tl.Name, tl.Annotations.ReadOnlyHint, isRead)
		}
		if isRead && !tl.Annotations.IdempotentHint {
			t.Errorf("%s: read tool must set IdempotentHint", tl.Name)
		}
		if isRead && (tl.Annotations.OpenWorldHint == nil || *tl.Annotations.OpenWorldHint) {
			t.Errorf("%s: read tool must set OpenWorldHint false", tl.Name)
		}
	}
}

func TestInstructionsDescribeTheFlow(t *testing.T) {
	f := newFixture(t)
	raw, _ := f.token("viewer@test.com", user.RoleViewer, apitoken.ScopeRead)
	cs := f.connect(raw)
	got := cs.InitializeResult().Instructions
	for _, want := range []string{"summary", "find_issues", "list_targets", "get_target", "changes_since"} {
		if !strings.Contains(got, want) {
			t.Errorf("instructions do not mention %s: %q", want, got)
		}
	}
}

func TestInstructionsSayWhyAConnectionIsReadOnly(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		email string
		role  user.Role
		scope apitoken.Scope
		want  string
	}{
		{"writer@test.com", user.RoleMember, apitoken.ScopeWrite, "can also change data"},
		{"reader@test.com", user.RoleMember, apitoken.ScopeRead, "token has read scope"},
		{"viewer@test.com", user.RoleViewer, apitoken.ScopeRead, "role is viewer"},
	} {
		raw, _ := f.token(tc.email, tc.role, tc.scope)
		if got := f.connect(raw).InitializeResult().Instructions; !strings.Contains(got, tc.want) {
			t.Errorf("%s: instructions lack %q: %q", tc.email, tc.want, got)
		}
	}
}

func TestReadToolsAgainstSeededData(t *testing.T) {
	f := newFixture(t)
	f.seed()
	raw, _ := f.token("viewer@test.com", user.RoleViewer, apitoken.ScopeRead)
	cs := f.connect(raw)

	t.Run("summary", func(t *testing.T) {
		res := call(t, cs, "summary", nil)
		// gone.example has never been SSL scanned, so it is named.
		for _, want := range []string{"4 targets", "example.com", "expired.test", "weakest SSL", "SSL not scanned yet: 1 target"} {
			if !strings.Contains(text(res), want) {
				t.Errorf("summary text lacks %q:\n%s", want, text(res))
			}
		}
	})

	t.Run("list_targets filters", func(t *testing.T) {
		res := call(t, cs, "list_targets", map[string]any{"ssl_below": "B"})
		if !strings.Contains(text(res), "mail.example.org") || strings.Contains(text(res), "example.com ") {
			t.Errorf("ssl_below B text:\n%s", text(res))
		}
		if !strings.HasPrefix(text(res), "2 of 2 targets") {
			t.Errorf("ssl_below B header: %q", text(res))
		}
	})

	t.Run("list_targets bad state", func(t *testing.T) {
		wantErr(t, call(t, cs, "list_targets", map[string]any{"state": "bogus"}), "state")
	})

	t.Run("list_targets bad sort", func(t *testing.T) {
		wantErr(t, call(t, cs, "list_targets", map[string]any{"sort": "nope"}), "sort")
	})

	t.Run("list_targets bad grade lists the valid ones", func(t *testing.T) {
		res := call(t, cs, "list_targets", map[string]any{"ssl_below": "Z"})
		wantErr(t, res, "ssl_below")
		for _, g := range []string{"A+", "B", "F", "M"} {
			if !strings.Contains(text(res), g) {
				t.Errorf("error text lacks grade %q: %s", g, text(res))
			}
		}
	})

	t.Run("list_targets paging text", func(t *testing.T) {
		res := call(t, cs, "list_targets", map[string]any{"limit": 2})
		if !strings.Contains(text(res), "2 more; pass offset=2") {
			t.Errorf("paging hint missing:\n%s", text(res))
		}
	})

	t.Run("get_target by name and id", func(t *testing.T) {
		res := call(t, cs, "get_target", map[string]any{"target": "example.com"})
		if res.IsError {
			t.Fatalf("get_target: %s", text(res))
		}
		if !strings.Contains(text(res), "IP 10.0.0.1: open ports 22, 443") {
			t.Errorf("get_target text:\n%s", text(res))
		}
		for _, want := range []string{"state: ok", "tags: prod", "checked ", "SSL: grade A (READY)"} {
			if !strings.Contains(text(res), want) {
				t.Errorf("get_target text lacks %q:\n%s", want, text(res))
			}
		}
		var d service.TargetDetail
		decode(t, res, &d)
		if d.Input != "example.com" || d.SSL == nil || d.SSL.Grade != "A" {
			t.Errorf("structured detail = %+v", d)
		}

		byID := call(t, cs, "get_target", map[string]any{"target": strconv.Itoa(f.id("example.com"))})
		if byID.IsError {
			t.Errorf("get_target by id: %s", text(byID))
		}
	})

	t.Run("get_target with CSP findings", func(t *testing.T) {
		res := call(t, cs, "get_target", map[string]any{"target": "mail.example.org"})
		if res.IsError || !strings.Contains(text(res), "CSP 2 findings") {
			t.Errorf("get_target mail.example.org: error %v, text %q", res.IsError, text(res))
		}
		for _, want := range []string{"- high script-src 'unsafe-inline': inline script allowed", "- info: no default-src"} {
			if !strings.Contains(text(res), want) {
				t.Errorf("get_target text lacks %q:\n%s", want, text(res))
			}
		}
		var d service.TargetDetail
		decode(t, res, &d)
		if d.CSP == nil || len(d.CSP.Findings) != 2 {
			t.Fatalf("csp detail = %+v", d.CSP)
		}
		if d.CSP.Findings[0].Level != "high" || d.CSP.Findings[1].Level != "info" {
			t.Errorf("finding levels = %q, %q, want high and info", d.CSP.Findings[0].Level, d.CSP.Findings[1].Level)
		}
	})

	t.Run("get_target name is normalized", func(t *testing.T) {
		res := call(t, cs, "get_target", map[string]any{"target": "Example.COM"})
		if res.IsError {
			t.Errorf("get_target Example.COM: %s", text(res))
		}
	})

	t.Run("get_target unknown", func(t *testing.T) {
		wantErr(t, call(t, cs, "get_target", map[string]any{"target": "missing.example"}), "target")
	})

	t.Run("get_target missing target argument", func(t *testing.T) {
		wantErr(t, call(t, cs, "get_target", map[string]any{"target": "  "}), "target")
	})

	t.Run("target_history", func(t *testing.T) {
		res := call(t, cs, "target_history", map[string]any{"target": "mail.example.org"})
		if res.IsError {
			t.Fatalf("target_history: %s", text(res))
		}
		if !strings.Contains(text(res), "csp 2 findings") && !strings.Contains(text(res), "CSP 2 findings") {
			t.Errorf("history lacks the CSP entry:\n%s", text(res))
		}
	})

	t.Run("find_issues weak_ssl and expired", func(t *testing.T) {
		res := call(t, cs, "find_issues", map[string]any{"categories": []string{"weak_ssl", "expired_certs"}})
		if res.IsError {
			t.Fatalf("find_issues: %s", text(res))
		}
		var out IssuesOut
		decode(t, res, &out)
		if len(out.Groups) != 2 {
			t.Fatalf("groups = %+v, want two", out.Groups)
		}
		weak, expired := out.Groups[0], out.Groups[1]
		if weak.Category != "weak_ssl" || weak.Total != 2 {
			t.Errorf("weak_ssl group = %+v", weak)
		}
		if weak.Targets[0].Input != "expired.test" || weak.Targets[0].Reason != "SSL grade F" {
			t.Errorf("worst SSL should come first: %+v", weak.Targets)
		}
		if expired.Category != "expired_certs" || expired.Total != 1 || expired.Targets[0].Input != "expired.test" {
			t.Errorf("expired group = %+v", expired)
		}
	})

	t.Run("find_issues expiring window", func(t *testing.T) {
		res := call(t, cs, "find_issues", map[string]any{"categories": []string{"expiring_certs"}, "expiring_within_days": 30})
		var out IssuesOut
		decode(t, res, &out)
		if len(out.Groups) != 1 || out.Groups[0].Total != 2 {
			t.Errorf("expiring_certs = %+v, want the expired and the 5-day certificate", out.Groups)
		}
	})

	t.Run("find_issues open_port", func(t *testing.T) {
		wantErr(t, call(t, cs, "find_issues", map[string]any{"categories": []string{"open_port"}}), "port")
		res := call(t, cs, "find_issues", map[string]any{"categories": []string{"open_port"}, "port": 443})
		var out IssuesOut
		decode(t, res, &out)
		if len(out.Groups) != 1 || out.Groups[0].Total != 1 || out.Groups[0].Targets[0].Input != "example.com" {
			t.Errorf("open_port 443 = %+v", out.Groups)
		}
	})

	t.Run("find_issues default categories skip open_port", func(t *testing.T) {
		res := call(t, cs, "find_issues", nil)
		var out IssuesOut
		decode(t, res, &out)
		var cats []string
		for _, g := range out.Groups {
			cats = append(cats, g.Category)
		}
		want := []string{"weak_ssl", "expiring_certs", "expired_certs", "csp_issues", "unreachable", "unresolved"}
		if !slices.Equal(cats, want) {
			t.Errorf("categories = %v, want %v", cats, want)
		}
	})

	t.Run("find_issues unknown category", func(t *testing.T) {
		wantErr(t, call(t, cs, "find_issues", map[string]any{"categories": []string{"bogus"}}), "categories")
	})

	t.Run("changes_since relative and invalid", func(t *testing.T) {
		res := call(t, cs, "changes_since", map[string]any{"since": "7d"})
		if res.IsError || !strings.Contains(text(res), "added") {
			t.Errorf("changes_since 7d: %s", text(res))
		}
		if !strings.Contains(text(res), "CSP not checked → 2 findings") {
			t.Errorf("changes_since lacks the first CSP result:\n%s", text(res))
		}
		wantErr(t, call(t, cs, "changes_since", map[string]any{"since": "yesterday"}), "since")
	})

	t.Run("list_tags", func(t *testing.T) {
		res := call(t, cs, "list_tags", nil)
		if !strings.Contains(text(res), "prod: 1 target") {
			t.Errorf("list_tags text: %s", text(res))
		}
	})
}

func TestSummarySaysSSLScanningOff(t *testing.T) {
	f := newFixture(t)
	f.seed()
	raw, _ := f.token("viewer@test.com", user.RoleViewer, apitoken.ScopeRead)
	cs := f.connectOffSSL(raw)
	res := call(t, cs, "summary", nil)
	if !strings.Contains(text(res), "SSL scanning is off") {
		t.Errorf("summary text lacks the scanning-off note:\n%s", text(res))
	}
	if strings.Contains(text(res), "SSL not scanned yet") {
		t.Errorf("scanning-off summary names unscanned targets:\n%s", text(res))
	}
}

func TestWriteToolsAuditAsMCP(t *testing.T) {
	f := newFixture(t)
	f.seed()
	f.tag("example.com", "ops") // placeholder so the tag exists before the test attaches it
	raw, admin := f.token("admin@test.com", user.RoleAdmin, apitoken.ScopeWrite)
	cs := f.connect(raw)

	t.Run("add_targets", func(t *testing.T) {
		res := call(t, cs, "add_targets", map[string]any{"inputs": []string{"new.example.net", "example.com", "bad value!"}})
		if res.IsError {
			t.Fatalf("add_targets: %s", text(res))
		}
		var out service.ImportResult
		decode(t, res, &out)
		if !slices.Equal(out.Added, []string{"new.example.net"}) || !slices.Equal(out.Existing, []string{"example.com"}) {
			t.Errorf("added %v existing %v", out.Added, out.Existing)
		}
		if !slices.Equal(out.Invalid, []string{"bad value!"}) {
			t.Errorf("invalid = %v", out.Invalid)
		}
	})

	t.Run("set_tags replace", func(t *testing.T) {
		res := call(t, cs, "set_tags", map[string]any{"target": "example.com", "tags": []string{"prod", "ops"}, "mode": "replace"})
		if res.IsError {
			t.Fatalf("set_tags: %s", text(res))
		}
		var out service.TargetSummary
		decode(t, res, &out)
		if !slices.Equal(slices.Sorted(slices.Values(out.Tags)), []string{"ops", "prod"}) {
			t.Errorf("tags = %v", out.Tags)
		}
	})

	t.Run("set_tags remove", func(t *testing.T) {
		res := call(t, cs, "set_tags", map[string]any{"target": "example.com", "tags": []string{"ops"}, "mode": "remove"})
		var out service.TargetSummary
		decode(t, res, &out)
		if !slices.Equal(out.Tags, []string{"prod"}) {
			t.Errorf("tags after remove = %v", out.Tags)
		}
	})

	t.Run("set_tags without mode adds", func(t *testing.T) {
		res := call(t, cs, "set_tags", map[string]any{"target": "example.com", "tags": []string{"ops"}})
		if res.IsError {
			t.Fatalf("set_tags: %s", text(res))
		}
		var out service.TargetSummary
		decode(t, res, &out)
		if !slices.Equal(slices.Sorted(slices.Values(out.Tags)), []string{"ops", "prod"}) {
			t.Errorf("tags after the default add = %v", out.Tags)
		}
	})

	t.Run("set_tags bad mode", func(t *testing.T) {
		wantErr(t, call(t, cs, "set_tags", map[string]any{"target": "example.com", "tags": []string{}, "mode": "merge"}), "mode")
	})

	t.Run("set_tags unknown tag", func(t *testing.T) {
		wantErr(t, call(t, cs, "set_tags", map[string]any{"target": "example.com", "tags": []string{"nope"}, "mode": "add"}), "tags")
	})

	t.Run("delete and restore by name", func(t *testing.T) {
		res := call(t, cs, "delete_target", map[string]any{"target": "mail.example.org"})
		if res.IsError {
			t.Fatalf("delete_target: %s", text(res))
		}
		if !strings.Contains(text(res), "mail.example.org (#") {
			t.Errorf("delete_target reply does not name the target: %s", text(res))
		}
		listed := call(t, cs, "list_targets", nil)
		if strings.Contains(text(listed), "mail.example.org") {
			t.Errorf("deleted target still listed:\n%s", text(listed))
		}
		wantErr(t, call(t, cs, "delete_target", map[string]any{"target": "mail.example.org"}), "target")

		res = call(t, cs, "restore_target", map[string]any{"target": "mail.example.org"})
		if res.IsError {
			t.Fatalf("restore_target: %s", text(res))
		}
		if !strings.Contains(text(res), "mail.example.org (#") {
			t.Errorf("restore_target reply does not name the target: %s", text(res))
		}
		if listed := call(t, cs, "list_targets", nil); !strings.Contains(text(listed), "mail.example.org") {
			t.Errorf("restored target not listed:\n%s", text(listed))
		}
		wantErr(t, call(t, cs, "restore_target", map[string]any{"target": "example.com"}), "target")
	})

	t.Run("rescan queues then reports cooldown", func(t *testing.T) {
		res := call(t, cs, "rescan", map[string]any{"targets": []string{"example.com", "expired.test"}})
		if res.IsError {
			t.Fatalf("rescan: %s", text(res))
		}
		var out service.RescanResult
		decode(t, res, &out)
		if len(out.Queued) != 2 {
			t.Errorf("queued = %v, want both", out.Queued)
		}
		for _, want := range []string{"queued: example.com (#", "expired.test (#"} {
			if !strings.Contains(text(res), want) {
				t.Errorf("rescan reply does not name the targets: %s", text(res))
			}
		}
		again := call(t, cs, "rescan", map[string]any{"targets": []string{"example.com"}})
		var second service.RescanResult
		decode(t, again, &second)
		if len(second.CoolingDown) != 1 || len(second.Queued) != 0 {
			t.Errorf("second rescan = %+v, want cooling down", second)
		}
		if !strings.Contains(text(again), "cooling down: example.com (#") {
			t.Errorf("cooldown reply does not name the target: %s", text(again))
		}
	})

	t.Run("rescan with an unknown name queues nothing", func(t *testing.T) {
		wantErr(t, call(t, cs, "rescan", map[string]any{"targets": []string{"example.com", "missing.example"}}), "target")
	})

	t.Run("rescan over the cap", func(t *testing.T) {
		many := make([]string, maxRescanTargets+1)
		for i := range many {
			many[i] = "example.com"
		}
		wantErr(t, call(t, cs, "rescan", map[string]any{"targets": many}), "targets")
	})

	rows, err := f.client.AuditEvent.Query().Where(auditevent.SourceEQ(auditevent.SourceMcp)).All(f.ctx)
	f.must(err)
	if len(rows) == 0 {
		t.Fatal("no audit rows with source mcp")
	}
	for _, r := range rows {
		if r.ActorID == nil || *r.ActorID != admin.ID {
			t.Errorf("audit %s: actor %v, want the admin", r.Action, r.ActorID)
		}
		if r.TokenPrefix == "" {
			t.Errorf("audit %s: no token prefix", r.Action)
		}
	}
}

func TestWriteToolsNotCallableWithReadToken(t *testing.T) {
	f := newFixture(t)
	f.seed()
	raw, _ := f.token("viewer@test.com", user.RoleViewer, apitoken.ScopeRead)
	cs := f.connect(raw)

	res, err := cs.CallTool(f.ctx, &mcp.CallToolParams{
		Name:      "add_targets",
		Arguments: map[string]any{"inputs": []string{"sneaky.example"}},
	})
	if err == nil && (res == nil || !res.IsError) {
		t.Fatalf("add_targets with a read token succeeded: %+v", res)
	}
	if n, _ := f.client.Target.Query().Where(target.Input("sneaky.example")).Count(f.ctx); n != 0 {
		t.Error("write went through with a read token")
	}
}

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	good := map[string]time.Time{
		"2026-10-11T00:00:00Z": time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC),
		"24h":                  now.Add(-24 * time.Hour),
		"7d":                   now.Add(-7 * 24 * time.Hour),
		"0":                    now,
	}
	for in, want := range good {
		got, err := parseSince(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("parseSince(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "yesterday", "-5h", "-2d", "2026-10-11"} {
		if _, err := parseSince(in, now); err == nil {
			t.Errorf("parseSince(%q) accepted", in)
		}
	}
}

func TestBearerToken(t *testing.T) {
	tests := map[string]string{
		"Bearer prm_abc":   "prm_abc",
		"bearer  prm_abc ": "prm_abc",
		"Basic dXNlcjpw":   "",
		"Bearer":           "",
		"":                 "",
	}
	for in, want := range tests {
		if got := bearerToken(in); got != want {
			t.Errorf("bearerToken(%q) = %q, want %q", in, got, want)
		}
	}
}
