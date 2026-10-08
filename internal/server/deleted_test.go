package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/ent/target"
	"perimeter/internal/auth"
	"perimeter/internal/storage"
)

// authedServer builds the real router over the real storage and returns it
// with a session token for a logged-in admin.
func authedServer(t *testing.T) (*Server, *ent.Client, string) {
	t.Helper()
	client := newTestClient(t)
	ctx := context.Background()
	a, err := auth.New(ctx, auth.Config{SessionMaxAge: time.Hour}, client)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	u, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	token, err := a.CreateSession(ctx, u)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	srv := New(storage.NewEntStorage(client), a, client, nil, nil, os.DirFS("../.."), 30*24*time.Hour, 50)
	return srv, client, token
}

// importTargets imports the inputs and returns their ids, looked up before
// any of them are soft-deleted.
func importTargets(t *testing.T, client *ent.Client, inputs ...string) map[string]int {
	t.Helper()
	ctx := context.Background()
	if _, err := storage.NewEntStorage(client).ImportTargets(ctx, inputs); err != nil {
		t.Fatalf("ImportTargets: %v", err)
	}
	ids := make(map[string]int, len(inputs))
	for _, in := range inputs {
		id, err := client.Target.Query().Where(target.InputEQ(in)).OnlyID(ctx)
		if err != nil {
			t.Fatalf("looking up %s: %v", in, err)
		}
		ids[in] = id
	}
	return ids
}

// reply is the part of a response the tests look at. The body is read and
// closed inside authedRequest.
type reply struct {
	StatusCode int
	Location   string
}

// authedRequest sends method path through the real router with the session.
func authedRequest(t *testing.T, srv *Server, token, method, path string) (reply, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: token})
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return reply{StatusCode: resp.StatusCode, Location: resp.Header.Get("Location")}, string(body)
}

func TestDeletedTargetsPageListsDeletedNotLive(t *testing.T) {
	srv, client, token := authedServer(t)
	ids := importTargets(t, client, "live.example", "dead.example")

	resp, _ := authedRequest(t, srv, token, "POST", "/targets/"+strconv.Itoa(ids["dead.example"])+"/delete")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("delete: status %d, want 302", resp.StatusCode)
	}

	resp, body := authedRequest(t, srv, token, "GET", "/targets/deleted")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /targets/deleted: status %d, body:\n%s", resp.StatusCode, body)
	}
	if strings.Contains(body, "template: views/") {
		t.Fatalf("template execution error in output:\n%s", body)
	}
	if !strings.Contains(body, "dead.example") {
		t.Errorf("deleted target missing from /targets/deleted")
	}
	if strings.Contains(body, "live.example") {
		t.Errorf("live target listed on /targets/deleted")
	}
	if !strings.Contains(body, `action="/targets/`+strconv.Itoa(ids["dead.example"])+`/restore"`) {
		t.Errorf("restore form for the deleted target missing")
	}
	if !strings.Contains(body, `action="/targets/`+strconv.Itoa(ids["dead.example"])+`/purge"`) {
		t.Errorf("purge form for the deleted target missing")
	}
}

func TestDeletedTargetsPageEmptyState(t *testing.T) {
	srv, _, token := authedServer(t)

	resp, body := authedRequest(t, srv, token, "GET", "/targets/deleted")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /targets/deleted: status %d", resp.StatusCode)
	}
	if !strings.Contains(body, "No deleted targets.") {
		t.Errorf("empty state text missing")
	}
}

func TestRestoreAndPurgeRoutes(t *testing.T) {
	srv, client, token := authedServer(t)
	ids := importTargets(t, client, "live.example", "dead.example")
	dead := strconv.Itoa(ids["dead.example"])
	live := strconv.Itoa(ids["live.example"])

	// Restore a deleted target: redirects back to the deleted list.
	authedRequest(t, srv, token, "POST", "/targets/"+dead+"/delete")
	resp, _ := authedRequest(t, srv, token, "POST", "/targets/"+dead+"/restore")
	if resp.StatusCode != http.StatusFound || resp.Location != "/targets/deleted" {
		t.Errorf("restore: status %d location %q, want 302 to /targets/deleted", resp.StatusCode, resp.Location)
	}
	if _, body := authedRequest(t, srv, token, "GET", "/"); !strings.Contains(body, "dead.example") {
		t.Errorf("restored target not back on the dashboard")
	}

	// Restoring a live target is a 404.
	if resp, _ := authedRequest(t, srv, token, "POST", "/targets/"+live+"/restore"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("restore live target: status %d, want 404", resp.StatusCode)
	}

	// Purging a live target is a 404, and it stays live.
	if resp, _ := authedRequest(t, srv, token, "POST", "/targets/"+live+"/purge"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("purge live target: status %d, want 404", resp.StatusCode)
	}

	// Purge a deleted target: redirects, and it is gone from the deleted list.
	authedRequest(t, srv, token, "POST", "/targets/"+dead+"/delete")
	resp, _ = authedRequest(t, srv, token, "POST", "/targets/"+dead+"/purge")
	if resp.StatusCode != http.StatusFound || resp.Location != "/targets/deleted" {
		t.Errorf("purge: status %d location %q, want 302 to /targets/deleted", resp.StatusCode, resp.Location)
	}
	if _, body := authedRequest(t, srv, token, "GET", "/targets/deleted"); strings.Contains(body, "dead.example") {
		t.Errorf("purged target still listed as deleted")
	}
	// Purging it again finds nothing.
	if resp, _ := authedRequest(t, srv, token, "POST", "/targets/"+dead+"/purge"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("purge purged target: status %d, want 404", resp.StatusCode)
	}

	if resp, _ := authedRequest(t, srv, token, "POST", "/targets/abc/restore"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("restore bad id: status %d, want 400", resp.StatusCode)
	}
	if resp, _ := authedRequest(t, srv, token, "POST", "/targets/abc/purge"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("purge bad id: status %d, want 400", resp.StatusCode)
	}
}

func TestDeleteUnknownTargetIs404(t *testing.T) {
	srv, _, token := authedServer(t)

	resp, _ := authedRequest(t, srv, token, "POST", "/targets/9999/delete")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("delete unknown target: status %d, want 404", resp.StatusCode)
	}
	resp, _ = authedRequest(t, srv, token, "POST", "/targets/abc/delete")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("delete bad id: status %d, want 400", resp.StatusCode)
	}
}

func TestDashboardDeletedTargetsLink(t *testing.T) {
	const link = "Deleted targets (1)"

	srv, client, token := authedServer(t)
	ids := importTargets(t, client, "live.example", "dead.example")

	_, body := authedRequest(t, srv, token, "GET", "/")
	if strings.Contains(body, "Deleted targets (") {
		t.Errorf("dashboard shows deleted link with nothing deleted")
	}

	authedRequest(t, srv, token, "POST", "/targets/"+strconv.Itoa(ids["dead.example"])+"/delete")
	resp, body := authedRequest(t, srv, token, "GET", "/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /: status %d", resp.StatusCode)
	}
	if !strings.Contains(body, link) || !strings.Contains(body, `href="/targets/deleted"`) {
		t.Errorf("dashboard missing %q link after a delete", link)
	}
	if !strings.Contains(body, "It can be restored from Deleted targets.") {
		t.Errorf("delete confirm text not updated")
	}
}
