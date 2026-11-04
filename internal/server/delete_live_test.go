package server

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// The bulk delete confirmation names the targets that still answered, and
// the deleted page shows the last state with a filter for them (#77).
func TestDeleteWarnsAboutLiveTargets(t *testing.T) {
	srv, client, token := authedServer(t)
	ctx := context.Background()
	live, err := client.Target.Create().SetInput("live.example").SetReachability("ok").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dead, err := client.Target.Create().SetInput("dead.example").SetReachability("unreachable").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"ids": {strconv.Itoa(live.ID), strconv.Itoa(dead.ID)}}
	resp := send(t, srv, token, "POST", "/targets/bulk/delete", "application/x-www-form-urlencoded", form.Encode())
	if resp.StatusCode != 200 {
		t.Fatalf("confirm page: status %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Body, "1 of these answered in their last scan") || !strings.Contains(resp.Body, "live.example") {
		t.Errorf("confirmation lacks the live warning:\n%s", resp.Body)
	}
	warning := resp.Body[strings.Index(resp.Body, "answered in their last scan"):strings.Index(resp.Body, "<table>")]
	if strings.Contains(warning, "dead.example") {
		t.Error("the unreachable target is listed as live")
	}

	form.Set("confirm", "1")
	if r := send(t, srv, token, "POST", "/targets/bulk/delete", "application/x-www-form-urlencoded", form.Encode()); r.StatusCode != 303 {
		t.Fatalf("delete: status %d", r.StatusCode)
	}
	all := send(t, srv, token, "GET", "/targets/deleted", "", "")
	if !strings.Contains(all.Body, "live.example") || !strings.Contains(all.Body, "dead.example") || !strings.Contains(all.Body, "Last state") {
		t.Errorf("deleted page lacks targets or the state column")
	}
	onlyLive := send(t, srv, token, "GET", "/targets/deleted?state=ok", "", "")
	if !strings.Contains(onlyLive.Body, "live.example") || strings.Contains(onlyLive.Body, "dead.example") {
		t.Errorf("?state=ok should list only live.example")
	}
}
