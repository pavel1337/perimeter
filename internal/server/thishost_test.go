package server

import (
	"context"
	"strconv"
	"strings"
	"testing"
)

// An address of the machine Perimeter runs on is marked "this host" on the
// dashboard and the target page (issue #79). Loopback counts as local.
func TestThisHostIsMarked(t *testing.T) {
	srv, client, token := authedServer(t)
	ctx := context.Background()
	local, err := client.Target.Create().SetInput("self.example").SetReachability("ok").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.IP.Create().SetAddress("127.0.0.1").AddTargetIDs(local.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}
	remote, err := client.Target.Create().SetInput("remote.example").SetReachability("ok").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.IP.Create().SetAddress("192.0.2.44").AddTargetIDs(remote.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}

	if page := send(t, srv, token, "GET", "/targets/"+strconv.Itoa(local.ID), "", ""); !strings.Contains(page.Body, ">this host<") {
		t.Error("target page for a local address lacks the this-host mark")
	}
	if page := send(t, srv, token, "GET", "/targets/"+strconv.Itoa(remote.ID), "", ""); strings.Contains(page.Body, ">this host<") {
		t.Error("a remote address is marked this host")
	}
	dash := send(t, srv, token, "GET", "/", "", "")
	row := dash.Body[strings.Index(dash.Body, "self.example"):]
	if !strings.Contains(row[:600], ">this host<") {
		t.Error("dashboard row lacks the this-host mark")
	}
}
