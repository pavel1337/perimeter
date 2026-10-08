package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/internal/auth"
	"perimeter/internal/importer"
	"perimeter/internal/notifier"
	"perimeter/internal/storage"
)

// fakeEmailFactory stands in for the real SMTP factory. It only checks that
// the config names at least one recipient.
func fakeEmailFactory(config json.RawMessage) (notifier.Notifier, error) {
	var cfg struct {
		To []string `json:"to"`
	}
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, err
	}
	if len(cfg.To) == 0 {
		return nil, errors.New("email: at least one recipient is required")
	}
	return nil, nil
}

// notifierServer is authedServer with a notifier registry holding the real
// webhook factory and a fake email factory.
func notifierServer(t *testing.T) (*Server, *ent.Client, string) {
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
	reg := notifier.NewRegistry()
	reg.Register("webhook", notifier.NewWebhookFactory())
	reg.Register("email", fakeEmailFactory)
	// The settings page lists importer providers too, so it needs a registry.
	srv := New(storage.NewEntStorage(client), a, client, importer.NewRegistry(), reg, os.DirFS("../.."), 30*24*time.Hour, 50)
	return srv, client, token
}

// createNotifierForm builds the form the settings page posts for a notifier.
func createNotifierForm(provider, config string, events ...string) url.Values {
	form := url.Values{}
	form.Set("provider", provider)
	form.Set("config", config)
	for _, e := range events {
		form.Add("events", e)
	}
	return form
}

// allEventValues returns every event type as form values.
func allEventValues() []string {
	out := make([]string, 0, len(notifier.AllEventTypes()))
	for _, t := range notifier.AllEventTypes() {
		out = append(out, string(t))
	}
	return out
}

func TestCreateEmailNotifierWithSelectedEvents(t *testing.T) {
	srv, client, token := notifierServer(t)
	ctx := context.Background()

	resp := postForm(t, srv, token, "/notifiers", createNotifierForm(
		"email",
		`{"to":["oncall@example.com"]}`,
		string(notifier.EventSSLGradeDrop),
		string(notifier.EventCertExpiring),
	))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d, want 302; body:\n%s", resp.StatusCode, resp.Body)
	}

	cfgs, err := client.NotifierConfig.Query().All(ctx)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(cfgs) != 1 {
		t.Fatalf("got %d notifiers, want 1", len(cfgs))
	}
	cfg := cfgs[0]
	if cfg.Provider.String() != "email" {
		t.Errorf("provider %q, want email", cfg.Provider)
	}
	want := []string{string(notifier.EventSSLGradeDrop), string(notifier.EventCertExpiring)}
	if !slices.Equal(cfg.Events, want) {
		t.Errorf("events %v, want %v", cfg.Events, want)
	}
	if !cfg.Enabled {
		t.Error("new notifier should be enabled")
	}
}

func TestCreateWebhookNotifierAllEventsStoresNil(t *testing.T) {
	srv, client, token := notifierServer(t)
	ctx := context.Background()

	resp := postForm(t, srv, token, "/notifiers", createNotifierForm(
		"webhook",
		`{"url":"https://example.com/hook"}`,
		allEventValues()...,
	))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d, want 302; body:\n%s", resp.StatusCode, resp.Body)
	}

	cfg, err := client.NotifierConfig.Query().Only(ctx)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if cfg.Events != nil {
		t.Errorf("events %v, want nil (all events)", cfg.Events)
	}
}

func TestCreateNotifierRejectsBadInput(t *testing.T) {
	tests := []struct {
		name    string
		form    url.Values
		wantMsg string
	}{
		{
			name:    "unknown event",
			form:    createNotifierForm("webhook", `{"url":"https://example.com/hook"}`, "ssl_bogus"),
			wantMsg: "unknown event type: ssl_bogus",
		},
		{
			name:    "no events selected",
			form:    createNotifierForm("webhook", `{"url":"https://example.com/hook"}`),
			wantMsg: "select at least one event type",
		},
		{
			name:    "invalid webhook config",
			form:    createNotifierForm("webhook", `{"url":""}`, allEventValues()...),
			wantMsg: "Invalid notifier config",
		},
		{
			name:    "email without recipients",
			form:    createNotifierForm("email", `{"to":[]}`, allEventValues()...),
			wantMsg: "at least one recipient is required",
		},
		{
			name:    "unknown provider",
			form:    createNotifierForm("pagerduty", `{}`, allEventValues()...),
			wantMsg: "unknown notifier provider",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, client, token := notifierServer(t)

			resp := postForm(t, srv, token, "/notifiers", tt.form)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d, want 200 with the settings page; body:\n%s", resp.StatusCode, resp.Body)
			}
			if !strings.Contains(resp.Body, tt.wantMsg) {
				t.Errorf("page does not show %q", tt.wantMsg)
			}
			n, err := client.NotifierConfig.Query().Count(context.Background())
			if err != nil {
				t.Fatalf("count: %v", err)
			}
			if n != 0 {
				t.Errorf("%d notifiers stored after rejected input, want 0", n)
			}
		})
	}
}

func TestSettingsShowsNotifierEvents(t *testing.T) {
	srv, client, token := notifierServer(t)
	ctx := context.Background()
	if _, err := client.NotifierConfig.Create().
		SetProvider("webhook").
		SetConfig([]byte(`{"url":"https://example.com/hook"}`)).
		SetEnabled(true).
		SetEvents([]string{string(notifier.EventCSPIssues)}).
		Save(ctx); err != nil {
		t.Fatalf("create: %v", err)
	}

	resp := send(t, srv, token, "GET", "/settings", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	for _, label := range []string{"CSP issues", "SSL grade drop", "Certificate expiring", "New open ports"} {
		if !strings.Contains(resp.Body, label) {
			t.Errorf("settings page missing event label %q", label)
		}
	}
}
