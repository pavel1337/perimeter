package notifier_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/ent/enttest"
	"perimeter/internal/notifier"

	sqlite "modernc.org/sqlite"
)

// ent opens the "sqlite3" driver name; modernc registers itself as "sqlite".
func init() { sql.Register("sqlite3", &sqlite.Driver{}) }

func TestWebhookNotify(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	factory := notifier.NewWebhookFactory()
	cfg, _ := json.Marshal(map[string]string{"url": srv.URL})
	n, err := factory(cfg)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	event := notifier.Event{
		Type:      notifier.EventNewOpenPorts,
		Target:    "1.2.3.4",
		Message:   "New open ports: 22, 80",
		Timestamp: time.Now(),
	}

	err = n.Notify(context.Background(), event)
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}

	if len(received) == 0 {
		t.Fatal("expected webhook to receive data")
	}

	var payload map[string]any
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if payload["event"] != string(notifier.EventNewOpenPorts) {
		t.Errorf("expected event type %s, got %v", notifier.EventNewOpenPorts, payload["event"])
	}
	if payload["target"] != "1.2.3.4" {
		t.Errorf("expected target 1.2.3.4, got %v", payload["target"])
	}
}

func TestWebhookInvalidURL(t *testing.T) {
	factory := notifier.NewWebhookFactory()
	cfg, _ := json.Marshal(map[string]string{"url": ""})
	_, err := factory(cfg)
	if err == nil {
		t.Error("expected error for empty URL")
	}
}

func TestRegistryGetUnknown(t *testing.T) {
	reg := notifier.NewRegistry()
	_, err := reg.Get("nonexistent", nil)
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}

func TestAllEventTypes(t *testing.T) {
	want := []notifier.EventType{
		notifier.EventNewOpenPorts,
		notifier.EventSSLGradeDrop,
		notifier.EventCertExpiring,
		notifier.EventCSPIssues,
	}
	if got := notifier.AllEventTypes(); !slices.Equal(got, want) {
		t.Errorf("AllEventTypes() = %v, want %v", got, want)
	}
}

func TestRegistryListSorted(t *testing.T) {
	reg := notifier.NewRegistry()
	reg.Register("webhook", notifier.NewWebhookFactory())
	reg.Register("email", notifier.NewWebhookFactory())
	if got, want := reg.List(), []string{"email", "webhook"}; !slices.Equal(got, want) {
		t.Errorf("List() = %v, want %v", got, want)
	}
}

// recorder collects the events a fake notifier was asked to send, keyed by
// the name in its config.
type recorder struct {
	got map[string][]notifier.EventType
}

type fakeNotifier struct {
	name string
	rec  *recorder
}

func (f *fakeNotifier) Name() string { return f.name }

func (f *fakeNotifier) Notify(_ context.Context, event notifier.Event) error {
	f.rec.got[f.name] = append(f.rec.got[f.name], event.Type)
	return nil
}

func newDispatchTest(t *testing.T) (*ent.Client, *notifier.Dispatcher, *recorder) {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:notifier_dispatch?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	t.Cleanup(func() { client.Close() })

	rec := &recorder{got: map[string][]notifier.EventType{}}
	reg := notifier.NewRegistry()
	fake := func(config json.RawMessage) (notifier.Notifier, error) {
		var cfg struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, err
		}
		return &fakeNotifier{name: cfg.Name, rec: rec}, nil
	}
	reg.Register("webhook", fake)
	reg.Register("email", fake)
	return client, notifier.NewDispatcher(client, reg), rec
}

func createFakeConfig(t *testing.T, client *ent.Client, name string, enabled bool, events []string) {
	t.Helper()
	cfg, _ := json.Marshal(map[string]string{"name": name})
	create := client.NotifierConfig.Create().
		SetProvider("webhook").
		SetConfig(cfg).
		SetEnabled(enabled)
	if events != nil {
		create.SetEvents(events)
	}
	if _, err := create.Save(context.Background()); err != nil {
		t.Fatalf("create notifier %s: %v", name, err)
	}
}

func TestDispatchFiltersByEvents(t *testing.T) {
	client, d, rec := newDispatchTest(t)
	createFakeConfig(t, client, "grade-only", true, []string{string(notifier.EventSSLGradeDrop)})
	createFakeConfig(t, client, "all", true, nil)

	ctx := context.Background()
	d.Dispatch(ctx, notifier.Event{Type: notifier.EventSSLGradeDrop, Target: "a.example.com", Timestamp: time.Now()})
	d.Dispatch(ctx, notifier.Event{Type: notifier.EventNewOpenPorts, Target: "a.example.com", Timestamp: time.Now()})

	if got, want := rec.got["grade-only"], []notifier.EventType{notifier.EventSSLGradeDrop}; !slices.Equal(got, want) {
		t.Errorf("grade-only received %v, want %v", got, want)
	}
	if got, want := rec.got["all"], []notifier.EventType{notifier.EventSSLGradeDrop, notifier.EventNewOpenPorts}; !slices.Equal(got, want) {
		t.Errorf("all received %v, want %v", got, want)
	}
}

func TestDispatchSkipsDisabled(t *testing.T) {
	client, d, rec := newDispatchTest(t)
	createFakeConfig(t, client, "off", false, nil)

	d.Dispatch(context.Background(), notifier.Event{Type: notifier.EventCSPIssues, Timestamp: time.Now()})

	if got := rec.got["off"]; len(got) != 0 {
		t.Errorf("disabled notifier received %v, want nothing", got)
	}
}
