package notifier_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"perimeter/internal/notifier"
)

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
