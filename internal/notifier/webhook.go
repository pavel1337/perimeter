package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type WebhookConfig struct {
	URL string `json:"url"`
}

type WebhookNotifier struct {
	config WebhookConfig
	client *http.Client
}

func NewWebhookFactory() Factory {
	return func(config json.RawMessage) (Notifier, error) {
		var cfg WebhookConfig
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, fmt.Errorf("invalid webhook config: %w", err)
		}
		if cfg.URL == "" {
			return nil, fmt.Errorf("webhook: url is required")
		}
		return &WebhookNotifier{
			config: cfg,
			client: &http.Client{Timeout: 10 * time.Second},
		}, nil
	}
}

func (w *WebhookNotifier) Name() string {
	return "webhook"
}

type webhookPayload struct {
	Event     EventType      `json:"event"`
	Target    string         `json:"target"`
	Message   string         `json:"message"`
	Details   map[string]any `json:"details,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}

func (w *WebhookNotifier) Notify(ctx context.Context, event Event) error {
	payload := webhookPayload{
		Event:     event.Type,
		Target:    event.Target,
		Message:   event.Message,
		Details:   event.Details,
		Timestamp: event.Timestamp,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook: marshal error: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.config.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: request error: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: send error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook: server returned %d", resp.StatusCode)
	}
	return nil
}
