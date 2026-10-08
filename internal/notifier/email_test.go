package notifier_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"perimeter/internal/mail"
	"perimeter/internal/notifier"
)

type recordingSender struct {
	msgs []mail.Message
}

func (r *recordingSender) Send(_ context.Context, m mail.Message) error {
	r.msgs = append(r.msgs, m)
	return nil
}

func emailConfig(t *testing.T, to ...string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(notifier.EmailConfig{To: to})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEmailFactoryValidation(t *testing.T) {
	factory := notifier.NewEmailFactory(&recordingSender{})

	if _, err := factory(json.RawMessage(`{"to": `)); err == nil {
		t.Error("expected error for bad JSON")
	}
	if _, err := factory(emailConfig(t)); err == nil {
		t.Error("expected error for no recipients")
	}
	if _, err := factory(emailConfig(t, "  ", "")); err == nil {
		t.Error("expected error for blank recipients")
	}
	if _, err := factory(emailConfig(t, "not an address")); err == nil {
		t.Error("expected error for invalid address")
	}
	if _, err := notifier.NewEmailFactory(nil)(emailConfig(t, "a@example.com")); err == nil {
		t.Error("expected error when SMTP is not configured")
	}
}

func TestEmailFactoryTrimsAndDedupes(t *testing.T) {
	sender := &recordingSender{}
	n, err := notifier.NewEmailFactory(sender)(emailConfig(t, " a@example.com ", "A@example.com", "", "b@example.com"))
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if n.Name() != "email" {
		t.Errorf("Name() = %q", n.Name())
	}

	err = n.Notify(context.Background(), notifier.Event{Type: notifier.EventCSPIssues, Target: "x.com", Message: "m"})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if len(sender.msgs) != 1 {
		t.Fatalf("sent %d messages, want 1", len(sender.msgs))
	}
	got := sender.msgs[0].To
	if len(got) != 2 || got[0] != "a@example.com" || got[1] != "b@example.com" {
		t.Errorf("recipients = %q", got)
	}
}

func notifyEvent(t *testing.T, event notifier.Event) mail.Message {
	t.Helper()
	sender := &recordingSender{}
	n, err := notifier.NewEmailFactory(sender)(emailConfig(t, "ops@example.com"))
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if err := n.Notify(context.Background(), event); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if len(sender.msgs) != 1 {
		t.Fatalf("sent %d messages, want 1", len(sender.msgs))
	}
	return sender.msgs[0]
}

func assertContains(t *testing.T, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Errorf("%q does not contain %q", s, sub)
		}
	}
}

var testTime = time.Date(2026, 10, 8, 12, 30, 0, 0, time.UTC)

func TestEmailNewOpenPorts(t *testing.T) {
	msg := notifyEvent(t, notifier.Event{
		Type:      notifier.EventNewOpenPorts,
		Target:    "1.2.3.4",
		Message:   "New open ports: 22, 8080",
		Details:   map[string]any{"new_ports": []int{22, 8080}, "all_ports": []int{22, 80, 8080}},
		Timestamp: testTime,
	})
	if msg.Subject != "[perimeter] New open ports: 1.2.3.4" {
		t.Errorf("subject = %q", msg.Subject)
	}
	assertContains(t, msg.Body, "New open ports: 22, 8080", "New ports: 22, 8080", "All open ports: 22, 80, 8080", "Time: Thu, 08 Oct 2026 12:30:00 UTC")
}

func TestEmailSSLGradeDrop(t *testing.T) {
	msg := notifyEvent(t, notifier.Event{
		Type:      notifier.EventSSLGradeDrop,
		Target:    "example.com",
		Message:   "SSL grade dropped from A to B",
		Details:   map[string]any{"previous_grade": "A", "new_grade": "B"},
		Timestamp: testTime,
	})
	if msg.Subject != "[perimeter] SSL grade dropped: example.com" {
		t.Errorf("subject = %q", msg.Subject)
	}
	assertContains(t, msg.Body, "SSL grade dropped from A to B", "Previous grade: A", "New grade: B")
}

func TestEmailCertExpiring(t *testing.T) {
	msg := notifyEvent(t, notifier.Event{
		Type:    notifier.EventCertExpiring,
		Target:  "example.com",
		Message: "Certificate expires in 7 days",
		Details: map[string]any{
			"cert_expiry":  testTime.Add(7 * 24 * time.Hour),
			"cert_subject": "CN=example.com",
		},
		Timestamp: testTime,
	})
	if msg.Subject != "[perimeter] Certificate expiring: example.com" {
		t.Errorf("subject = %q", msg.Subject)
	}
	assertContains(t, msg.Body, "Certificate expires in 7 days", "Certificate: CN=example.com", "Expires: Thu, 15 Oct 2026 12:30:00 UTC")
}

func TestEmailCertExpiringStringExpiry(t *testing.T) {
	msg := notifyEvent(t, notifier.Event{
		Type:      notifier.EventCertExpiring,
		Target:    "example.com",
		Message:   "Certificate expires soon",
		Details:   map[string]any{"cert_expiry": "2026-10-15"},
		Timestamp: testTime,
	})
	assertContains(t, msg.Body, "Expires: 2026-10-15")
}

func TestEmailCSPIssues(t *testing.T) {
	msg := notifyEvent(t, notifier.Event{
		Type:      notifier.EventCSPIssues,
		Target:    "example.com",
		Message:   "CSP has 3 issues",
		Details:   map[string]any{"findings_count": 3},
		Timestamp: testTime,
	})
	if msg.Subject != "[perimeter] CSP issues: example.com" {
		t.Errorf("subject = %q", msg.Subject)
	}
	assertContains(t, msg.Body, "CSP has 3 issues", "Findings: 3")
}

func TestEmailUnknownTypeFallsBack(t *testing.T) {
	msg := notifyEvent(t, notifier.Event{
		Type:      notifier.EventType("custom_thing"),
		Target:    "example.com",
		Message:   "Something happened",
		Details:   map[string]any{"zeta": "last", "alpha": 1},
		Timestamp: testTime,
	})
	if msg.Subject != "[perimeter] custom_thing: example.com" {
		t.Errorf("subject = %q", msg.Subject)
	}
	assertContains(t, msg.Body, "Something happened", "alpha: 1", "zeta: last")
	if strings.Index(msg.Body, "alpha: 1") > strings.Index(msg.Body, "zeta: last") {
		t.Errorf("details not sorted by key:\n%s", msg.Body)
	}
}

func TestEmailSubjectHasNoLineBreaks(t *testing.T) {
	msg := notifyEvent(t, notifier.Event{
		Type:      notifier.EventCSPIssues,
		Target:    "evil.com\r\nBcc: victim@example.com",
		Message:   "m",
		Timestamp: testTime,
	})
	if strings.ContainsAny(msg.Subject, "\r\n") {
		t.Errorf("subject contains line break: %q", msg.Subject)
	}
	assertContains(t, msg.Subject, "evil.com  Bcc: victim@example.com")
}
