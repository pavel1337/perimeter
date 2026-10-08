package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	netmail "net/mail"
	"strings"
	"text/template"
	"time"

	"perimeter/internal/mail"
)

type EmailConfig struct {
	To []string `json:"to"`
}

type EmailNotifier struct {
	config EmailConfig
	sender mail.Sender
}

// NewEmailFactory returns a factory for email notifiers that send through sender.
func NewEmailFactory(sender mail.Sender) Factory {
	return func(config json.RawMessage) (Notifier, error) {
		var cfg EmailConfig
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, fmt.Errorf("invalid email config: %w", err)
		}
		if sender == nil {
			return nil, errors.New("email: SMTP is not configured (set SMTP_HOST)")
		}
		to, err := cleanRecipients(cfg.To)
		if err != nil {
			return nil, err
		}
		cfg.To = to
		return &EmailNotifier{config: cfg, sender: sender}, nil
	}
}

// cleanRecipients trims, validates and dedupes recipient addresses.
func cleanRecipients(in []string) ([]string, error) {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, addr := range in {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if _, err := netmail.ParseAddress(addr); err != nil {
			return nil, fmt.Errorf("email: invalid recipient %q: %w", addr, err)
		}
		key := strings.ToLower(addr)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, addr)
	}
	if len(out) == 0 {
		return nil, errors.New("email: at least one recipient is required")
	}
	return out, nil
}

func (e *EmailNotifier) Name() string {
	return "email"
}

// emailData is what the subject and body templates render from.
type emailData struct {
	Type    EventType
	Target  string
	Message string
	Details map[string]any
	Time    string
}

type emailTemplate struct {
	subject *template.Template
	body    *template.Template
}

const emailFooter = "\nTime: {{.Time}}\n"

// emailFuncs holds the helpers the templates use.
var emailFuncs = template.FuncMap{"detail": detail}

// detail renders one detail value as text, or "" if it is missing or empty.
func detail(details map[string]any, key string) string {
	switch v := details[key].(type) {
	case nil:
		return ""
	case []int:
		parts := make([]string, len(v))
		for i, n := range v {
			parts[i] = fmt.Sprint(n)
		}
		return strings.Join(parts, ", ")
	case time.Time:
		return v.UTC().Format(time.RFC1123)
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}

func parseEmailTemplate(subject, body string) emailTemplate {
	return emailTemplate{
		subject: template.Must(template.New("subject").Funcs(emailFuncs).Parse(subject)),
		body:    template.Must(template.New("body").Funcs(emailFuncs).Parse(body + emailFooter)),
	}
}

var emailTemplates = map[EventType]emailTemplate{
	EventNewOpenPorts: parseEmailTemplate(
		"[perimeter] New open ports: {{.Target}}",
		`{{.Message}}

{{with detail .Details "new_ports"}}New ports: {{.}}
{{end}}{{with detail .Details "all_ports"}}All open ports: {{.}}
{{end}}`),
	EventSSLGradeDrop: parseEmailTemplate(
		"[perimeter] SSL grade dropped: {{.Target}}",
		`{{.Message}}

{{with detail .Details "previous_grade"}}Previous grade: {{.}}
{{end}}{{with detail .Details "new_grade"}}New grade: {{.}}
{{end}}`),
	EventCertExpiring: parseEmailTemplate(
		"[perimeter] Certificate expiring: {{.Target}}",
		`{{.Message}}

{{with detail .Details "cert_subject"}}Certificate: {{.}}
{{end}}{{with detail .Details "cert_expiry"}}Expires: {{.}}
{{end}}`),
	EventCSPIssues: parseEmailTemplate(
		"[perimeter] CSP issues: {{.Target}}",
		`{{.Message}}

{{with detail .Details "findings_count"}}Findings: {{.}}
{{end}}`),
}

// genericEmailTemplate covers event types without a dedicated template.
var genericEmailTemplate = parseEmailTemplate(
	"[perimeter] {{.Type}}: {{.Target}}",
	`{{.Message}}

{{range $k, $v := .Details}}{{$k}}: {{detail $.Details $k}}
{{end}}`)

var lineBreaks = strings.NewReplacer("\r", " ", "\n", " ")

func (e *EmailNotifier) Notify(ctx context.Context, event Event) error {
	tmpl, ok := emailTemplates[event.Type]
	if !ok {
		tmpl = genericEmailTemplate
	}
	ts := event.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	data := emailData{
		Type:    event.Type,
		Target:  event.Target,
		Message: event.Message,
		Details: event.Details,
		Time:    ts.UTC().Format(time.RFC1123),
	}

	var subject, body bytes.Buffer
	if err := tmpl.subject.Execute(&subject, data); err != nil {
		return fmt.Errorf("email: render subject: %w", err)
	}
	if err := tmpl.body.Execute(&body, data); err != nil {
		return fmt.Errorf("email: render body: %w", err)
	}

	return e.sender.Send(ctx, mail.Message{
		To:      e.config.To,
		Subject: lineBreaks.Replace(subject.String()),
		Body:    body.String(),
	})
}
