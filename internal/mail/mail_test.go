package mail

import (
	"bufio"
	"context"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func TestNewSMTPSenderValidation(t *testing.T) {
	valid := Config{Host: "smtp.example.com", Port: 587, From: "Perimeter <noreply@example.com>", TLS: TLSStartTLS}
	tests := map[string]func(c *Config){
		"empty host":     func(c *Config) { c.Host = "" },
		"zero port":      func(c *Config) { c.Port = 0 },
		"empty from":     func(c *Config) { c.From = "" },
		"invalid from":   func(c *Config) { c.From = "not an address" },
		"unknown tls":    func(c *Config) { c.TLS = "ssl3" },
		"from with crlf": func(c *Config) { c.From = "a@example.com\r\nBcc: x@example.com" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			mutate(&cfg)
			if _, err := NewSMTPSender(cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}

	s, err := NewSMTPSender(Config{Host: "h", Port: 25, From: "a@example.com"})
	if err != nil {
		t.Fatalf("empty TLS should be accepted: %v", err)
	}
	if s.cfg.TLS != TLSStartTLS {
		t.Errorf("TLS = %q, want %q", s.cfg.TLS, TLSStartTLS)
	}
}

func TestConfigFromEnv(t *testing.T) {
	env := map[string]string{
		"SMTP_HOST":     "smtp.example.com",
		"SMTP_USERNAME": "user",
		"SMTP_PASSWORD": "secret",
		"SMTP_FROM":     "noreply@example.com",
	}
	get := func(k string) string { return env[k] }

	cfg, err := ConfigFromEnv(get)
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if cfg.Port != 587 || cfg.TLS != TLSStartTLS {
		t.Errorf("defaults: port=%d tls=%q", cfg.Port, cfg.TLS)
	}
	if cfg.Host != "smtp.example.com" || cfg.Username != "user" || cfg.Password != "secret" || cfg.From != "noreply@example.com" {
		t.Errorf("unexpected config: %+v", cfg)
	}
	if !cfg.Enabled() {
		t.Error("expected Enabled")
	}

	env["SMTP_PORT"] = "465"
	env["SMTP_TLS"] = "tls"
	cfg, err = ConfigFromEnv(get)
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if cfg.Port != 465 || cfg.TLS != TLSImplicit {
		t.Errorf("port=%d tls=%q", cfg.Port, cfg.TLS)
	}

	env["SMTP_PORT"] = "abc"
	if _, err := ConfigFromEnv(get); err == nil {
		t.Error("expected error for non-integer port")
	}

	if (Config{}).Enabled() {
		t.Error("empty config should not be Enabled")
	}
}

func TestSendRejectsHeaderInjection(t *testing.T) {
	// Validation runs before any dial, so the unreachable port is never used.
	s, err := NewSMTPSender(Config{Host: "127.0.0.1", Port: 1, From: "a@example.com", TLS: TLSNone})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tests := map[string]Message{
		"subject newline":   {To: []string{"b@example.com"}, Subject: "hi\r\nBcc: x@example.com", Body: "x"},
		"recipient newline": {To: []string{"b@example.com\r\nBcc: x@example.com"}, Subject: "hi", Body: "x"},
		"no recipients":     {Subject: "hi", Body: "x"},
		"invalid recipient": {To: []string{"nope"}, Subject: "hi", Body: "x"},
	}
	for name, m := range tests {
		t.Run(name, func(t *testing.T) {
			if err := s.Send(ctx, m); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// fakeSMTP is a minimal SMTP server that accepts one session and records it.
type fakeSMTP struct {
	ln        net.Listener
	starttls  bool
	from      string
	rcpts     []string
	data      string
	sessionOK chan struct{}
}

func newFakeSMTP(t *testing.T, starttls bool) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, starttls: starttls, sessionOK: make(chan struct{})}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeSMTP) port() int {
	return f.ln.Addr().(*net.TCPAddr).Port
}

func (f *fakeSMTP) serve() {
	defer close(f.sessionOK)
	conn, err := f.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	write := func(s string) { _, _ = io.WriteString(conn, s+"\r\n") }

	write("220 fake.local ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			if f.starttls {
				write("250-fake.local")
				write("250 STARTTLS")
			} else {
				write("250 fake.local")
			}
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			f.from = addrArg(line)
			write("250 OK")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			f.rcpts = append(f.rcpts, addrArg(line))
			write("250 OK")
		case cmd == "DATA":
			write("354 go ahead")
			var sb strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				sb.WriteString(l)
			}
			f.data = sb.String()
			write("250 queued")
		case cmd == "QUIT":
			write("221 bye")
			return
		default:
			write("502 unsupported")
		}
	}
}

func addrArg(line string) string {
	i := strings.Index(line, "<")
	j := strings.LastIndex(line, ">")
	if i < 0 || j < i {
		return ""
	}
	return line[i+1 : j]
}

func TestSendEndToEnd(t *testing.T) {
	srv := newFakeSMTP(t, false)
	s, err := NewSMTPSender(Config{
		Host: "127.0.0.1", Port: srv.port(), From: "Perimeter <noreply@example.com>", TLS: TLSNone,
	})
	if err != nil {
		t.Fatal(err)
	}

	subject := "Grade dropped — ä"
	body := "Line one\nLine two with ümlaut\n"
	err = s.Send(context.Background(), Message{
		To:      []string{"alice@example.org", "Bob <bob@example.org>"},
		Subject: subject,
		Body:    body,
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	<-srv.sessionOK

	if srv.from != "noreply@example.com" {
		t.Errorf("envelope from = %q", srv.from)
	}
	if len(srv.rcpts) != 2 || srv.rcpts[0] != "alice@example.org" || srv.rcpts[1] != "bob@example.org" {
		t.Errorf("envelope rcpts = %v", srv.rcpts)
	}

	msg, err := mail.ReadMessage(strings.NewReader(srv.data))
	if err != nil {
		t.Fatalf("parse message: %v", err)
	}
	dec := new(mime.WordDecoder)
	gotSubject, err := dec.DecodeHeader(msg.Header.Get("Subject"))
	if err != nil {
		t.Fatalf("decode subject: %v", err)
	}
	if gotSubject != subject {
		t.Errorf("subject = %q, want %q", gotSubject, subject)
	}
	if from, err := mail.ParseAddress(msg.Header.Get("From")); err != nil || from.Address != "noreply@example.com" || from.Name != "Perimeter" {
		t.Errorf("From = %q (%v)", msg.Header.Get("From"), err)
	}
	if got := msg.Header.Get("To"); !strings.Contains(got, "alice@example.org") || !strings.Contains(got, "bob@example.org") {
		t.Errorf("To = %q", got)
	}
	if msg.Header.Get("Date") == "" || msg.Header.Get("Message-ID") == "" {
		t.Error("missing Date or Message-ID")
	}
	if got := msg.Header.Get("Content-Transfer-Encoding"); got != "quoted-printable" {
		t.Errorf("Content-Transfer-Encoding = %q", got)
	}
	gotBody, err := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if strings.ReplaceAll(string(gotBody), "\r\n", "\n") != body {
		t.Errorf("body = %q, want %q", gotBody, body)
	}
}

func TestSendStartTLSRequiresExtension(t *testing.T) {
	srv := newFakeSMTP(t, false)
	s, err := NewSMTPSender(Config{
		Host: "127.0.0.1", Port: srv.port(), From: "noreply@example.com", TLS: TLSStartTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = s.Send(context.Background(), Message{To: []string{"alice@example.org"}, Subject: "hi", Body: "x"})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("expected STARTTLS error, got %v", err)
	}
}

func TestSendHonorsContextDeadline(t *testing.T) {
	// A listener that never greets: Send must give up at the context deadline.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			defer conn.Close()
			time.Sleep(5 * time.Second)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	s, err := NewSMTPSender(Config{Host: "127.0.0.1", Port: port, From: "noreply@example.com", TLS: TLSNone})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = s.Send(ctx, Message{To: []string{"alice@example.org"}, Subject: "hi", Body: "x"})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Send took %v, expected to honor the deadline", elapsed)
	}
}
