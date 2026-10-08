// Package mail sends email over SMTP. It holds the one SMTP configuration
// the app has, shared by the email notifier and, later, account email
// confirmation (REQUIRE_CONFIRM).
package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// TLSMode is how the connection to the SMTP server is secured.
type TLSMode string

const (
	// TLSStartTLS upgrades a plain connection with STARTTLS (port 587), and
	// fails if the server does not offer it.
	TLSStartTLS TLSMode = "starttls"
	// TLSImplicit speaks TLS from the first byte (port 465).
	TLSImplicit TLSMode = "tls"
	// TLSNone sends in the clear. Only for local relays and tests.
	TLSNone TLSMode = "none"
)

const defaultDialTimeout = 30 * time.Second

// Config is the SMTP configuration, read from SMTP_* environment variables.
type Config struct {
	Host     string
	Port     int
	Username string // empty: no authentication
	Password string
	From     string // envelope sender and From header
	TLS      TLSMode
}

// Enabled reports whether SMTP is configured at all.
func (c Config) Enabled() bool { return c.Host != "" }

// ConfigFromEnv reads the SMTP configuration through getenv. It only parses
// the values; NewSMTPSender validates them.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	cfg := Config{
		Host:     getenv("SMTP_HOST"),
		Username: getenv("SMTP_USERNAME"),
		Password: getenv("SMTP_PASSWORD"),
		From:     getenv("SMTP_FROM"),
		TLS:      TLSMode(getenv("SMTP_TLS")),
		Port:     587,
	}
	if cfg.TLS == "" {
		cfg.TLS = TLSStartTLS
	}
	if p := getenv("SMTP_PORT"); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil {
			return Config{}, fmt.Errorf("SMTP_PORT: %w", err)
		}
		cfg.Port = port
	}
	return cfg, nil
}

// Message is a plain-text email.
type Message struct {
	To      []string
	Subject string
	Body    string
}

// Sender sends email.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// SMTPSender sends through the configured SMTP server.
type SMTPSender struct {
	cfg  Config
	from *mail.Address
}

// NewSMTPSender validates cfg and returns a sender for it.
func NewSMTPSender(cfg Config) (*SMTPSender, error) {
	if cfg.Host == "" {
		return nil, errors.New("smtp: host is required")
	}
	if cfg.Port <= 0 {
		return nil, fmt.Errorf("smtp: invalid port %d", cfg.Port)
	}
	if cfg.From == "" {
		return nil, errors.New("smtp: from address is required")
	}
	from, err := parseAddress(cfg.From)
	if err != nil {
		return nil, fmt.Errorf("smtp: invalid from address: %w", err)
	}
	if cfg.TLS == "" {
		cfg.TLS = TLSStartTLS
	}
	switch cfg.TLS {
	case TLSStartTLS, TLSImplicit, TLSNone:
	default:
		return nil, fmt.Errorf("smtp: unknown TLS mode %q", cfg.TLS)
	}
	return &SMTPSender{cfg: cfg, from: from}, nil
}

// Send delivers m as a plain-text message to m.To.
func (s *SMTPSender) Send(ctx context.Context, m Message) error {
	if len(m.To) == 0 {
		return errors.New("smtp: no recipients")
	}
	rcpts := make([]*mail.Address, 0, len(m.To))
	for _, to := range m.To {
		addr, err := parseAddress(to)
		if err != nil {
			return fmt.Errorf("smtp: invalid recipient: %w", err)
		}
		rcpts = append(rcpts, addr)
	}
	if strings.ContainsAny(m.Subject, "\r\n") {
		return errors.New("smtp: subject contains a line break")
	}
	data, err := s.buildMessage(rcpts, m)
	if err != nil {
		return err
	}

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultDialTimeout)
		defer cancel()
	}
	return s.deliver(ctx, rcpts, data)
}

// deliver runs one SMTP transaction for an already built message.
func (s *SMTPSender) deliver(ctx context.Context, rcpts []*mail.Address, data []byte) error {
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp: dial: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			conn.Close()
			return fmt.Errorf("smtp: set deadline: %w", err)
		}
	}

	tlsCfg := &tls.Config{ServerName: s.cfg.Host}
	var c *smtp.Client
	if s.cfg.TLS == TLSImplicit {
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return fmt.Errorf("smtp: tls handshake: %w", err)
		}
		conn = tlsConn
	}
	c, err = smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp: greeting: %w", err)
	}
	defer c.Close()

	if s.cfg.TLS == TLSStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("smtp: server does not support STARTTLS")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp: starttls: %w", err)
		}
	}
	if s.cfg.Username != "" {
		auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp: auth: %w", err)
		}
	}

	if err := c.Mail(s.from.Address); err != nil {
		return fmt.Errorf("smtp: MAIL FROM: %w", err)
	}
	for _, r := range rcpts {
		if err := c.Rcpt(r.Address); err != nil {
			return fmt.Errorf("smtp: RCPT TO %s: %w", r.Address, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp: DATA: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		w.Close()
		return fmt.Errorf("smtp: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: end DATA: %w", err)
	}
	if err := c.Quit(); err != nil {
		return fmt.Errorf("smtp: quit: %w", err)
	}
	return nil
}

// buildMessage renders the headers and the quoted-printable body with CRLF
// line endings.
func (s *SMTPSender) buildMessage(rcpts []*mail.Address, m Message) ([]byte, error) {
	to := make([]string, 0, len(rcpts))
	for _, r := range rcpts {
		to = append(to, r.String())
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("smtp: message id: %w", err)
	}
	domain := s.from.Address[strings.LastIndex(s.from.Address, "@")+1:]

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\n", s.from.String())
	fmt.Fprintf(&buf, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&buf, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", m.Subject))
	fmt.Fprintf(&buf, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&buf, "Message-ID: <%s@%s>\r\n", hex.EncodeToString(idBytes), domain)
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	buf.WriteString("\r\n")

	body := strings.ReplaceAll(m.Body, "\r\n", "\n")
	body = strings.ReplaceAll(body, "\n", "\r\n")
	qp := quotedprintable.NewWriter(&buf)
	if _, err := qp.Write([]byte(body)); err != nil {
		return nil, fmt.Errorf("smtp: encode body: %w", err)
	}
	if err := qp.Close(); err != nil {
		return nil, fmt.Errorf("smtp: encode body: %w", err)
	}
	return buf.Bytes(), nil
}

// parseAddress parses a single bare or named address, rejecting line breaks.
func parseAddress(s string) (*mail.Address, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("address %q contains a line break", s)
	}
	return mail.ParseAddress(s)
}
