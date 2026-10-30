// Package mailer sends Peerline's transactional email (invite links and
// new-message notifications).
//
// Two implementations: SMTP (configured via PEERLINE_SMTP_* env vars) and a
// dev-mode Log sender that writes the message to the logger instead of
// sending it, so invites keep working when SMTP is not configured.
package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

// Message is a plain-text email.
type Message struct {
	To      string
	Subject string
	Body    string
}

// Sender delivers a Message.
type Sender interface {
	Send(ctx context.Context, m Message) error
	// Mode is "smtp" or "log" (dev mode); reported back to API callers.
	Mode() string
}

// ValidAddress returns the normalized bare address (no display name) or an error.
// It rejects anything that could smuggle extra headers or recipients.
func ValidAddress(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 254 || strings.ContainsAny(s, "\r\n,;<>\"") {
		return "", errors.New("invalid email address")
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Name != "" || a.Address != s || !strings.Contains(a.Address[strings.LastIndexByte(a.Address, '@')+1:], ".") {
		return "", errors.New("invalid email address")
	}
	return a.Address, nil
}

// ---- dev mode ----

// Log is the dev-mode sender: it logs the full message and reports success.
type Log struct{ Logger *slog.Logger }

func (l Log) Mode() string { return "log" }

func (l Log) Send(_ context.Context, m Message) error {
	lg := l.Logger
	if lg == nil {
		lg = slog.Default()
	}
	lg.Warn("SMTP not configured; email logged instead of sent (dev mode)",
		"to", m.To, "subject", m.Subject, "body", m.Body)
	return nil
}

// ---- SMTP ----

// SMTP sends via an SMTP relay. Port 465 uses implicit TLS; any other port
// uses STARTTLS when the server offers it (required when User is set and the
// host is not localhost, as enforced by net/smtp's PLAIN auth).
type SMTP struct {
	Host, User, Pass, From string
	Port                   int
	Timeout                time.Duration
	// TLSConfig is optional (tests); defaults to ServerName=Host.
	TLSConfig *tls.Config
}

func (s *SMTP) Mode() string { return "smtp" }

// FromEnv builds a Sender from PEERLINE_SMTP_HOST/PORT/USER/PASS/FROM.
// If PEERLINE_SMTP_HOST is unset it returns a dev-mode Log sender.
func FromEnv(lg *slog.Logger) (Sender, error) {
	host := strings.TrimSpace(os.Getenv("PEERLINE_SMTP_HOST"))
	if host == "" {
		return Log{Logger: lg}, nil
	}
	port := 587
	if p := os.Getenv("PEERLINE_SMTP_PORT"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return nil, fmt.Errorf("PEERLINE_SMTP_PORT: invalid port %q", p)
		}
		port = n
	}
	from := strings.TrimSpace(os.Getenv("PEERLINE_SMTP_FROM"))
	if from == "" {
		return nil, errors.New("PEERLINE_SMTP_FROM is required when PEERLINE_SMTP_HOST is set")
	}
	if _, err := mail.ParseAddress(from); err != nil || strings.ContainsAny(from, "\r\n") {
		return nil, fmt.Errorf("PEERLINE_SMTP_FROM: %v", err)
	}
	user, pass := os.Getenv("PEERLINE_SMTP_USER"), os.Getenv("PEERLINE_SMTP_PASS")
	if (user == "") != (pass == "") {
		return nil, errors.New("PEERLINE_SMTP_USER and PEERLINE_SMTP_PASS must be set together")
	}
	return &SMTP{Host: host, Port: port, User: user, Pass: pass, From: from, Timeout: 10 * time.Second}, nil
}

func (s *SMTP) Send(ctx context.Context, m Message) error {
	to, err := ValidAddress(m.To)
	if err != nil {
		return err
	}
	fromAddr, err := mail.ParseAddress(s.From)
	if err != nil {
		return fmt.Errorf("from: %w", err)
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	tlsCfg := s.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}
	}

	var conn net.Conn
	d := &net.Dialer{}
	if s.Port == 465 {
		conn, err = (&tls.Dialer{NetDialer: d, Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp hello: %w", err)
	}
	defer c.Close()
	if s.Port != 465 {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("smtp starttls: %w", err)
			}
		}
	}
	if s.User != "" {
		if err := c.Auth(smtp.PlainAuth("", s.User, s.Pass, s.Host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(fromAddr.Address); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(Compose(s.From, to, m.Subject, m.Body, time.Now())); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp end DATA: %w", err)
	}
	return c.Quit()
}

// Compose renders an RFC 5322 plain-text message with CRLF line endings.
func Compose(from, to, subject, body string, now time.Time) []byte {
	clean := func(v string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(v) }
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", clean(from))
	fmt.Fprintf(&b, "To: %s\r\n", clean(to))
	fmt.Fprintf(&b, "Subject: %s\r\n", mimeSubject(clean(subject)))
	fmt.Fprintf(&b, "Date: %s\r\n", now.Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("Auto-Submitted: auto-generated\r\n\r\n")
	body = strings.ReplaceAll(body, "\r\n", "\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	if !strings.HasSuffix(body, "\n") {
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}

func mimeSubject(s string) string { return mime.QEncoding.Encode("UTF-8", s) }
