package mailer

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func TestValidAddress(t *testing.T) {
	for _, ok := range []string{"bob@example.com", " bob+bots@mail.example.co.uk "} {
		if _, err := ValidAddress(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "bob", "Bob <bob@example.com>", "bob@example.com\nBcc: x@y.z", "a@b.com, c@d.com", "bob@localhost", strings.Repeat("a", 250) + "@x.com"} {
		if _, err := ValidAddress(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestLogMailerDoesNotLogBody(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	l := Log{Logger: logger}
	secretBody := "invite code inv_secretcode123456 and pair_token987654321"
	err := l.Send(context.Background(), Message{
		To:      "test@example.com",
		Subject: "Test",
		Body:    secretBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	logged := buf.String()
	if strings.Contains(logged, secretBody) || strings.Contains(logged, "inv_secretcode") || strings.Contains(logged, "pair_token") {
		t.Fatalf("log mailer leaked body content: %s", logged)
	}
	if !strings.Contains(logged, "body_len=") || !strings.Contains(logged, "dev mode") {
		t.Fatalf("log mailer missing expected fields: %s", logged)
	}
}

func TestCompose(t *testing.T) {
	m := string(Compose("Peerline <noreply@example.com>", "bob@example.com", "hi\r\nBcc: evil@x.com", "line1\nline2", time.Unix(0, 0)))
	if strings.Contains(m, "\r\nBcc:") {
		t.Fatalf("header injection: %q", m)
	}
	if !strings.Contains(m, "\r\n\r\nline1\r\nline2\r\n") {
		t.Fatalf("body: %q", m)
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("PEERLINE_SMTP_HOST", "")
	s, err := FromEnv(nil)
	if err != nil || s.Mode() != "log" {
		t.Fatal(s, err)
	}
	if err := s.Send(context.Background(), Message{To: "a@b.co", Subject: "s", Body: "b"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PEERLINE_SMTP_HOST", "smtp.example.com")
	if _, err := FromEnv(nil); err == nil {
		t.Fatal("FROM required")
	}
	t.Setenv("PEERLINE_SMTP_FROM", "Peerline <noreply@example.com>")
	t.Setenv("PEERLINE_SMTP_USER", "u")
	if _, err := FromEnv(nil); err == nil {
		t.Fatal("USER without PASS")
	}
	t.Setenv("PEERLINE_SMTP_PASS", "p")
	t.Setenv("PEERLINE_SMTP_PORT", "2525")
	s, err = FromEnv(nil)
	smtp := s.(*SMTP)
	if err != nil || s.Mode() != "smtp" || smtp.Port != 2525 || !smtp.RequireTLS {
		t.Fatalf("smtp config: port=%d requireTLS=%v err=%v", smtp.Port, smtp.RequireTLS, err)
	}
	// RequireTLS defaults to true when authenticated
	t.Setenv("PEERLINE_SMTP_REQUIRE_TLS", "0")
	s, err = FromEnv(nil)
	smtp = s.(*SMTP)
	if err != nil || smtp.RequireTLS {
		t.Fatalf("requireTLS=false failed: %v %v", smtp.RequireTLS, err)
	}
}

// Minimal SMTP server (no TLS/auth) to exercise the SMTP sender end to end.
func TestSMTPSend(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r, w := bufio.NewReader(c), bufio.NewWriter(c)
		say := func(s string) { w.WriteString(s + "\r\n"); w.Flush() }
		say("220 test")
		var data strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250 test")
			case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
				data.WriteString(line)
				say("250 ok")
			case cmd == "DATA":
				say("354 go")
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if l == ".\r\n" {
						break
					}
					data.WriteString(l)
				}
				say("250 queued")
			case cmd == "QUIT":
				say("221 bye")
				got <- data.String()
				return
			default:
				say("502 no")
			}
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	s := &SMTP{Host: "127.0.0.1", Port: port, From: "Peerline <noreply@example.com>", Timeout: 5 * time.Second}
	if err := s.Send(context.Background(), Message{To: "bob@example.com", Subject: "Invite", Body: "code inv_x"}); err != nil {
		t.Fatal(err)
	}
	d := <-got
	for _, w := range []string{"MAIL FROM:<noreply@example.com>", "RCPT TO:<bob@example.com>", "Subject: Invite", "code inv_x"} {
		if !strings.Contains(d, w) {
			t.Fatalf("missing %q in %q", w, d)
		}
	}
}

func TestSMTPRequireTLS(t *testing.T) {
	// Server without STARTTLS support
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r, w := bufio.NewReader(c), bufio.NewWriter(c)
		say := func(s string) { w.WriteString(s + "\r\n"); w.Flush() }
		say("220 test")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250 test")
			case cmd == "QUIT":
				say("221 bye")
				return
			default:
				say("502 no")
			}
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	s := &SMTP{Host: "127.0.0.1", Port: port, From: "test@example.com", Timeout: 2 * time.Second, RequireTLS: true}
	err = s.Send(context.Background(), Message{To: "bob@example.com", Subject: "test", Body: "test"})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS required") {
		t.Fatalf("expected STARTTLS required error, got: %v", err)
	}
}
