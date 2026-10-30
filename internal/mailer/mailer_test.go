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
	if err != nil || s.Mode() != "smtp" || s.(*SMTP).Port != 2525 {
		t.Fatal(s, err)
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
	s := &SMTP{Host: "127.0.0.1", Port: port, From: "Peerline <noreply@example.com>", Timeout: 5 * time.Second, AllowPlaintext: true}
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

func TestSMTPRequiresSTARTTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	seen := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		c.Write([]byte("220 test\r\n"))
		var cmds strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				break
			}
			cmds.WriteString(line)
			if strings.HasPrefix(strings.ToUpper(line), "EHLO") {
				c.Write([]byte("250 test\r\n"))
			} else {
				c.Write([]byte("221 bye\r\n"))
			}
		}
		seen <- cmds.String()
	}()
	s := &SMTP{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, From: "a@example.com", Timeout: 5 * time.Second}
	if err := s.Send(context.Background(), Message{To: "bob@example.com", Subject: "s", Body: "secret"}); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("want STARTTLS error, got %v", err)
	}
	if got := <-seen; strings.Contains(got, "MAIL") || strings.Contains(got, "DATA") || strings.Contains(got, "secret") {
		t.Fatalf("mail sent in cleartext: %q", got)
	}
}

func TestLogRedactsBodyByDefault(t *testing.T) {
	var buf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&buf, nil))
	m := Message{To: "a@b.co", Subject: "s", Body: "code inv_SECRETSECRETSECRET"}
	Log{Logger: lg}.Send(context.Background(), m)
	if strings.Contains(buf.String(), "SECRET") {
		t.Fatalf("body logged: %s", buf.String())
	}
	buf.Reset()
	Log{Logger: lg, FullBody: true}.Send(context.Background(), m)
	if !strings.Contains(buf.String(), "SECRET") {
		t.Fatalf("opt-in body missing: %s", buf.String())
	}
}
