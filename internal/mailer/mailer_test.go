package mailer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
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
	l := Log{Logger: logger, LogFullBody: false}
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

func TestLogMailerOptInBody(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	l := Log{Logger: logger, LogFullBody: true}
	secretBody := "secret content"
	err := l.Send(context.Background(), Message{
		To:      "test@example.com",
		Subject: "Test",
		Body:    secretBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	logged := buf.String()
	if !strings.Contains(logged, secretBody) || !strings.Contains(logged, "FULL BODY LOGGED") {
		t.Fatalf("opt-in body logging failed: %s", logged)
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

func TestIsLoopback(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
		// Only exact matches per net/smtp PlainAuth
		{"127.1.2.3", false},
		{"192.168.1.1", false},
		{"example.com", false},
		{"10.0.0.1", false},
	} {
		if got := IsLoopback(tc.host); got != tc.want {
			t.Errorf("IsLoopback(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestFromEnv(t *testing.T) {
	tests := []struct {
		name            string
		host            string
		port            string
		user            string
		pass            string
		from            string
		requireTLS      string
		wantMode        string
		wantPlaintext   bool
		wantImplicitTLS bool
		wantErr         bool
		wantLogBody     bool
		devLogEmailEnv  string
	}{
		{"no host = log mode", "", "", "", "", "", "", "log", false, false, false, false, ""},
		{"no host with opt-in body", "", "", "", "", "", "", "log", false, false, false, true, "1"},
		{"localhost no auth = plaintext ok", "localhost", "", "", "", "test@example.com", "", "smtp", true, false, false, false, ""},
		{"localhost with auth = plaintext ok", "localhost", "", "u", "p", "test@example.com", "", "smtp", true, false, false, false, ""},
		{"non-loopback no auth = TLS required", "192.168.1.1", "", "", "", "test@example.com", "", "smtp", false, false, false, false, ""},
		{"non-loopback with auth = TLS required", "192.168.1.1", "", "u", "p", "test@example.com", "", "smtp", false, false, false, false, ""},
		{"explicit require TLS", "localhost", "", "", "", "test@example.com", "1", "smtp", false, false, false, false, ""},
		{"explicit allow plaintext", "192.168.1.1", "", "", "", "test@example.com", "0", "smtp", true, false, false, false, ""},
		{"port 465 = implicit TLS", "192.168.1.1", "465", "", "", "test@example.com", "", "smtp", false, true, false, false, ""},
		{"port 2525", "mail.example.com", "2525", "", "", "test@example.com", "", "smtp", false, false, false, false, ""},
		{"host set without FROM is error", "mail.example.com", "", "", "", "", "", "", false, false, true, false, ""},
		{"invalid require TLS", "localhost", "", "", "", "test@example.com", "ture", "", false, false, true, false, ""},
		{"user without pass", "localhost", "", "u", "", "test@example.com", "", "", false, false, true, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PEERLINE_SMTP_HOST", tt.host)
			t.Setenv("PEERLINE_SMTP_PORT", tt.port)
			t.Setenv("PEERLINE_SMTP_USER", tt.user)
			t.Setenv("PEERLINE_SMTP_PASS", tt.pass)
			t.Setenv("PEERLINE_SMTP_FROM", tt.from)
			t.Setenv("PEERLINE_SMTP_REQUIRE_TLS", tt.requireTLS)
			t.Setenv("PEERLINE_DEV_LOG_EMAIL_BODY", tt.devLogEmailEnv)

			s, err := FromEnv(nil)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if s.Mode() != tt.wantMode {
				t.Fatalf("mode = %q, want %q", s.Mode(), tt.wantMode)
			}
			if tt.wantMode == "log" {
				if l, ok := s.(Log); ok {
					if l.LogFullBody != tt.wantLogBody {
						t.Fatalf("LogFullBody = %v, want %v", l.LogFullBody, tt.wantLogBody)
					}
				}
			} else if tt.wantMode == "smtp" {
				smtp := s.(*SMTP)
				if smtp.AllowPlaintext != tt.wantPlaintext {
					t.Fatalf("AllowPlaintext = %v, want %v", smtp.AllowPlaintext, tt.wantPlaintext)
				}
				if smtp.ImplicitTLS != tt.wantImplicitTLS {
					t.Fatalf("ImplicitTLS = %v, want %v", smtp.ImplicitTLS, tt.wantImplicitTLS)
				}
			}
		})
	}
}

// fakeServer is a minimal SMTP server for testing.
type fakeServer struct {
	ln                net.Listener
	advertiseSTARTTLS bool
	cert              *tls.Certificate
	commands          []string
	mu                sync.Mutex
	t                 *testing.T
}

func newFakeServer(t *testing.T, advertiseSTARTTLS bool, cert *tls.Certificate) *fakeServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fs := &fakeServer{
		ln:                ln,
		advertiseSTARTTLS: advertiseSTARTTLS,
		cert:              cert,
		t:                 t,
	}
	go fs.serve()
	return fs
}

func (fs *fakeServer) serve() {
	for {
		c, err := fs.ln.Accept()
		if err != nil {
			return
		}
		go fs.handleConn(c)
	}
}

func (fs *fakeServer) handleConn(c net.Conn) {
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
		fs.mu.Lock()
		fs.commands = append(fs.commands, cmd)
		fs.mu.Unlock()

		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			say("250-test")
			if fs.advertiseSTARTTLS {
				say("250 STARTTLS")
			} else {
				say("250 ok")
			}
		case cmd == "STARTTLS":
			if !fs.advertiseSTARTTLS || fs.cert == nil {
				say("502 no")
				continue
			}
			say("220 Ready to start TLS")
			w.Flush()
			tlsConn := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*fs.cert}})
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			c = tlsConn
			r, w = bufio.NewReader(c), bufio.NewWriter(c)
		case strings.HasPrefix(cmd, "HELO"):
			say("250 test")
		case strings.HasPrefix(cmd, "AUTH"):
			say("235 ok")
		case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
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
			}
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("502 no")
		}
	}
}

func (fs *fakeServer) addr() string {
	return fs.ln.Addr().String()
}

func (fs *fakeServer) port() int {
	return fs.ln.Addr().(*net.TCPAddr).Port
}

func (fs *fakeServer) close() {
	fs.ln.Close()
}

func (fs *fakeServer) receivedCommands() []string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	cmds := make([]string, len(fs.commands))
	copy(cmds, fs.commands)
	return cmds
}

func genTestCert(t *testing.T, hostname string) tls.Certificate {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
}

func TestSMTPZeroValueFailsClosed(t *testing.T) {
	// Zero-value SMTP{} must fail without STARTTLS (AllowPlaintext defaults to false)
	srv := newFakeServer(t, false, nil) // no STARTTLS
	defer srv.close()

	s := &SMTP{
		Host:    "127.0.0.1",
		Port:    srv.port(),
		From:    "test@example.com",
		Timeout: 2 * time.Second,
	}
	err := s.Send(context.Background(), Message{To: "bob@example.com", Subject: "test", Body: "test"})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS required") {
		t.Fatalf("zero value should fail closed, got: %v", err)
	}
	// No AUTH, MAIL, RCPT or DATA should have been sent
	cmds := srv.receivedCommands()
	for _, cmd := range cmds {
		if strings.HasPrefix(cmd, "AUTH") || strings.HasPrefix(cmd, "MAIL") || strings.HasPrefix(cmd, "RCPT") || cmd == "DATA" {
			t.Fatalf("command %q sent despite missing STARTTLS: %v", cmd, cmds)
		}
	}
}

func TestSMTPSTARTTLSUpgrade(t *testing.T) {
	cert := genTestCert(t, "localhost")
	srv := newFakeServer(t, true, &cert)
	defer srv.close()

	certPool := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(cert.Certificate[0])
	certPool.AddCert(parsed)

	s := &SMTP{
		Host:           "127.0.0.1",
		Port:           srv.port(),
		User:           "testuser",
		Pass:           "testpass",
		From:           "test@example.com",
		Timeout:        5 * time.Second,
		AllowPlaintext: false,
		TLSConfig:      &tls.Config{RootCAs: certPool, ServerName: "localhost"},
	}
	err := s.Send(context.Background(), Message{To: "bob@example.com", Subject: "test", Body: "test"})
	if err != nil {
		t.Fatalf("STARTTLS upgrade failed: %v", err)
	}
	cmds := srv.receivedCommands()
	hasSTARTTLS := false
	hasAUTH := false
	for _, cmd := range cmds {
		if cmd == "STARTTLS" {
			hasSTARTTLS = true
		}
		if strings.HasPrefix(cmd, "AUTH") {
			hasAUTH = true
		}
	}
	if !hasSTARTTLS {
		t.Fatal("STARTTLS not negotiated")
	}
	if !hasAUTH {
		t.Fatal("AUTH not sent after STARTTLS")
	}
}

func TestSMTPUntrustedCert(t *testing.T) {
	cert := genTestCert(t, "localhost")
	srv := newFakeServer(t, true, &cert)
	defer srv.close()

	// Don't provide custom TLSConfig, so default will be used with system roots
	s := &SMTP{
		Host:           "127.0.0.1",
		Port:           srv.port(),
		From:           "test@example.com",
		Timeout:        2 * time.Second,
		AllowPlaintext: false,
	}
	err := s.Send(context.Background(), Message{To: "bob@example.com", Subject: "test", Body: "test"})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected certificate error, got: %v", err)
	}
	// No DATA should have been sent
	cmds := srv.receivedCommands()
	for _, cmd := range cmds {
		if cmd == "DATA" {
			t.Fatalf("DATA sent despite cert failure: %v", cmds)
		}
	}
}

func TestSMTPHostnameMismatch(t *testing.T) {
	cert := genTestCert(t, "wronghost.example.com")
	srv := newFakeServer(t, true, &cert)
	defer srv.close()

	certPool := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(cert.Certificate[0])
	certPool.AddCert(parsed)

	s := &SMTP{
		Host:           "127.0.0.1",
		Port:           srv.port(),
		From:           "test@example.com",
		Timeout:        2 * time.Second,
		AllowPlaintext: false,
		TLSConfig:      &tls.Config{RootCAs: certPool, ServerName: "localhost"},
	}
	err := s.Send(context.Background(), Message{To: "bob@example.com", Subject: "test", Body: "test"})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected hostname mismatch error, got: %v", err)
	}
}

func TestSMTPAllowPlaintext(t *testing.T) {
	srv := newFakeServer(t, false, nil) // no STARTTLS
	defer srv.close()

	s := &SMTP{
		Host:           "127.0.0.1",
		Port:           srv.port(),
		From:           "test@example.com",
		Timeout:        2 * time.Second,
		AllowPlaintext: true,
	}
	err := s.Send(context.Background(), Message{To: "bob@example.com", Subject: "test", Body: "test"})
	if err != nil {
		t.Fatalf("AllowPlaintext=true should succeed: %v", err)
	}
	cmds := srv.receivedCommands()
	hasDATA := false
	for _, cmd := range cmds {
		if cmd == "DATA" {
			hasDATA = true
		}
	}
	if !hasDATA {
		t.Fatal("DATA not sent in plaintext mode")
	}
}

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

	s := &SMTP{
		Host:           "127.0.0.1",
		Port:           ln.Addr().(*net.TCPAddr).Port,
		From:           "alice@example.com",
		Timeout:        2 * time.Second,
		AllowPlaintext: true,
	}
	err = s.Send(context.Background(), Message{To: "bob@example.com", Subject: "Hello", Body: "test body"})
	if err != nil {
		t.Fatal(err)
	}
	data := <-got
	if !strings.Contains(data, "MAIL FROM:") {
		t.Errorf("missing MAIL FROM in %q", data)
	}
	if !strings.Contains(data, "RCPT TO:") {
		t.Errorf("missing RCPT TO in %q", data)
	}
	if !strings.Contains(data, "Subject: Hello") {
		t.Errorf("missing Subject in %q", data)
	}
	if !strings.Contains(data, "test body") {
		t.Errorf("missing body in %q", data)
	}
}

func TestFromEnvRejectsLegacyAllowPlaintext(t *testing.T) {
	t.Setenv("PEERLINE_SMTP_HOST", "localhost")
	t.Setenv("PEERLINE_SMTP_FROM", "test@example.com")
	t.Setenv("PEERLINE_SMTP_ALLOW_PLAINTEXT", "1")
	if _, err := FromEnv(nil); err == nil || !strings.Contains(err.Error(), "PEERLINE_SMTP_REQUIRE_TLS") {
		t.Fatalf("want rename error, got %v", err)
	}
}

func TestSMTPProbeCredentialsWithoutSTARTTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.1.2.3:0")
	if err != nil {
		t.Skip("cannot bind a non-loopback-named address:", err)
	}
	srv := &fakeServer{ln: ln, t: t}
	go srv.serve()
	defer srv.close()

	s := &SMTP{Host: "127.1.2.3", Port: srv.port(), User: "u", Pass: "p", Timeout: 2 * time.Second, AllowPlaintext: true}
	err = s.Probe(context.Background(), nil)
	if err == nil || errors.Is(err, ErrRelayUnreachable) || !strings.Contains(err.Error(), "PLAIN auth") {
		t.Fatalf("want fatal credentials error, got %v", err)
	}
}

func TestSMTPProbe(t *testing.T) {
	t.Run("STARTTLS offered = ok", func(t *testing.T) {
		cert := genTestCert(t, "localhost")
		srv := newFakeServer(t, true, &cert)
		defer srv.close()

		certPool := x509.NewCertPool()
		parsed, _ := x509.ParseCertificate(cert.Certificate[0])
		certPool.AddCert(parsed)

		s := &SMTP{
			Host:           "127.0.0.1",
			Port:           srv.port(),
			Timeout:        2 * time.Second,
			AllowPlaintext: false,
			TLSConfig:      &tls.Config{RootCAs: certPool, ServerName: "localhost"},
		}
		err := s.Probe(context.Background(), nil)
		if err != nil {
			t.Fatalf("probe should succeed: %v", err)
		}
	})

	t.Run("STARTTLS missing, TLS required = error", func(t *testing.T) {
		srv := newFakeServer(t, false, nil)
		defer srv.close()

		s := &SMTP{
			Host:           "127.0.0.1",
			Port:           srv.port(),
			Timeout:        2 * time.Second,
			AllowPlaintext: false,
		}
		err := s.Probe(context.Background(), nil)
		if err == nil || !strings.Contains(err.Error(), "PEERLINE_SMTP_REQUIRE_TLS") {
			t.Fatalf("probe should fail and mention env var, got: %v", err)
		}
	})

	t.Run("unreachable = ErrRelayUnreachable", func(t *testing.T) {
		// Use ephemeral port that's closed
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		ln.Close() // close it immediately

		s := &SMTP{
			Host:           "127.0.0.1",
			Port:           port,
			Timeout:        100 * time.Millisecond,
			AllowPlaintext: false,
		}
		err = s.Probe(context.Background(), nil)
		if err == nil {
			t.Fatal("probe should return error for unreachable")
		}
		if !errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("expected ErrRelayUnreachable, got: %v", err)
		}
	})

	t.Run("STARTTLS with untrusted cert is fatal", func(t *testing.T) {
		cert := genTestCert(t, "localhost")
		srv := newFakeServer(t, true, &cert)
		defer srv.close()

		s := &SMTP{
			Host:           "127.0.0.1",
			Port:           srv.port(),
			Timeout:        2 * time.Second,
			AllowPlaintext: false,
			// No custom TLSConfig - will use system roots and fail
		}
		err := s.Probe(context.Background(), nil)
		if err == nil {
			t.Fatal("probe should fail on untrusted cert")
		}
		if errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("untrusted cert should be fatal, not ErrRelayUnreachable: %v", err)
		}
		if !strings.Contains(err.Error(), "certificate") {
			t.Fatalf("expected certificate error, got: %v", err)
		}
	})

	t.Run("STARTTLS with trusted cert succeeds", func(t *testing.T) {
		cert := genTestCert(t, "localhost")
		srv := newFakeServer(t, true, &cert)
		defer srv.close()

		certPool := x509.NewCertPool()
		parsed, _ := x509.ParseCertificate(cert.Certificate[0])
		certPool.AddCert(parsed)

		s := &SMTP{
			Host:           "127.0.0.1",
			Port:           srv.port(),
			Timeout:        2 * time.Second,
			AllowPlaintext: false,
			TLSConfig:      &tls.Config{RootCAs: certPool, ServerName: "localhost"},
		}
		err := s.Probe(context.Background(), nil)
		if err != nil {
			t.Fatalf("probe should succeed with trusted cert: %v", err)
		}
	})

	t.Run("STARTTLS handshake timeout = ErrRelayUnreachable", func(t *testing.T) {
		// Server that advertises STARTTLS but hangs during handshake
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					// Send greeting and EHLO response advertising STARTTLS
					conn.Write([]byte("220 test\r\n"))
					buf := make([]byte, 1024)
					conn.Read(buf) // read EHLO
					conn.Write([]byte("250-test\r\n250 STARTTLS\r\n"))
					conn.Read(buf) // read STARTTLS
					conn.Write([]byte("220 Ready to start TLS\r\n"))
					// Then hang - don't start TLS handshake
					time.Sleep(2 * time.Second)
				}(c)
			}
		}()

		s := &SMTP{
			Host:           "127.0.0.1",
			Port:           ln.Addr().(*net.TCPAddr).Port,
			Timeout:        500 * time.Millisecond,
			AllowPlaintext: false,
		}
		err = s.Probe(context.Background(), nil)
		if err == nil {
			t.Fatal("probe should return error for timeout")
		}
		if !errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("timeout should be ErrRelayUnreachable, got: %v", err)
		}
	})

	t.Run("4xx greeting = ErrRelayUnreachable", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Write([]byte("421 Service not available\r\n"))
				c.Close()
			}
		}()

		s := &SMTP{
			Host:           "127.0.0.1",
			Port:           ln.Addr().(*net.TCPAddr).Port,
			Timeout:        500 * time.Millisecond,
			AllowPlaintext: false,
		}
		err = s.Probe(context.Background(), nil)
		if err == nil {
			t.Fatal("probe should return error for 4xx greeting")
		}
		if !errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("4xx greeting should be ErrRelayUnreachable, got: %v", err)
		}
	})

	t.Run("EHLO failure = ErrRelayUnreachable", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					conn.Write([]byte("220 test\r\n"))
					buf := make([]byte, 1024)
					conn.Read(buf) // read EHLO
					conn.Write([]byte("550 EHLO rejected\r\n"))
				}(c)
			}
		}()

		s := &SMTP{
			Host:           "127.0.0.1",
			Port:           ln.Addr().(*net.TCPAddr).Port,
			Timeout:        500 * time.Millisecond,
			AllowPlaintext: false,
		}
		err = s.Probe(context.Background(), nil)
		if err == nil {
			t.Fatal("probe should return error for EHLO failure")
		}
		if !errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("EHLO failure should be ErrRelayUnreachable, got: %v", err)
		}
	})
}

func TestSMTPImplicitTLS(t *testing.T) {
	cert := genTestCert(t, "localhost")

	t.Run("port 465 success with trusted cert", func(t *testing.T) {
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		fs := &fakeServer{
			ln:                ln,
			advertiseSTARTTLS: false,
			cert:              &cert,
			t:                 t,
		}
		go fs.serve()

		certPool := x509.NewCertPool()
		parsed, _ := x509.ParseCertificate(cert.Certificate[0])
		certPool.AddCert(parsed)

		s := &SMTP{
			Host:        "127.0.0.1",
			Port:        ln.Addr().(*net.TCPAddr).Port,
			From:        "test@example.com",
			Timeout:     2 * time.Second,
			ImplicitTLS: true,
			TLSConfig:   &tls.Config{RootCAs: certPool, ServerName: "localhost"},
		}
		err = s.Send(context.Background(), Message{To: "bob@example.com", Subject: "test", Body: "test"})
		if err != nil {
			t.Fatalf("implicit TLS should succeed: %v", err)
		}
		cmds := fs.receivedCommands()
		hasDATA := false
		for _, cmd := range cmds {
			if cmd == "DATA" {
				hasDATA = true
			}
		}
		if !hasDATA {
			t.Fatal("DATA not sent over implicit TLS")
		}
	})

	t.Run("port 465 failure with untrusted cert", func(t *testing.T) {
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		fs := &fakeServer{
			ln:                ln,
			advertiseSTARTTLS: false,
			cert:              &cert,
			t:                 t,
		}
		go fs.serve()

		s := &SMTP{
			Host:        "127.0.0.1",
			Port:        ln.Addr().(*net.TCPAddr).Port,
			From:        "test@example.com",
			Timeout:     2 * time.Second,
			ImplicitTLS: true,
			// No custom TLSConfig - will use system roots and fail
		}
		err = s.Send(context.Background(), Message{To: "bob@example.com", Subject: "test", Body: "test"})
		if err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Fatalf("expected certificate error, got: %v", err)
		}
		// No MAIL or DATA should have been sent
		cmds := fs.receivedCommands()
		for _, cmd := range cmds {
			if strings.HasPrefix(cmd, "MAIL") || cmd == "DATA" {
				t.Fatalf("command %q sent despite TLS failure: %v", cmd, cmds)
			}
		}
	})

	t.Run("port 465 probe TLS handshake failure is fatal", func(t *testing.T) {
		// TLS listener with cert the client won't trust
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		// Accept and do real TLS handshake
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				// Just accept and let TLS handshake happen; will fail on client side due to untrusted cert
				buf := make([]byte, 1024)
				c.Read(buf) // block until client closes or we're done
				c.Close()
			}
		}()

		s := &SMTP{
			Host:        "127.0.0.1",
			Port:        ln.Addr().(*net.TCPAddr).Port,
			Timeout:     2 * time.Second,
			ImplicitTLS: true,
			// No custom TLSConfig - will use system roots and fail cert validation
		}
		err = s.Probe(context.Background(), nil)
		if err == nil {
			t.Fatal("probe should fail on port 465 TLS error, got nil")
		}
		if errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("cert error should be fatal, not ErrRelayUnreachable: %v", err)
		}
		if !strings.Contains(err.Error(), "TLS handshake") && !strings.Contains(err.Error(), "certificate") {
			t.Fatalf("expected TLS/certificate error, got: %v", err)
		}
	})

	t.Run("port 465 probe timeout during handshake = ErrRelayUnreachable", func(t *testing.T) {
		// TCP listener that accepts but never speaks TLS
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				// Accept but never write anything (simulates hung handshake)
				time.Sleep(2 * time.Second)
				c.Close()
			}
		}()

		s := &SMTP{
			Host:        "127.0.0.1",
			Port:        ln.Addr().(*net.TCPAddr).Port,
			Timeout:     500 * time.Millisecond,
			ImplicitTLS: true,
		}
		err = s.Probe(context.Background(), nil)
		if err == nil {
			t.Fatal("probe should return error for timeout")
		}
		if !errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("timeout should be ErrRelayUnreachable, got: %v", err)
		}
	})

	t.Run("port 465 probe closed port = ErrRelayUnreachable", func(t *testing.T) {
		// Use ephemeral port that's closed
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		ln.Close() // close it immediately

		s := &SMTP{
			Host:        "127.0.0.1",
			Port:        port,
			Timeout:     100 * time.Millisecond,
			ImplicitTLS: true,
		}
		err = s.Probe(context.Background(), nil)
		if err == nil {
			t.Fatal("probe should return error for closed port")
		}
		if !errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("closed port should be ErrRelayUnreachable, got: %v", err)
		}
	})
}

func TestIsLoopbackAddr(t *testing.T) {
	for addr, want := range map[string]bool{"127.0.0.1:25": true, "[::1]:25": true, "10.0.0.5:25": false, "[2001:db8::1]:25": false} {
		a, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		if got := isLoopbackAddr(a); got != want {
			t.Errorf("isLoopbackAddr(%s) = %v, want %v", addr, got, want)
		}
	}
}
