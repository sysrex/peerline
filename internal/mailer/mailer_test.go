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
		{"127.1.2.3", true},
		{"::1", true},
		{"192.168.1.1", false},
		{"example.com", false},
		{"10.0.0.1", false},
	} {
		if got := isLoopback(tc.host); got != tc.want {
			t.Errorf("isLoopback(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestFromEnv(t *testing.T) {
	tests := []struct {
		name           string
		host           string
		port           string
		user           string
		pass           string
		from           string
		requireTLS     string
		wantMode       string
		wantPlaintext  bool
		wantErr        bool
		wantLogBody    bool
		devLogEmailEnv string
	}{
		{"no host = log mode", "", "", "", "", "", "", "log", false, false, false, ""},
		{"no host with opt-in body", "", "", "", "", "", "", "log", false, false, true, "1"},
		{"localhost no auth = plaintext ok", "localhost", "", "", "", "test@example.com", "", "smtp", true, false, false, ""},
		{"localhost with auth = plaintext ok", "localhost", "", "u", "p", "test@example.com", "", "smtp", true, false, false, ""},
		{"non-loopback no auth = TLS required", "mail.example.com", "", "", "", "test@example.com", "", "smtp", false, false, false, ""},
		{"non-loopback with auth = TLS required", "mail.example.com", "", "u", "p", "test@example.com", "", "smtp", false, false, false, ""},
		{"explicit require TLS", "localhost", "", "", "", "test@example.com", "1", "smtp", false, false, false, ""},
		{"explicit allow plaintext", "mail.example.com", "", "", "", "test@example.com", "0", "smtp", true, false, false, ""},
		{"invalid require TLS", "localhost", "", "", "", "test@example.com", "ture", "", false, true, false, ""},
		{"user without pass", "localhost", "", "u", "", "test@example.com", "", "", false, true, false, ""},
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
				smtp.skipProbe = true // disable probe for this unit test
				if smtp.AllowPlaintext != tt.wantPlaintext {
					t.Fatalf("AllowPlaintext = %v, want %v", smtp.AllowPlaintext, tt.wantPlaintext)
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
	cert := genTestCert(t, "localhost")
	srv := newFakeServer(t, false, &cert) // no STARTTLS
	defer srv.close()

	s := &SMTP{
		Host:      "127.0.0.1",
		Port:      srv.port(),
		From:      "test@example.com",
		Timeout:   2 * time.Second,
		skipProbe: true,
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
		skipProbe:      true,
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
		skipProbe:      true,
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
		skipProbe:      true,
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
		skipProbe:      true,
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
		err := s.Probe(context.Background())
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
		err := s.Probe(context.Background())
		if err == nil || !strings.Contains(err.Error(), "PEERLINE_SMTP_REQUIRE_TLS") {
			t.Fatalf("probe should fail and mention env var, got: %v", err)
		}
	})

	t.Run("unreachable = warning only", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		slog.SetDefault(logger)

		s := &SMTP{
			Host:           "127.0.0.1",
			Port:           1, // unreachable
			Timeout:        100 * time.Millisecond,
			AllowPlaintext: false,
		}
		err := s.Probe(context.Background())
		if err != nil {
			t.Fatalf("probe should not fail for unreachable: %v", err)
		}
		logged := buf.String()
		if !strings.Contains(logged, "unreachable") {
			t.Fatalf("expected warning about unreachable relay: %s", logged)
		}
	})
}
