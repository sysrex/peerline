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
	"os"
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
		// Expanded forms
		{"127.0.0.2", true},
		{"127.1.2.3", true},
		{"0:0:0:0:0:0:0:1", true},
		{"0000:0000:0000:0000:0000:0000:0000:0001", true},
		// Non-loopback
		{"192.168.1.1", false},
		{"example.com", false},
		{"10.0.0.1", false},
		{"2001:db8::1", false},
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
		{"credentials with REQUIRE_TLS=false on non-loopback", "192.168.1.1", "", "u", "p", "test@example.com", "false", "smtp", true, false, false, false, ""},
		{"::1 IPv6 loopback = plaintext ok", "::1", "", "", "", "test@example.com", "", "smtp", true, false, false, false, ""},
		{"2001:db8::1 IPv6 non-loopback = TLS required", "2001:db8::1", "", "", "", "test@example.com", "", "smtp", false, false, false, false, ""},
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

func TestFromEnvRejectsBracketedHosts(t *testing.T) {
	tests := []struct {
		name               string
		host               string
		wantSuggestedValue string
	}{
		{"[::1]:25", "[::1]:25", "use ::1 with PEERLINE_SMTP_PORT=25"},
		{"[::1]", "[::1]", "use ::1"},
		{"[::1", "[::1", "use a valid hostname or IP"},
		{"::1]", "::1]", "use a valid hostname or IP"},
		{"[]", "[]", "use a valid hostname or IP"},
		{"[127.0.0.1]:587", "[127.0.0.1]:587", "use 127.0.0.1 with PEERLINE_SMTP_PORT=587"},
		{"[127.0.0.1]", "[127.0.0.1]", "use 127.0.0.1"},
		{"[[::1]]", "[[::1]]", "use a valid hostname or IP"},
		{"[::1]]", "[::1]]", "use a valid hostname or IP"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PEERLINE_SMTP_HOST", tt.host)
			t.Setenv("PEERLINE_SMTP_FROM", "test@example.com")
			_, err := FromEnv(nil)
			if err == nil {
				t.Fatalf("expected error for host %q, got nil", tt.host)
			}
			if !strings.Contains(err.Error(), "bracketed") {
				t.Fatalf("error %q should mention 'bracketed'", err.Error())
			}
			if !strings.Contains(err.Error(), tt.wantSuggestedValue) {
				t.Fatalf("error %q should contain suggestion %q", err.Error(), tt.wantSuggestedValue)
			}
			// Verify no error message suggests a value containing brackets
			if strings.Contains(err.Error(), "[") && !strings.Contains(err.Error(), tt.host) {
				// The error contains the input host (which has brackets), that's ok
				// But if there are OTHER brackets (in the suggestion), that's bad
				errWithoutInput := strings.ReplaceAll(err.Error(), tt.host, "")
				if strings.Contains(errWithoutInput, "[") || strings.Contains(errWithoutInput, "]") {
					t.Fatalf("error suggests a value with brackets: %q", err.Error())
				}
			}
		})
	}
}

func TestFromEnvRejectsHostWithPort(t *testing.T) {
	tests := []struct {
		name               string
		host               string
		wantErrContains    []string
		wantSuggestedValue string
	}{
		{"host:port", "mail.example.com:587", []string{"mail.example.com", "PEERLINE_SMTP_PORT"}, "use mail.example.com with PEERLINE_SMTP_PORT=587"},
		{"host", "host:25", []string{"host", "PEERLINE_SMTP_PORT=25"}, "use host with PEERLINE_SMTP_PORT=25"},
		{"[::1]:25", "[::1]:25", []string{"bracketed"}, "use ::1 with PEERLINE_SMTP_PORT=25"},
		{"[::1]", "[::1]", []string{"bracketed"}, "use ::1"},
		{"::1", "::1", nil, ""}, // plain IPv6 is ok
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PEERLINE_SMTP_HOST", tt.host)
			t.Setenv("PEERLINE_SMTP_FROM", "test@example.com")
			_, err := FromEnv(nil)
			if tt.wantErrContains == nil {
				if err != nil {
					t.Fatalf("expected no error for host %q, got %v", tt.host, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error for host %q, got nil", tt.host)
			}
			for _, want := range tt.wantErrContains {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q should contain %q", err.Error(), want)
				}
			}
			if tt.wantSuggestedValue != "" && !strings.Contains(err.Error(), tt.wantSuggestedValue) {
				t.Fatalf("error %q should contain full suggestion %q", err.Error(), tt.wantSuggestedValue)
			}
			// Verify no error message suggests a value containing brackets
			if strings.Contains(err.Error(), "[") || strings.Contains(err.Error(), "]") {
				errWithoutInput := strings.ReplaceAll(err.Error(), tt.host, "")
				if strings.Contains(errWithoutInput, "[") || strings.Contains(errWithoutInput, "]") {
					t.Fatalf("error suggests a value with brackets: %q", err.Error())
				}
			}
		})
	}
}

func TestFromEnvRejectsZonedHosts(t *testing.T) {
	tests := []struct {
		name string
		host string
	}{
		{"fe80::1%eth0", "fe80::1%eth0"},
		{"fe80::1%lo0", "fe80::1%lo0"},
		{"[fe80::1%eth0]:25", "[fe80::1%eth0]:25"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PEERLINE_SMTP_HOST", tt.host)
			t.Setenv("PEERLINE_SMTP_FROM", "test@example.com")
			_, err := FromEnv(nil)
			if err == nil {
				t.Fatalf("expected error for zoned host %q, got nil", tt.host)
			}
			if !strings.Contains(err.Error(), "zone ID") {
				t.Fatalf("error should mention zone ID, got: %v", err)
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
	stallSecondConn   bool // if true, stall the second connection's greeting
	connCount         int
	closeCh           chan struct{} // closed when server closes
	closeOnce         sync.Once
}

func newFakeServer(t *testing.T, advertiseSTARTTLS bool, cert *tls.Certificate) *fakeServer {
	return newFakeServerWithOptions(t, advertiseSTARTTLS, cert, false)
}

func newFakeServerWithOptions(t *testing.T, advertiseSTARTTLS bool, cert *tls.Certificate, stallSecondConn bool) *fakeServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fs := &fakeServer{
		ln:                ln,
		advertiseSTARTTLS: advertiseSTARTTLS,
		cert:              cert,
		t:                 t,
		stallSecondConn:   stallSecondConn,
		closeCh:           make(chan struct{}),
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

	// Track connection count and check if should stall
	fs.mu.Lock()
	fs.connCount++
	connNum := fs.connCount
	shouldStall := fs.stallSecondConn && connNum == 2
	fs.mu.Unlock()

	r, w := bufio.NewReader(c), bufio.NewWriter(c)
	say := func(s string) { w.WriteString(s + "\r\n"); w.Flush() }

	// Stall the second connection if requested (block until server closes)
	if shouldStall {
		<-fs.closeCh
		return
	}

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
	fs.closeOnce.Do(func() {
		fs.ln.Close()
		if fs.closeCh != nil {
			close(fs.closeCh)
		}
	})
}

func (fs *fakeServer) receivedCommands() []string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	cmds := make([]string, len(fs.commands))
	copy(cmds, fs.commands)
	return cmds
}

func genTestCert(t *testing.T, hostname string) tls.Certificate {
	return genTestCertWithValidity(t, hostname, time.Now(), time.Now().Add(time.Hour))
}

func genExpiredTestCert(t *testing.T, hostname string) tls.Certificate {
	return genTestCertWithValidity(t, hostname, time.Now().Add(-2*time.Hour), time.Now().Add(-1*time.Hour))
}

func genTestCertWithValidity(t *testing.T, hostname string, notBefore, notAfter time.Time) tls.Certificate {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
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

func genTestCertDNSOnly(t *testing.T, hostname string) tls.Certificate {
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

func genTestCertIPOnly(t *testing.T, ip string) tls.Certificate {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: ip},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP(ip)},
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

// genTestCertChain generates a certificate chain: root CA -> intermediate CA -> leaf cert.
// Returns the leaf tls.Certificate (with full chain) and the root cert for building a trust pool.
func genTestCertChain(t *testing.T, hostname string, leafNotBefore, leafNotAfter, intermediateNotBefore, intermediateNotAfter time.Time) (tls.Certificate, *x509.Certificate) {
	// Root CA
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-10 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            2,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	// Intermediate CA
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intermediateTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             intermediateNotBefore,
		NotAfter:              intermediateNotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, &intermediateTemplate, rootCert, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	// Leaf certificate
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intermediateCert, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    leafNotBefore,
		NotAfter:     leafNotAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, intermediateCert, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{leafDER, intermediateDER},
		PrivateKey:  leafKey,
	}, rootCert
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

func TestSMTPSendRefusesExpiredCert(t *testing.T) {
	cert := genExpiredTestCert(t, "localhost")
	srv := newFakeServer(t, true, &cert)
	defer srv.close()

	certPool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse test cert: %v", err)
	}
	certPool.AddCert(parsed)

	tests := []struct {
		name           string
		allowPlaintext bool
	}{
		{"AllowPlaintext=false", false},
		{"AllowPlaintext=true", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SMTP{
				Host:           "127.0.0.1",
				Port:           srv.port(),
				From:           "test@example.com",
				User:           "testuser",
				Pass:           "testpass",
				Timeout:        2 * time.Second,
				AllowPlaintext: tt.allowPlaintext,
				TLSConfig:      &tls.Config{RootCAs: certPool, ServerName: "localhost"},
			}
			err := s.Send(context.Background(), Message{To: "bob@example.com", Subject: "test", Body: "test"})
			if err == nil {
				t.Fatal("Send should refuse expired cert")
			}
			// Positive control: verify STARTTLS was attempted
			cmds := srv.receivedCommands()
			hasSTARTTLS := false
			for _, cmd := range cmds {
				if cmd == "STARTTLS" {
					hasSTARTTLS = true
					break
				}
			}
			if !hasSTARTTLS {
				t.Fatalf("STARTTLS not attempted: %v", cmds)
			}
			// Positive control: verify the error is a certificate expiry error
			var x509Invalid x509.CertificateInvalidError
			if !errors.As(err, &x509Invalid) {
				t.Fatalf("error should be x509.CertificateInvalidError, got: %T %v", err, err)
			}
			if x509Invalid.Reason != x509.Expired {
				t.Fatalf("error reason should be Expired, got: %v", x509Invalid.Reason)
			}
			// Verify no AUTH, MAIL, RCPT or DATA were sent
			for _, cmd := range cmds {
				if strings.HasPrefix(cmd, "AUTH") || strings.HasPrefix(cmd, "MAIL") ||
					strings.HasPrefix(cmd, "RCPT") || cmd == "DATA" {
					t.Fatalf("command %q reached server despite expired cert: %v", cmd, cmds)
				}
			}
		})
	}
}

func TestSMTPSendRefusedBeforeAUTH(t *testing.T) {
	srv := newFakeServer(t, false, nil) // no STARTTLS
	defer srv.close()

	s := &SMTP{
		Host:           "127.0.0.1",
		Port:           srv.port(),
		From:           "test@example.com",
		User:           "testuser",
		Pass:           "testpass",
		Timeout:        2 * time.Second,
		AllowPlaintext: false, // STARTTLS required
	}
	err := s.Send(context.Background(), Message{To: "bob@example.com", Subject: "test", Body: "test"})
	if err == nil {
		t.Fatal("Send should fail when STARTTLS is required but not offered")
	}
	if !strings.Contains(err.Error(), "STARTTLS required") {
		t.Fatalf("error should mention STARTTLS required, got: %v", err)
	}

	// Verify no AUTH, MAIL FROM, RCPT or DATA were sent
	cmds := srv.receivedCommands()
	for _, cmd := range cmds {
		if strings.HasPrefix(cmd, "AUTH") || strings.HasPrefix(cmd, "MAIL") ||
			strings.HasPrefix(cmd, "RCPT") || cmd == "DATA" {
			t.Fatalf("command %q should not have been sent when STARTTLS is missing: %v", cmd, cmds)
		}
	}
}

func TestSMTPSendWrongHostnameTrustedChain(t *testing.T) {
	cert := genTestCert(t, "wronghost.example.com")
	srv := newFakeServer(t, true, &cert)
	defer srv.close()

	certPool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse test cert: %v", err)
	}
	certPool.AddCert(parsed)

	s := &SMTP{
		Host:           "127.0.0.1",
		Port:           srv.port(),
		From:           "test@example.com",
		User:           "testuser",
		Pass:           "testpass",
		Timeout:        2 * time.Second,
		AllowPlaintext: false,
		TLSConfig:      &tls.Config{RootCAs: certPool, ServerName: "localhost"},
	}
	err = s.Send(context.Background(), Message{To: "bob@example.com", Subject: "test", Body: "test"})
	if err == nil {
		t.Fatal("Send should fail on hostname mismatch")
	}
	var hostnameErr x509.HostnameError
	if !errors.As(err, &hostnameErr) {
		t.Fatalf("error should be x509.HostnameError, got: %T: %v", err, err)
	}

	// Verify STARTTLS was attempted
	cmds := srv.receivedCommands()
	hasSTARTTLS := false
	for _, cmd := range cmds {
		if cmd == "STARTTLS" {
			hasSTARTTLS = true
			break
		}
	}
	if !hasSTARTTLS {
		t.Fatalf("STARTTLS should have been attempted: %v", cmds)
	}

	// Verify no AUTH, MAIL FROM, RCPT or DATA were sent
	for _, cmd := range cmds {
		if strings.HasPrefix(cmd, "AUTH") || strings.HasPrefix(cmd, "MAIL") ||
			strings.HasPrefix(cmd, "RCPT") || cmd == "DATA" {
			t.Fatalf("command %q should not have been sent after hostname error: %v", cmd, cmds)
		}
	}
}

func TestSMTPSendWrongHostnamePort465TrustedChain(t *testing.T) {
	tests := []struct {
		name       string
		serverName string // empty means use default from Host
	}{
		{"explicit ServerName", "localhost"},
		{"default ServerName from Host", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := genTestCertDNSOnly(t, "wronghost.example.com")
			ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			fs := &fakeServer{ln: ln, cert: &cert, t: t, closeCh: make(chan struct{})}
			go fs.serve()

			certPool := x509.NewCertPool()
			parsed, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatalf("failed to parse test cert: %v", err)
			}
			certPool.AddCert(parsed)

			tlsCfg := &tls.Config{RootCAs: certPool}
			if tt.serverName != "" {
				tlsCfg.ServerName = tt.serverName
			}

			s := &SMTP{
				Host:        "127.0.0.1",
				Port:        ln.Addr().(*net.TCPAddr).Port,
				From:        "test@example.com",
				User:        "testuser",
				Pass:        "testpass",
				Timeout:     2 * time.Second,
				ImplicitTLS: true,
				TLSConfig:   tlsCfg,
			}
			err = s.Send(context.Background(), Message{To: "bob@example.com", Subject: "test", Body: "test"})
			if err == nil {
				t.Fatal("Send should fail on hostname mismatch")
			}
			var hostnameErr x509.HostnameError
			if !errors.As(err, &hostnameErr) {
				t.Fatalf("error should be x509.HostnameError, got: %T: %v", err, err)
			}

			// The handshake fails before any SMTP command is read, so no EHLO, AUTH, MAIL or DATA is sent.
			cmds := fs.receivedCommands()
			if len(cmds) != 0 {
				t.Fatalf("expected no commands after handshake failure, got: %v", cmds)
			}

			// Verify the server accepted exactly one connection (proves the empty-commands check isn't vacuous).
			fs.mu.Lock()
			connCount := fs.connCount
			fs.mu.Unlock()
			if connCount != 1 {
				t.Fatalf("expected exactly 1 connection, got %d", connCount)
			}
		})
	}
}

func TestSMTPSendPort465IPSANTrustedChain(t *testing.T) {
	cert := genTestCertIPOnly(t, "127.0.0.1")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	fs := &fakeServer{ln: ln, cert: &cert, t: t, closeCh: make(chan struct{})}
	go fs.serve()

	certPool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse test cert: %v", err)
	}
	certPool.AddCert(parsed)

	// No ServerName, so it uses Host 127.0.0.1, which matches the IP SAN
	s := &SMTP{
		Host:        "127.0.0.1",
		Port:        ln.Addr().(*net.TCPAddr).Port,
		From:        "test@example.com",
		User:        "testuser",
		Pass:        "testpass",
		Timeout:     2 * time.Second,
		ImplicitTLS: true,
		TLSConfig:   &tls.Config{RootCAs: certPool},
	}
	err = s.Send(context.Background(), Message{To: "bob@example.com", Subject: "test", Body: "test"})
	if err != nil {
		var hostnameErr x509.HostnameError
		if errors.As(err, &hostnameErr) {
			t.Fatalf("Send should succeed with matching IP SAN, got HostnameError: %v", err)
		}
		t.Fatalf("Send should succeed with matching IP SAN, got: %v", err)
	}

	// Verify handshake succeeded and SMTP commands were sent
	cmds := fs.receivedCommands()
	hasEHLO := false
	for _, cmd := range cmds {
		if strings.HasPrefix(cmd, "EHLO") || strings.HasPrefix(cmd, "HELO") {
			hasEHLO = true
			break
		}
	}
	if !hasEHLO {
		t.Fatalf("expected EHLO/HELO after successful handshake, got: %v", cmds)
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
	t.Run("ALLOW_PLAINTEXT alone", func(t *testing.T) {
		t.Setenv("PEERLINE_SMTP_HOST", "localhost")
		t.Setenv("PEERLINE_SMTP_FROM", "test@example.com")
		t.Setenv("PEERLINE_SMTP_ALLOW_PLAINTEXT", "1")
		if _, err := FromEnv(nil); err == nil || !strings.Contains(err.Error(), "PEERLINE_SMTP_REQUIRE_TLS") {
			t.Fatalf("want rename error, got %v", err)
		}
	})

	t.Run("both ALLOW_PLAINTEXT and REQUIRE_TLS set", func(t *testing.T) {
		t.Setenv("PEERLINE_SMTP_HOST", "localhost")
		t.Setenv("PEERLINE_SMTP_FROM", "test@example.com")
		t.Setenv("PEERLINE_SMTP_ALLOW_PLAINTEXT", "1")
		t.Setenv("PEERLINE_SMTP_REQUIRE_TLS", "false")
		if _, err := FromEnv(nil); err == nil || !strings.Contains(err.Error(), "PEERLINE_SMTP_REQUIRE_TLS") {
			t.Fatalf("want rename error, got %v", err)
		}
	})
}

func TestSMTPProbeCredentialsWithoutSTARTTLS(t *testing.T) {
	// This test verifies that credentials without STARTTLS on a non-loopback host
	// produces a fatal error. Probe uses PlainAuth's exact three literals to predict
	// what Send will do, so 127.0.0.2 and expanded ::1 are NOT considered loopback.
	tests := []struct {
		name string
		host string
	}{
		{"non-loopback hostname", "relay.example.test"},
		{"127.0.0.2 (not in PlainAuth's set)", "127.0.0.2"},
		{"expanded ::1 (not in PlainAuth's set)", "0:0:0:0:0:0:0:1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newFakeServer(t, false, nil) // no STARTTLS
			defer srv.close()

			dial := (&net.Dialer{}).DialContext
			s := &SMTP{
				Host:           tt.host,
				Port:           srv.port(),
				User:           "u",
				Pass:           "p",
				Timeout:        2 * time.Second,
				AllowPlaintext: true,
				dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					// Redirect to the fake server
					return dial(ctx, network, srv.addr())
				},
			}
			err := s.Probe(context.Background())

			if err == nil {
				t.Fatal("Probe should return error for credentials without STARTTLS on non-loopback host")
			}
			if errors.Is(err, ErrRelayUnreachable) {
				t.Fatalf("want fatal error, got ErrRelayUnreachable: %v", err)
			}
			if !strings.Contains(err.Error(), "PLAIN auth") {
				t.Fatalf("error should mention PLAIN auth, got: %v", err)
			}
		})
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
		err = s.Probe(context.Background())
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
		err := s.Probe(context.Background())
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
		err := s.Probe(context.Background())
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
		err = s.Probe(context.Background())
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
		err = s.Probe(context.Background())
		if err == nil {
			t.Fatal("probe should return error for 4xx greeting")
		}
		if !errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("4xx greeting should be ErrRelayUnreachable, got: %v", err)
		}
	})

	t.Run("AllowPlaintext true: STARTTLS offered = handshake runs", func(t *testing.T) {
		cert := genTestCert(t, "localhost")
		srv := newFakeServer(t, true, &cert)
		defer srv.close()

		certPool := x509.NewCertPool()
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse test cert: %v", err)
		}
		certPool.AddCert(parsed)

		s := &SMTP{
			Host:           "127.0.0.1",
			Port:           srv.port(),
			Timeout:        2 * time.Second,
			AllowPlaintext: true,
			TLSConfig:      &tls.Config{RootCAs: certPool, ServerName: "localhost"},
		}
		err = s.Probe(context.Background())
		if err != nil {
			t.Fatalf("probe should succeed with AllowPlaintext and good cert: %v", err)
		}
		// Verify STARTTLS was actually negotiated
		cmds := srv.receivedCommands()
		hasSTARTTLS := false
		for _, cmd := range cmds {
			if cmd == "STARTTLS" {
				hasSTARTTLS = true
				break
			}
		}
		if !hasSTARTTLS {
			t.Fatal("STARTTLS handshake should have been negotiated")
		}
	})

	t.Run("AllowPlaintext true: STARTTLS absent = passes", func(t *testing.T) {
		srv := newFakeServer(t, false, nil)
		defer srv.close()

		s := &SMTP{
			Host:           "127.0.0.1",
			Port:           srv.port(),
			Timeout:        2 * time.Second,
			AllowPlaintext: true,
		}
		err := s.Probe(context.Background())
		if err != nil {
			t.Fatalf("probe should succeed with AllowPlaintext and no STARTTLS: %v", err)
		}
	})

	t.Run("AllowPlaintext true: STARTTLS offered with bad cert = fatal", func(t *testing.T) {
		cert := genTestCert(t, "localhost")
		srv := newFakeServer(t, true, &cert)
		defer srv.close()

		s := &SMTP{
			Host:           "127.0.0.1",
			Port:           srv.port(),
			Timeout:        2 * time.Second,
			AllowPlaintext: true,
			// Use explicit empty RootCAs pool to fail cert validation (no system roots)
			TLSConfig: &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "localhost"},
		}
		err := s.Probe(context.Background())
		if err == nil {
			t.Fatal("probe should fail on bad cert even with AllowPlaintext")
		}
		if errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("cert error should be fatal, not ErrRelayUnreachable: %v", err)
		}
	})

	t.Run("STARTTLS with expired cert = ErrRelayUnreachable", func(t *testing.T) {
		cert := genExpiredTestCert(t, "localhost")
		srv := newFakeServer(t, true, &cert)
		defer srv.close()

		certPool := x509.NewCertPool()
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse test cert: %v", err)
		}
		certPool.AddCert(parsed)

		s := &SMTP{
			Host:      "127.0.0.1",
			Port:      srv.port(),
			Timeout:   2 * time.Second,
			TLSConfig: &tls.Config{RootCAs: certPool, ServerName: "localhost"},
		}
		err = s.Probe(context.Background())
		if err == nil {
			t.Fatal("probe should fail on expired cert")
		}
		if !errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("expired cert should be ErrRelayUnreachable, got: %v", err)
		}
		if !strings.Contains(err.Error(), "expired") {
			t.Fatalf("expected expired cert message, got: %v", err)
		}
	})

	t.Run("STARTTLS with not-yet-valid cert = fatal (clock skew)", func(t *testing.T) {
		cert := genTestCertWithValidity(t, "localhost", time.Now().Add(time.Hour), time.Now().Add(2*time.Hour))
		srv := newFakeServer(t, true, &cert)
		defer srv.close()

		certPool := x509.NewCertPool()
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse test cert: %v", err)
		}
		certPool.AddCert(parsed)

		s := &SMTP{
			Host:      "127.0.0.1",
			Port:      srv.port(),
			Timeout:   2 * time.Second,
			TLSConfig: &tls.Config{RootCAs: certPool, ServerName: "localhost"},
		}
		err = s.Probe(context.Background())
		if err == nil {
			t.Fatal("probe should fail on not-yet-valid cert")
		}
		if errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("not-yet-valid cert should be fatal, not ErrRelayUnreachable (clock skew): %v", err)
		}
		if !strings.Contains(err.Error(), "not yet valid") {
			t.Fatalf("error should mention 'not yet valid', got: %v", err)
		}
		if !strings.Contains(err.Error(), "check the host clock") {
			t.Fatalf("error should mention 'check the host clock', got: %v", err)
		}
	})

	t.Run("STARTTLS expired+self-signed = fatal", func(t *testing.T) {
		cert := genExpiredTestCert(t, "localhost")
		srv := newFakeServer(t, true, &cert)
		defer srv.close()

		s := &SMTP{
			Host:    "127.0.0.1",
			Port:    srv.port(),
			Timeout: 2 * time.Second,
			// Use explicit empty RootCAs pool (self-signed won't be trusted)
			TLSConfig: &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "localhost"},
		}
		err := s.Probe(context.Background())
		if err == nil {
			t.Fatal("probe should fail on expired+self-signed cert")
		}
		if errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("expired+self-signed should be fatal, not ErrRelayUnreachable: %v", err)
		}
	})

	t.Run("STARTTLS expired+wrong-host = fatal", func(t *testing.T) {
		// Control: see 'STARTTLS with expired cert = ErrRelayUnreachable' (same cert expiry, matching host -> warn)
		cert := genExpiredTestCert(t, "wronghost.example.com")
		srv := newFakeServer(t, true, &cert)
		defer srv.close()

		certPool := x509.NewCertPool()
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse test cert: %v", err)
		}
		certPool.AddCert(parsed)

		s := &SMTP{
			Host:      "127.0.0.1",
			Port:      srv.port(),
			Timeout:   2 * time.Second,
			TLSConfig: &tls.Config{RootCAs: certPool, ServerName: "localhost"},
		}
		err = s.Probe(context.Background())
		if err == nil {
			t.Fatal("probe should fail on expired+wrong-host cert")
		}
		if errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("expired+wrong-host should be fatal, not ErrRelayUnreachable: %v", err)
		}
		// The re-check at alternate time must still fail on hostname, but the original
		// error (expiry) is what gets returned. Verify it's a certificate error.
		var x509Invalid x509.CertificateInvalidError
		if !errors.As(err, &x509Invalid) {
			t.Fatalf("error should contain x509.CertificateInvalidError, got: %T: %v", err, err)
		}
		// Verify it's expired (not a different invalid reason)
		if x509Invalid.Reason != x509.Expired {
			t.Fatalf("certificate error reason should be Expired, got: %v", x509Invalid.Reason)
		}
	})

	t.Run("STARTTLS expired cert re-check respects caller context timeout", func(t *testing.T) {
		cert := genExpiredTestCert(t, "localhost")
		srv := newFakeServerWithOptions(t, true, &cert, true) // Stall the second connection (the re-check)
		defer srv.close()

		certPool := x509.NewCertPool()
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse test cert: %v", err)
		}
		certPool.AddCert(parsed)

		// Use a very short timeout - the re-check should respect it and fail quickly
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		s := &SMTP{
			Host:      "127.0.0.1",
			Port:      srv.port(),
			Timeout:   5 * time.Second,
			TLSConfig: &tls.Config{RootCAs: certPool, ServerName: "localhost"},
		}
		start := time.Now()
		err = s.Probe(ctx)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("probe should fail on expired cert")
		}
		// The re-check should respect the caller's short timeout and return quickly
		if elapsed > 300*time.Millisecond {
			t.Fatalf("probe took %v, should respect caller's short timeout and return within ~300ms", elapsed)
		}
	})

	t.Run("STARTTLS expired intermediate under trusted root = expiry-only warn", func(t *testing.T) {
		// #246 and Architect P1-2: expired intermediate under a trusted root.
		// The leaf must be issued while the intermediate was valid, so the re-check succeeds.
		now := time.Now()
		leafCert, rootCert := genTestCertChain(t, "localhost",
			now.Add(-3*time.Hour), now.Add(24*time.Hour), // leaf: issued 3h ago, valid for 24h more
			now.Add(-4*time.Hour), now.Add(-time.Hour)) // intermediate: issued 4h ago, expired 1h ago

		srv := newFakeServer(t, true, &leafCert)
		defer srv.close()

		// Trust the root
		certPool := x509.NewCertPool()
		certPool.AddCert(rootCert)

		s := &SMTP{
			Host:      "127.0.0.1",
			Port:      srv.port(),
			Timeout:   2 * time.Second,
			TLSConfig: &tls.Config{RootCAs: certPool, ServerName: "localhost"},
		}
		err := s.Probe(context.Background())
		if err == nil {
			t.Fatal("probe should fail on expired intermediate")
		}
		// The expiry-only error should be ErrRelayUnreachable (transient/warn)
		if !errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("expired intermediate under trusted root should be ErrRelayUnreachable (expiry-only warn), got: %v", err)
		}
		// Assert the exact message text the code emits for this case
		if !strings.Contains(err.Error(), "relay certificate expired") {
			t.Fatalf("error should contain 'relay certificate expired', got: %v", err)
		}
	})

	t.Run("STARTTLS expired intermediate under untrusted root = fatal", func(t *testing.T) {
		// #246: expired intermediate under an untrusted (or no) root.
		now := time.Now()
		leafCert, _ := genTestCertChain(t, "localhost",
			now.Add(-3*time.Hour), now.Add(24*time.Hour), // leaf: issued 3h ago, valid for 24h more
			now.Add(-4*time.Hour), now.Add(-time.Hour)) // intermediate: issued 4h ago, expired 1h ago

		srv := newFakeServer(t, true, &leafCert)
		defer srv.close()

		// Don't trust the root - use empty RootCAs pool
		s := &SMTP{
			Host:      "127.0.0.1",
			Port:      srv.port(),
			Timeout:   2 * time.Second,
			TLSConfig: &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "localhost"},
		}
		err := s.Probe(context.Background())
		if err == nil {
			t.Fatal("probe should fail on expired intermediate under untrusted root")
		}
		// Should be fatal, not ErrRelayUnreachable
		if errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("expired intermediate under untrusted root should be fatal, not ErrRelayUnreachable: %v", err)
		}
		// Positive control: assert STARTTLS was attempted
		cmds := srv.receivedCommands()
		hasSTARTTLS := false
		for _, cmd := range cmds {
			if cmd == "STARTTLS" {
				hasSTARTTLS = true
				break
			}
		}
		if !hasSTARTTLS {
			t.Fatalf("STARTTLS not attempted: %v", cmds)
		}
		// With untrusted root + expired intermediate, x509 checks expiry first.
		// The re-check also fails (because root is untrusted), so isExpiryOnlyError returns false,
		// and we get the original CertificateInvalidError (expiry), not wrapped in ErrRelayUnreachable.
		// This is correct: a fatal configuration error that happens to have an expired cert too.
		var x509Invalid x509.CertificateInvalidError
		if !errors.As(err, &x509Invalid) || x509Invalid.Reason != x509.Expired {
			t.Fatalf("error should be x509.CertificateInvalidError with Expired reason (because x509 checks expiry before trust), got: %T %v", err, err)
		}
	})

	t.Run("STARTTLS valid cert under untrusted root = fatal", func(t *testing.T) {
		// #335 item 2 and Architect P3: a currently valid but untrusted (self-signed) cert.
		// This should be fatal (UnknownAuthorityError), not ErrRelayUnreachable.
		cert := genTestCert(t, "localhost")
		srv := newFakeServer(t, true, &cert)
		defer srv.close()

		// Don't trust it - use empty RootCAs pool
		s := &SMTP{
			Host:      "127.0.0.1",
			Port:      srv.port(),
			Timeout:   2 * time.Second,
			TLSConfig: &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "localhost"},
		}
		err := s.Probe(context.Background())
		if err == nil {
			t.Fatal("probe should fail on untrusted cert")
		}
		// Should be fatal, not ErrRelayUnreachable
		if errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("untrusted cert should be fatal, not ErrRelayUnreachable: %v", err)
		}
		// Positive control: assert STARTTLS was attempted
		cmds := srv.receivedCommands()
		hasSTARTTLS := false
		for _, cmd := range cmds {
			if cmd == "STARTTLS" {
				hasSTARTTLS = true
				break
			}
		}
		if !hasSTARTTLS {
			t.Fatalf("STARTTLS not attempted: %v", cmds)
		}
		// Assert the error is an x509 UnknownAuthorityError
		var x509Unknown x509.UnknownAuthorityError
		if !errors.As(err, &x509Unknown) {
			t.Fatalf("error should be x509.UnknownAuthorityError, got: %T %v", err, err)
		}
	})

	t.Run("STARTTLS expired+untrusted-CA = fatal", func(t *testing.T) {
		cert := genExpiredTestCert(t, "localhost")
		srv := newFakeServer(t, true, &cert)
		defer srv.close()

		// Create a different CA pool without our cert
		otherCert := genTestCert(t, "other.example.com")
		certPool := x509.NewCertPool()
		otherParsed, err := x509.ParseCertificate(otherCert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse other cert: %v", err)
		}
		certPool.AddCert(otherParsed)

		s := &SMTP{
			Host:      "127.0.0.1",
			Port:      srv.port(),
			Timeout:   2 * time.Second,
			TLSConfig: &tls.Config{RootCAs: certPool, ServerName: "localhost"},
		}
		err = s.Probe(context.Background())
		if err == nil {
			t.Fatal("probe should fail on expired+untrusted cert")
		}
		if errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("expired+untrusted should be fatal, not ErrRelayUnreachable: %v", err)
		}
	})

	t.Run("STARTTLS wrong-hostname on TRUSTED chain = fatal", func(t *testing.T) {
		cert := genTestCert(t, "wronghost.example.com")
		srv := newFakeServer(t, true, &cert)
		defer srv.close()

		certPool := x509.NewCertPool()
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse test cert: %v", err)
		}
		certPool.AddCert(parsed)

		s := &SMTP{
			Host:      "127.0.0.1",
			Port:      srv.port(),
			Timeout:   2 * time.Second,
			TLSConfig: &tls.Config{RootCAs: certPool, ServerName: "localhost"},
		}
		err = s.Probe(context.Background())
		if err == nil {
			t.Fatal("probe should fail on hostname mismatch")
		}
		if errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("hostname mismatch should be fatal, not ErrRelayUnreachable: %v", err)
		}
		// Verify STARTTLS was attempted
		cmds := srv.receivedCommands()
		hasSTARTTLS := false
		for _, cmd := range cmds {
			if cmd == "STARTTLS" {
				hasSTARTTLS = true
				break
			}
		}
		if !hasSTARTTLS {
			t.Fatal("STARTTLS should have been attempted")
		}
		// Verify it's a hostname error
		var hostnameErr x509.HostnameError
		if !errors.As(err, &hostnameErr) {
			t.Fatalf("error should be x509.HostnameError, got: %T: %v", err, err)
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
		err = s.Probe(context.Background())
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
		err = s.Probe(context.Background())
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
		err = s.Probe(context.Background())
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
		err = s.Probe(context.Background())
		if err == nil {
			t.Fatal("probe should return error for closed port")
		}
		if !errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("closed port should be ErrRelayUnreachable, got: %v", err)
		}
	})

	t.Run("port 465 with expired cert = ErrRelayUnreachable", func(t *testing.T) {
		cert := genExpiredTestCert(t, "localhost")
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		fs := &fakeServer{ln: ln, cert: &cert, t: t}
		go fs.serve()

		certPool := x509.NewCertPool()
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse test cert: %v", err)
		}
		certPool.AddCert(parsed)

		s := &SMTP{
			Host:        "127.0.0.1",
			Port:        ln.Addr().(*net.TCPAddr).Port,
			Timeout:     2 * time.Second,
			ImplicitTLS: true,
			TLSConfig:   &tls.Config{RootCAs: certPool, ServerName: "localhost"},
		}
		err = s.Probe(context.Background())
		if err == nil {
			t.Fatal("probe should fail on expired cert")
		}
		if !errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("expired cert should be ErrRelayUnreachable, got: %v", err)
		}
		if !strings.Contains(err.Error(), "expired") {
			t.Fatalf("expected expired cert message, got: %v", err)
		}
	})

	t.Run("port 465 expired+self-signed = fatal", func(t *testing.T) {
		cert := genExpiredTestCert(t, "localhost")
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		fs := &fakeServer{ln: ln, cert: &cert, t: t}
		go fs.serve()

		s := &SMTP{
			Host:        "127.0.0.1",
			Port:        ln.Addr().(*net.TCPAddr).Port,
			Timeout:     2 * time.Second,
			ImplicitTLS: true,
			// Use explicit empty RootCAs pool (self-signed won't be trusted)
			TLSConfig: &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "localhost"},
		}
		err = s.Probe(context.Background())
		if err == nil {
			t.Fatal("probe should fail on expired+self-signed cert")
		}
		if errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("port 465 expired+self-signed should be fatal, not ErrRelayUnreachable: %v", err)
		}
	})

	t.Run("port 465 expired+wrong-host = fatal", func(t *testing.T) {
		cert := genExpiredTestCert(t, "wronghost.example.com")
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		fs := &fakeServer{ln: ln, cert: &cert, t: t}
		go fs.serve()

		certPool := x509.NewCertPool()
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse test cert: %v", err)
		}
		certPool.AddCert(parsed)

		s := &SMTP{
			Host:        "127.0.0.1",
			Port:        ln.Addr().(*net.TCPAddr).Port,
			Timeout:     2 * time.Second,
			ImplicitTLS: true,
			TLSConfig:   &tls.Config{RootCAs: certPool, ServerName: "localhost"},
		}
		err = s.Probe(context.Background())
		if err == nil {
			t.Fatal("probe should fail on expired+wrong-host cert")
		}
		if errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("port 465 expired+wrong-host should be fatal, not ErrRelayUnreachable: %v", err)
		}
	})

	t.Run("port 465 not-yet-valid cert = fatal (check the host clock)", func(t *testing.T) {
		cert := genTestCertWithValidity(t, "localhost", time.Now().Add(time.Hour), time.Now().Add(2*time.Hour))
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		fs := &fakeServer{ln: ln, cert: &cert, t: t, closeCh: make(chan struct{})}
		go fs.serve()

		certPool := x509.NewCertPool()
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse test cert: %v", err)
		}
		certPool.AddCert(parsed)

		s := &SMTP{
			Host:        "127.0.0.1",
			Port:        ln.Addr().(*net.TCPAddr).Port,
			Timeout:     2 * time.Second,
			ImplicitTLS: true,
			TLSConfig:   &tls.Config{RootCAs: certPool, ServerName: "localhost"},
		}
		err = s.Probe(context.Background())
		if err == nil {
			t.Fatal("probe should fail on not-yet-valid cert")
		}
		if errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("port 465 not-yet-valid cert should be fatal (clock skew), not ErrRelayUnreachable: %v", err)
		}
		if !strings.Contains(err.Error(), "not yet valid") {
			t.Fatalf("error should mention 'not yet valid', got: %v", err)
		}
		if !strings.Contains(err.Error(), "check the host clock") {
			t.Fatalf("error should mention 'check the host clock', got: %v", err)
		}
		if !strings.Contains(err.Error(), "port 465") {
			t.Fatalf("error should mention 'port 465', got: %v", err)
		}
		// Assert the underlying x509 error is still accessible
		var x509Invalid x509.CertificateInvalidError
		if !errors.As(err, &x509Invalid) {
			t.Fatalf("error should wrap x509.CertificateInvalidError, got: %T %v", err, err)
		}
	})

	t.Run("port 465 wrong-hostname on TRUSTED chain = fatal", func(t *testing.T) {
		cert := genTestCert(t, "wronghost.example.com")
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		fs := &fakeServer{ln: ln, cert: &cert, t: t, closeCh: make(chan struct{})}
		go fs.serve()

		certPool := x509.NewCertPool()
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse test cert: %v", err)
		}
		certPool.AddCert(parsed)

		s := &SMTP{
			Host:        "127.0.0.1",
			Port:        ln.Addr().(*net.TCPAddr).Port,
			Timeout:     2 * time.Second,
			ImplicitTLS: true,
			TLSConfig:   &tls.Config{RootCAs: certPool, ServerName: "localhost"},
		}
		err = s.Probe(context.Background())
		if err == nil {
			t.Fatal("probe should fail on hostname mismatch")
		}
		if errors.Is(err, ErrRelayUnreachable) {
			t.Fatalf("port 465 hostname mismatch should be fatal, not ErrRelayUnreachable: %v", err)
		}
		// Verify it's a hostname error
		var hostnameErr x509.HostnameError
		if !errors.As(err, &hostnameErr) {
			t.Fatalf("error should be x509.HostnameError, got: %T: %v", err, err)
		}
	})

	t.Run("port 465 Probe with empty ServerName", func(t *testing.T) {
		cert := genTestCert(t, "localhost")
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		fs := &fakeServer{ln: ln, cert: &cert, t: t, closeCh: make(chan struct{})}
		go fs.serve()

		certPool := x509.NewCertPool()
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse test cert: %v", err)
		}
		certPool.AddCert(parsed)

		s := &SMTP{
			Host:        "127.0.0.1",
			Port:        ln.Addr().(*net.TCPAddr).Port,
			Timeout:     2 * time.Second,
			ImplicitTLS: true,
			// Empty ServerName to verify the helper fills it in for Probe
			TLSConfig: &tls.Config{RootCAs: certPool},
		}
		err = s.Probe(context.Background())
		if err != nil {
			t.Fatalf("Probe should succeed with empty ServerName filled in: %v", err)
		}
	})

	t.Run("port 465 uses dialContext field and handles empty ServerName", func(t *testing.T) {
		cert := genTestCert(t, "localhost")
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
		defer tlsLn.Close()

		fs := &fakeServer{ln: tlsLn, cert: &cert, t: t, closeCh: make(chan struct{})}
		go fs.serve()

		certPool := x509.NewCertPool()
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse test cert: %v", err)
		}
		certPool.AddCert(parsed)

		dialCalled := false
		dial := (&net.Dialer{}).DialContext
		s := &SMTP{
			Host:        "127.0.0.1",
			Port:        tlsLn.Addr().(*net.TCPAddr).Port,
			From:        "test@example.com",
			Timeout:     2 * time.Second,
			ImplicitTLS: true,
			// Empty ServerName to verify the helper fills it in
			TLSConfig: &tls.Config{RootCAs: certPool},
			dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialCalled = true
				return dial(ctx, network, tlsLn.Addr().String())
			},
		}
		err = s.Send(context.Background(), Message{To: "bob@example.com", Subject: "test", Body: "test"})
		if err != nil {
			t.Fatalf("Send should succeed with dialContext hook: %v", err)
		}
		if !dialCalled {
			t.Fatal("dialContext hook should have been called for implicit TLS")
		}
		// Verify DATA was sent (handshake succeeded)
		cmds := fs.receivedCommands()
		hasDATA := false
		for _, cmd := range cmds {
			if cmd == "DATA" {
				hasDATA = true
				break
			}
		}
		if !hasDATA {
			t.Fatalf("DATA should have been sent (handshake succeeded), got: %v", cmds)
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

// TestLogFullBodyDefault verifies that FromEnv defaults to LogFullBody == false
// when PEERLINE_DEV_LOG_EMAIL_BODY is unset (issue #303).
func TestLogFullBodyDefault(t *testing.T) {
	// Unset PEERLINE_SMTP_HOST and PEERLINE_DEV_LOG_EMAIL_BODY to get Log sender with default
	t.Setenv("PEERLINE_SMTP_HOST", "")
	os.Unsetenv("PEERLINE_SMTP_HOST")
	t.Setenv("PEERLINE_DEV_LOG_EMAIL_BODY", "")
	os.Unsetenv("PEERLINE_DEV_LOG_EMAIL_BODY")

	sender, err := FromEnv(nil)
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	log, ok := sender.(Log)
	if !ok {
		t.Fatalf("FromEnv with no SMTP_HOST should return Log, got %T", sender)
	}
	if log.LogFullBody {
		t.Error("LogFullBody should be false by default, got true")
	}

	// Verify that setting PEERLINE_DEV_LOG_EMAIL_BODY=1 enables LogFullBody
	t.Setenv("PEERLINE_DEV_LOG_EMAIL_BODY", "1")
	sender, err = FromEnv(nil)
	if err != nil {
		t.Fatalf("FromEnv with DEV_LOG_EMAIL_BODY=1: %v", err)
	}
	log, ok = sender.(Log)
	if !ok {
		t.Fatalf("FromEnv should return Log, got %T", sender)
	}
	if !log.LogFullBody {
		t.Error("LogFullBody should be true with PEERLINE_DEV_LOG_EMAIL_BODY=1, got false")
	}
}
