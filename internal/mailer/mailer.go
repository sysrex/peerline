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
	"crypto/x509"
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

// ErrRelayUnreachable is returned by Probe when the SMTP server is unreachable
// (connection refused, timeout, reset, or SMTP-level greeting/EHLO errors).
// Startup logs a warning and continues; runtime Send will retry.
var ErrRelayUnreachable = errors.New("smtp relay unreachable")

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

// Log is the dev-mode sender: it logs the message metadata and reports success.
type Log struct {
	Logger      *slog.Logger
	LogFullBody bool // when true, logs the full body (opt-in with PEERLINE_DEV_LOG_EMAIL_BODY=1)
}

func (l Log) Mode() string { return "log" }

func (l Log) Send(_ context.Context, m Message) error {
	lg := l.Logger
	if lg == nil {
		lg = slog.Default()
	}
	if l.LogFullBody {
		lg.Warn("SMTP not configured; email logged instead of sent (dev mode, PEERLINE_DEV_LOG_EMAIL_BODY=1: FULL BODY LOGGED)",
			"to", m.To, "subject", m.Subject, "body", m.Body)
	} else {
		lg.Warn("SMTP not configured; email logged instead of sent (dev mode)",
			"to", m.To, "subject", m.Subject, "body_len", len(m.Body))
	}
	return nil
}

// ---- SMTP ----

// SMTP sends via an SMTP relay. Port 465 uses implicit TLS; any other port
// uses STARTTLS when the server offers it.
type SMTP struct {
	Host, User, Pass, From string
	Port                   int
	Timeout                time.Duration
	// AllowPlaintext permits sending without STARTTLS on non-465 ports.
	// Zero value (false) requires TLS, failing the send if STARTTLS is not offered.
	// Only set to true for loopback relays or with explicit PEERLINE_SMTP_REQUIRE_TLS=false.
	AllowPlaintext bool
	// ImplicitTLS is true for port 465 (implicit TLS without STARTTLS).
	ImplicitTLS bool
	// TLSConfig is optional (tests); defaults to ServerName=Host.
	TLSConfig *tls.Config
	// dialContext is the dialer for SMTP connections (tests).
	// nil means the default net.Dialer{}.DialContext.
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (s *SMTP) Mode() string { return "smtp" }

// tlsConfigForImplicitTLS clones cfg and ensures ServerName is set to s.Host.
// This matches the old tls.Dialer behavior: DialContext filled in an empty
// Config.ServerName from the addr host. Raw tls.Client doesn't, so we do it here.
func (s *SMTP) tlsConfigForImplicitTLS(cfg *tls.Config) *tls.Config {
	clone := cfg.Clone()
	if clone.ServerName == "" {
		clone.ServerName = s.Host
	}
	return clone
}

// checkSTARTTLS validates STARTTLS policy: returns an error if STARTTLS is required but not offered.
func (s *SMTP) checkSTARTTLS(offered bool) error {
	if !offered && !s.AllowPlaintext {
		return errors.New("STARTTLS required but not offered by server (set PEERLINE_SMTP_REQUIRE_TLS=false to allow cleartext)")
	}
	return nil
}

// IsLoopback returns true if host is a loopback address.
// Recognizes "localhost" by name, and any IPv4 or IPv6 loopback address
// (including expanded forms like "0:0:0:0:0:0:0:1" or "127.0.0.2").
func IsLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// isPlainAuthLoopback reports whether host is one of the three exact literals
// that net/smtp's PlainAuth accepts: "localhost", "127.0.0.1", or "::1".
// PlainAuth refuses to send credentials in cleartext unless the hostname
// matches one of these three strings exactly, without DNS resolution or IP parsing.
// Probe uses this narrower check (rather than IsLoopback) to predict whether
// Send's PlainAuth will accept or refuse credentials when STARTTLS is absent.
// Differs from IsLoopback, which accepts all loopback IPs (127.0.0.2, expanded IPv6 forms, etc.).
func isPlainAuthLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// isLoopbackAddr reports whether a connection's remote address is a loopback IP.
func isLoopbackAddr(a net.Addr) bool {
	tcp, ok := a.(*net.TCPAddr)
	return ok && tcp.IP.IsLoopback()
}

// FromEnv builds a Sender from PEERLINE_SMTP_HOST/PORT/USER/PASS/FROM.
// If PEERLINE_SMTP_HOST is unset it returns a dev-mode Log sender.
func FromEnv(lg *slog.Logger) (Sender, error) {
	host := strings.TrimSpace(os.Getenv("PEERLINE_SMTP_HOST"))
	if host == "" {
		logBody := os.Getenv("PEERLINE_DEV_LOG_EMAIL_BODY") == "1"
		return Log{Logger: lg, LogFullBody: logBody}, nil
	}
	// Reject IPv6 zone IDs (e.g. fe80::1%eth0) before building bracket hints
	if strings.Contains(host, "%") {
		return nil, errors.New("PEERLINE_SMTP_HOST: IPv6 zone IDs are not supported in PEERLINE_SMTP_HOST")
	}
	if strings.Contains(host, "[") || strings.Contains(host, "]") {
		var suggested string
		// Try to parse as [host]:port
		if bareHost, port, err := net.SplitHostPort(host); err == nil {
			suggested = fmt.Sprintf("use %s with PEERLINE_SMTP_PORT=%s", bareHost, port)
		} else if len(host) > 2 && host[0] == '[' && host[len(host)-1] == ']' {
			// Exactly [addr] format - but check inner value doesn't contain brackets
			inner := host[1 : len(host)-1]
			if strings.Contains(inner, "[") || strings.Contains(inner, "]") {
				suggested = "use a valid hostname or IP"
			} else {
				suggested = fmt.Sprintf("use %s", inner)
			}
		} else {
			// Malformed brackets
			suggested = "use a valid hostname or IP"
		}
		return nil, fmt.Errorf("PEERLINE_SMTP_HOST: bracketed address %q not allowed (%s)", host, suggested)
	}
	// Reject host:port syntax (port must be in PEERLINE_SMTP_PORT), but allow IPv6 addresses
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		// If it has a port, extract the bare host and port for the hint
		bareHost, portStr, err := net.SplitHostPort(host)
		if err == nil {
			return nil, fmt.Errorf("PEERLINE_SMTP_HOST: host %q contains ':' (use %s with PEERLINE_SMTP_PORT=%s for the port)", host, bareHost, portStr)
		}
		return nil, fmt.Errorf("PEERLINE_SMTP_HOST: host %q contains ':' (use PEERLINE_SMTP_PORT for the port)", host)
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
	if os.Getenv("PEERLINE_SMTP_ALLOW_PLAINTEXT") != "" {
		return nil, errors.New("PEERLINE_SMTP_ALLOW_PLAINTEXT was renamed: use PEERLINE_SMTP_REQUIRE_TLS=false")
	}
	// Default: allow plaintext only for loopback, require TLS otherwise
	allowPlaintext := IsLoopback(host)
	if v := os.Getenv("PEERLINE_SMTP_REQUIRE_TLS"); v != "" {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes":
			allowPlaintext = false
		case "0", "false", "no":
			allowPlaintext = true
		default:
			return nil, fmt.Errorf("PEERLINE_SMTP_REQUIRE_TLS: invalid value %q (must be 1/0/true/false/yes/no)", v)
		}
	}
	implicitTLS := port == 465
	return &SMTP{
		Host:           host,
		Port:           port,
		User:           user,
		Pass:           pass,
		From:           from,
		Timeout:        10 * time.Second,
		AllowPlaintext: allowPlaintext,
		ImplicitTLS:    implicitTLS,
	}, nil
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

	dial := s.dialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	var conn net.Conn
	if s.ImplicitTLS {
		conn, err = dial(ctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("smtp dial: %w", err)
		}
		// Perform TLS handshake on the established connection
		implicitCfg := s.tlsConfigForImplicitTLS(tlsCfg)
		tlsConn := tls.Client(conn, implicitCfg)
		if dl, ok := ctx.Deadline(); ok {
			tlsConn.SetDeadline(dl)
		}
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return fmt.Errorf("smtp tls handshake: %w", err)
		}
		conn = tlsConn
	} else {
		conn, err = dial(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	if IsLoopback(s.Host) && !isLoopbackAddr(conn.RemoteAddr()) {
		conn.Close()
		return fmt.Errorf("smtp dial: %s resolved to non-loopback %s", s.Host, conn.RemoteAddr())
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
	if !s.ImplicitTLS {
		hasSTARTTLS, _ := c.Extension("STARTTLS")
		if err := s.checkSTARTTLS(hasSTARTTLS); err != nil {
			return fmt.Errorf("smtp: %w", err)
		}
		if hasSTARTTLS {
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

// Probe connects to the SMTP server, checks for STARTTLS availability, and disconnects.
// It fails fast (returns a non-nil error) only for provable misconfiguration:
// x509 or TLS errors (certificate problems, handshake failures) and missing STARTTLS when required.
// Network errors (timeouts, connection refused, resets), SMTP greeting/EHLO errors, and
// all other transient failures return an error wrapping ErrRelayUnreachable; the caller
// should log a warning and continue (Send will retry at runtime).
func (s *SMTP) Probe(ctx context.Context) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	// Use a shorter timeout for the probe
	if timeout > 3*time.Second {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	tlsCfg := s.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}
	}

	dial := s.dialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	// Always do TCP dial first
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		// TCP dial failure: connection refused, timeout, no route, etc. - transient
		return fmt.Errorf("%w: %v", ErrRelayUnreachable, err)
	}
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}

	// For implicit TLS (port 465), perform TLS handshake now
	if s.ImplicitTLS {
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			// Check for not-yet-valid certificate (fatal: clock skew or misconfiguration)
			if isNotYetValid, wrappedErr := isNotYetValidError(err, tlsCfg, "TLS handshake failed on port 465"); isNotYetValid {
				return wrappedErr
			}
			// Check for expiry-only error (transient: relay state, not Peerline config)
			if s.isExpiryOnlyError(ctx, err, conn, tlsCfg) {
				return fmt.Errorf("%w: relay certificate expired (sends will fail until renewed): %v", ErrRelayUnreachable, err)
			}
			// Check if it's a certificate/TLS error (fatal) or a timeout/reset (transient)
			if isTLSError(err) {
				return fmt.Errorf("smtp probe: TLS handshake failed on port 465: %w", err)
			}
			return fmt.Errorf("%w: TLS handshake timeout/reset on port 465: %v", ErrRelayUnreachable, err)
		}
		conn = tlsConn
	}

	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		// SMTP greeting or protocol error - transient
		return fmt.Errorf("%w: SMTP greeting failed: %v", ErrRelayUnreachable, err)
	}
	defer c.Quit()

	// Explicitly call EHLO/HELO to catch EHLO failures
	if err := c.Hello("localhost"); err != nil {
		// EHLO/HELO failure (4xx/5xx response, timeout, reset) - transient
		return fmt.Errorf("%w: EHLO failed: %v", ErrRelayUnreachable, err)
	}

	if !s.ImplicitTLS {
		hasSTARTTLS, _ := c.Extension("STARTTLS")
		if err := s.checkSTARTTLS(hasSTARTTLS); err != nil {
			return fmt.Errorf("smtp probe: %s:%d: %w", s.Host, s.Port, err)
		}
		if !hasSTARTTLS && s.User != "" && !isPlainAuthLoopback(s.Host) {
			return fmt.Errorf("smtp probe: credentials are set but %s:%d offers no STARTTLS and is not loopback; PLAIN auth would be refused", s.Host, s.Port)
		}
		if hasSTARTTLS {
			// Actually perform the handshake to verify certs
			if err := c.StartTLS(tlsCfg); err != nil {
				// Check for not-yet-valid certificate (fatal: clock skew or misconfiguration)
				if isNotYetValid, wrappedErr := isNotYetValidError(err, tlsCfg, "STARTTLS handshake failed"); isNotYetValid {
					return wrappedErr
				}
				// Check for expiry-only error (transient: relay state, not Peerline config)
				if s.isExpiryOnlyError(ctx, err, conn, tlsCfg) {
					return fmt.Errorf("%w: relay certificate expired (sends will fail until renewed): %v", ErrRelayUnreachable, err)
				}
				if isTLSError(err) {
					return fmt.Errorf("smtp probe: STARTTLS handshake failed: %w", err)
				}
				return fmt.Errorf("%w: STARTTLS timeout/reset: %v", ErrRelayUnreachable, err)
			}
		}
	}
	return nil
}

// isNotYetValidError returns true if err is a certificate not-yet-valid error (NotBefore in the future).
// If true, it returns a wrapped error (mentions "check the host clock" and includes the stage).
// The stage parameter describes where the error occurred (e.g., "port 465" or "STARTTLS handshake").
func isNotYetValidError(err error, tlsCfg *tls.Config, stage string) (bool, error) {
	var x509Invalid x509.CertificateInvalidError
	if !errors.As(err, &x509Invalid) || x509Invalid.Reason != x509.Expired || x509Invalid.Cert == nil {
		return false, nil
	}
	// Use tlsCfg.Time if set (for tests), otherwise use time.Now()
	now := time.Now()
	if tlsCfg != nil && tlsCfg.Time != nil {
		now = tlsCfg.Time()
	}
	if now.Before(x509Invalid.Cert.NotBefore) {
		return true, fmt.Errorf("smtp probe: %s: certificate not yet valid (NotBefore=%v); check the host clock: %w",
			stage, x509Invalid.Cert.NotBefore.Format(time.RFC3339), err)
	}
	return false, nil
}

// isTLSError returns true if err is a certificate validation error or TLS protocol error.
// These are fatal configuration errors, not transient network errors.
// Note: x509 expiry errors require special handling (see isExpiryOnlyError) because Go reports
// expiry before checking hostname or trust, so a bare Reason == Expired check would hide config errors.
func isTLSError(err error) bool {
	if err == nil {
		return false
	}
	// Check for x509 certificate errors
	var x509Unknown x509.UnknownAuthorityError
	var x509Hostname x509.HostnameError
	var x509Invalid x509.CertificateInvalidError
	if errors.As(err, &x509Unknown) || errors.As(err, &x509Hostname) || errors.As(err, &x509Invalid) {
		return true
	}
	// Check for TLS errors
	var tlsCertVerify *tls.CertificateVerificationError
	var tlsRecordHeader tls.RecordHeaderError
	var tlsAlert tls.AlertError
	if errors.As(err, &tlsCertVerify) || errors.As(err, &tlsRecordHeader) || errors.As(err, &tlsAlert) {
		return true
	}
	return false
}

// isExpiryOnlyError returns true if err is a certificate expiry error (past NotAfter) and that is
// the ONLY problem (hostname and trust are valid). Go's x509 checks validity dates before
// hostname and trust, so Reason == Expired can mask config errors (wrong host, untrusted CA).
// We re-verify at a time when the cert would be valid to distinguish expiry-only (transient)
// from multi-problem certs (fatal config error).
// Not-yet-valid certificates (NotBefore in the future) are treated as fatal: they indicate
// clock skew or misconfiguration, not relay state.
//
// The re-verification makes a second connection to the same host:port with a modified TLS config
// (Time set to NotAfter - 1s). If that connection fails for any reason (network error, rate limit,
// timeout), the expired certificate is treated as fatal (safe side). A load-balanced relay could
// answer from a different backend with a different certificate; that is acceptable since Send
// verifies independently.
func (s *SMTP) isExpiryOnlyError(ctx context.Context, err error, conn net.Conn, tlsCfg *tls.Config) bool {
	var x509Invalid x509.CertificateInvalidError
	if !errors.As(err, &x509Invalid) || x509Invalid.Reason != x509.Expired {
		return false
	}
	if x509Invalid.Cert == nil {
		return false
	}
	// Not-yet-valid (NotBefore in the future) is fatal: indicates clock skew or misconfiguration
	// Use tlsCfg.Time if set (for tests), otherwise use time.Now()
	now := time.Now()
	if tlsCfg != nil && tlsCfg.Time != nil {
		now = tlsCfg.Time()
	}
	if now.Before(x509Invalid.Cert.NotBefore) {
		return false
	}
	// Cert is expired (past NotAfter). Check if it would be valid at NotAfter - 1s.
	// If that succeeds, expiry was the only problem (transient).

	recheckCfg := tlsCfg.Clone()
	fixedTime := x509Invalid.Cert.NotAfter.Add(-time.Second)
	recheckCfg.Time = func() time.Time { return fixedTime }

	// Re-handshake on a new connection to verify at the alternate time.
	// Use the caller's context so cancellation propagates; bound to 2s max.
	recheckCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	dial := s.dialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))

	if s.ImplicitTLS {
		// For implicit TLS, dial then upgrade
		recheckConn, err := dial(recheckCtx, "tcp", addr)
		if err != nil {
			return false
		}
		implicitCfg := s.tlsConfigForImplicitTLS(recheckCfg)
		tlsConn := tls.Client(recheckConn, implicitCfg)
		if deadline, ok := recheckCtx.Deadline(); ok {
			tlsConn.SetDeadline(deadline)
		}
		if err := tlsConn.HandshakeContext(recheckCtx); err == nil {
			tlsConn.Close()
			return true // Handshake succeeded at alternate time, so expiry was the only problem
		}
		recheckConn.Close()
		return false
	}

	// For STARTTLS, dial plaintext then upgrade
	recheckConn, err := dial(recheckCtx, "tcp", addr)
	if err != nil {
		return false
	}
	defer recheckConn.Close()

	if deadline, ok := recheckCtx.Deadline(); ok {
		recheckConn.SetDeadline(deadline)
	}

	c, err := smtp.NewClient(recheckConn, s.Host)
	if err != nil {
		return false
	}
	defer c.Quit()

	if err := c.Hello("localhost"); err != nil {
		return false
	}

	hasSTARTTLS, _ := c.Extension("STARTTLS")
	if !hasSTARTTLS {
		return false
	}

	if err := c.StartTLS(recheckCfg); err == nil {
		return true // STARTTLS succeeded at alternate time
	}
	return false
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
