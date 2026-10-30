package main

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/sysrex/peerline/internal/mailer"
)

// checkLogBody warns when the dev mailer logs full email bodies (live invite
// and verification tokens) and refuses to do so on a non-loopback listener.
func checkLogBody(log *slog.Logger, ml mailer.Sender, addr string) error {
	l, ok := ml.(mailer.Log)
	if !ok || !l.LogFullBody {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("PEERLINE_DEV_LOG_EMAIL_BODY=1 logs live invite and verification tokens and requires a loopback listen address, got %q", addr)
	}
	log.Warn("PEERLINE_DEV_LOG_EMAIL_BODY=1: full email bodies (invite codes, verification tokens) are written to the log")
	return nil
}
