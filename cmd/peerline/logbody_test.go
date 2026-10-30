package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/sysrex/peerline/internal/mailer"
)

func TestCheckLogBody(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	on, off := mailer.Log{LogFullBody: true}, mailer.Log{}
	for _, tc := range []struct {
		ml      mailer.Sender
		addr    string
		wantErr bool
	}{
		{on, "127.0.0.1:8787", false},
		{on, "localhost:8787", false},
		{on, "[::1]:8787", false},
		{on, "0.0.0.0:8787", true},
		{on, ":8787", true},
		{on, "example.com:8787", true},
		{off, "0.0.0.0:8787", false},
		{&mailer.SMTP{}, "0.0.0.0:8787", false},
	} {
		if err := checkLogBody(log, tc.ml, tc.addr); (err != nil) != tc.wantErr {
			t.Errorf("%T %q: err=%v wantErr=%v", tc.ml, tc.addr, err, tc.wantErr)
		}
	}
}
