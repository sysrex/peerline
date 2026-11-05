package store

import (
	"testing"
)

// TestDBFilePath tests DSN parsing to extract the actual file path.
// This matches the behavior of modernc.org/sqlite v1.61.0's newConn (conn.go:103-119).
func TestDBFilePath(t *testing.T) {
	tests := []struct {
		name     string
		dsn      string
		wantPath string
		wantMem  bool
	}{
		{
			name:     "plain memory",
			dsn:      ":memory:",
			wantPath: "",
			wantMem:  true,
		},
		{
			name:     "file URI memory",
			dsn:      "file::memory:",
			wantPath: "",
			wantMem:  true,
		},
		{
			name:     "file URI memory with query",
			dsn:      "file::memory:?cache=shared",
			wantPath: "",
			wantMem:  true,
		},
		{
			name:     "plain path with mode=memory query NOT memory",
			dsn:      "test.db?mode=memory",
			wantPath: "test.db",
			wantMem:  false,
		},
		{
			name:     "plain path with MODE=MEMORY query NOT memory",
			dsn:      "test.db?MODE=MEMORY",
			wantPath: "test.db",
			wantMem:  false,
		},
		{
			name:     "plain path with Mode=Memory query NOT memory",
			dsn:      "test.db?Mode=Memory",
			wantPath: "test.db",
			wantMem:  false,
		},
		{
			name:     "mode=rwc not memory",
			dsn:      "test.db?mode=rwc",
			wantPath: "test.db",
			wantMem:  false,
		},
		{
			name:     "plain file path",
			dsn:      "/data/peer.db",
			wantPath: "/data/peer.db",
			wantMem:  false,
		},
		{
			name:     "plain file with query",
			dsn:      "/data/peer.db?_pragma=foreign_keys(1)",
			wantPath: "/data/peer.db",
			wantMem:  false,
		},
		{
			name:     "file URI absolute triple slash",
			dsn:      "file:///data/peer.db",
			wantPath: "/data/peer.db",
			wantMem:  false,
		},
		{
			name:     "file URI absolute single slash",
			dsn:      "file:/data/peer.db",
			wantPath: "/data/peer.db",
			wantMem:  false,
		},
		{
			name:     "file URI relative",
			dsn:      "file:relative/peer.db",
			wantPath: "relative/peer.db",
			wantMem:  false,
		},
		{
			name:     "file URI with query",
			dsn:      "file:///data/peer.db?mode=ro",
			wantPath: "/data/peer.db",
			wantMem:  false,
		},
		{
			name:     "file URI with percent encoding",
			dsn:      "file:///tmp/my%20data.db",
			wantPath: "/tmp/my data.db",
			wantMem:  false,
		},
		{
			name:     "file URI with percent encoding and query",
			dsn:      "file:///tmp/my%20data.db?mode=ro",
			wantPath: "/tmp/my data.db",
			wantMem:  false,
		},
		{
			name:     "relative path",
			dsn:      "test.db",
			wantPath: "test.db",
			wantMem:  false,
		},
		{
			name:     "relative path with query",
			dsn:      "test.db?_pragma=busy_timeout(5000)",
			wantPath: "test.db",
			wantMem:  false,
		},
		{
			name:     "file URI with mode=memory then mode=rwc NOT memory",
			dsn:      "file:x.db?mode=memory&mode=rwc",
			wantPath: "x.db",
			wantMem:  false,
		},
		{
			name:     "file URI with mode=rwc then mode=memory IS memory",
			dsn:      "file:x.db?mode=rwc&mode=memory",
			wantPath: "",
			wantMem:  true,
		},
		{
			name:     "file URI with MODE=memory wrong key case NOT memory",
			dsn:      "file:x.db?MODE=memory",
			wantPath: "x.db",
			wantMem:  false,
		},
		{
			name:     "file URI with mode=MEMORY case-insensitive value IS memory",
			dsn:      "file:x.db?mode=MEMORY",
			wantPath: "",
			wantMem:  true,
		},
		{
			name:     "file URI with fragment",
			dsn:      "file:/tmp/test.db#section",
			wantPath: "/tmp/test.db",
			wantMem:  false,
		},
		{
			name:     "file URI with query and fragment",
			dsn:      "file:/tmp/test.db?mode=ro#section",
			wantPath: "/tmp/test.db",
			wantMem:  false,
		},
		{
			name:     "file://localhost/path",
			dsn:      "file://localhost/tmp/test.db",
			wantPath: "/tmp/test.db",
			wantMem:  false,
		},
		{
			name:     "file:// empty authority",
			dsn:      "file:///tmp/test.db",
			wantPath: "/tmp/test.db",
			wantMem:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotMem, err := dbFilePath(tt.dsn)
			if err != nil {
				t.Fatalf("dbFilePath(%q) error: %v", tt.dsn, err)
			}
			if gotPath != tt.wantPath {
				t.Errorf("dbFilePath(%q) path = %q, want %q", tt.dsn, gotPath, tt.wantPath)
			}
			if gotMem != tt.wantMem {
				t.Errorf("dbFilePath(%q) isMemory = %v, want %v", tt.dsn, gotMem, tt.wantMem)
			}
		})
	}
}
