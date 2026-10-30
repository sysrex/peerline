package version

import (
	"strings"
	"sync"
	"testing"
)

func TestInfo(t *testing.T) {
	info := Info()
	if info["version"] == "" {
		t.Error("version should not be empty")
	}
	if info["commit"] == "" {
		t.Error("commit should not be empty")
	}
	if info["build_time"] == "" {
		t.Error("build_time should not be empty")
	}

	// Should have all three keys
	if len(info) != 3 {
		t.Errorf("expected 3 keys, got %d", len(info))
	}

	// Calling again should return the same map (computed once)
	info2 := Info()
	if info["version"] != info2["version"] || info["commit"] != info2["commit"] || info["build_time"] != info2["build_time"] {
		t.Error("Info() should be computed once and return consistent values")
	}
}

func TestString(t *testing.T) {
	s := String()
	if s == "" {
		t.Error("version string should not be empty")
	}

	// Should contain version components
	info := Info()
	if !strings.Contains(s, info["version"]) {
		t.Errorf("version string should contain version %q", info["version"])
	}
	if !strings.Contains(s, info["commit"]) {
		t.Errorf("version string should contain commit %q", info["commit"])
	}
}

func TestShortCommit(t *testing.T) {
	short := ShortCommit()
	if short == "" {
		t.Error("short commit should not be empty")
	}

	info := Info()
	fullCommit := info["commit"]
	if fullCommit == "unknown" {
		if short != "unknown" {
			t.Errorf("short commit should be 'unknown' when full commit is 'unknown', got %q", short)
		}
	} else if len(fullCommit) > 12 {
		if len(short) != 12 {
			t.Errorf("short commit should be 12 chars, got %d (%q)", len(short), short)
		}
		if !strings.HasPrefix(fullCommit, short) {
			t.Errorf("short commit %q should be prefix of full commit %q", short, fullCommit)
		}
	}
}

func TestInfoWithInjectedValues(t *testing.T) {
	// This test must run in a separate process to reset sync.Once
	// Here we just document the expected behavior when ldflags are set
	t.Run("defaults", func(t *testing.T) {
		// Default version is "dev"
		if Version != "dev" && Version != "v1.0.0-test" {
			t.Logf("Version is set to non-default: %s", Version)
		}
	})
}

func TestInfoFallbackBehavior(t *testing.T) {
	// Save originals
	origCommit := Commit
	origBuildTime := BuildTime
	origVersion := Version
	defer func() {
		Commit = origCommit
		BuildTime = origBuildTime
		Version = origVersion
		// Reset sync.Once for subsequent tests
		once = sync.Once{}
		infoOnce = nil
	}()

	tests := []struct {
		name         string
		version      string
		commit       string
		buildTime    string
		wantVersion  string
		checkUnknown bool
	}{
		{
			name:         "empty strings fall back",
			version:      "",
			commit:       "",
			buildTime:    "",
			wantVersion:  "dev",
			checkUnknown: true,
		},
		{
			name:         "unknown strings fall back",
			version:      "unknown",
			commit:       "unknown",
			buildTime:    "unknown",
			wantVersion:  "dev",
			checkUnknown: true,
		},
		{
			name:         "branch name becomes dev",
			version:      "feature/add-versioning",
			commit:       "abc123",
			buildTime:    "2024-01-15T10:30:00Z",
			wantVersion:  "dev",
			checkUnknown: false,
		},
		{
			name:         "PR merge ref becomes dev",
			version:      "123/merge",
			commit:       "abc123",
			buildTime:    "2024-01-15T10:30:00Z",
			wantVersion:  "dev",
			checkUnknown: false,
		},
		{
			name:         "release version preserved",
			version:      "v1.2.3",
			commit:       "abc123",
			buildTime:    "2024-01-15T10:30:00Z",
			wantVersion:  "v1.2.3",
			checkUnknown: false,
		},
		{
			name:         "semver without v preserved",
			version:      "1.2.3",
			commit:       "abc123",
			buildTime:    "2024-01-15T10:30:00Z",
			wantVersion:  "1.2.3",
			checkUnknown: false,
		},
		{
			name:         "prerelease becomes dev (tightened regex)",
			version:      "v1.2.3-beta.1",
			commit:       "abc123",
			buildTime:    "2024-01-15T10:30:00Z",
			wantVersion:  "dev",
			checkUnknown: false,
		},
		{
			name:         "git describe output becomes dev",
			version:      "v1.2.3-5-g915919b",
			commit:       "abc123",
			buildTime:    "2024-01-15T10:30:00Z",
			wantVersion:  "dev",
			checkUnknown: false,
		},
		{
			name:         "dirty tag becomes dev",
			version:      "v1.2.3-dirty",
			commit:       "abc123",
			buildTime:    "2024-01-15T10:30:00Z",
			wantVersion:  "dev",
			checkUnknown: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset for each subtest
			once = sync.Once{}
			infoOnce = nil
			Version = tt.version
			Commit = tt.commit
			BuildTime = tt.buildTime

			info := Info()
			if info["version"] != tt.wantVersion {
				t.Errorf("version = %q, want %q", info["version"], tt.wantVersion)
			}
			if tt.checkUnknown {
				// Should never be empty after Info()
				if info["commit"] == "" {
					t.Error("commit should not be empty after fallback")
				}
				if info["build_time"] == "" {
					t.Error("build_time should not be empty after fallback")
				}
			}
		})
	}
}

func TestNeedsAttention(t *testing.T) {
	// Reset state
	once = sync.Once{}
	infoOnce = nil
	origCommit := Commit
	defer func() {
		Commit = origCommit
		once = sync.Once{}
		infoOnce = nil
	}()

	Commit = "unknown"
	if !NeedsAttention() {
		t.Error("NeedsAttention should be true when commit is unknown")
	}

	once = sync.Once{}
	infoOnce = nil
	Commit = "abc123def456"
	if NeedsAttention() {
		t.Error("NeedsAttention should be false when commit is set")
	}
}
