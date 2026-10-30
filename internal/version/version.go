// Package version provides build-time version information.
package version

import (
	"fmt"
	"regexp"
	"runtime/debug"
	"sync"
	"time"
)

var (
	// Version is the version string, injected at build time via -ldflags.
	// Defaults to "dev" if not set.
	Version = "dev"

	// Commit is the full git commit SHA, injected at build time via -ldflags.
	// Falls back to VCS info from runtime/debug if not set or "unknown".
	Commit = ""

	// BuildTime is the ISO 8601 build timestamp, injected at build time via -ldflags.
	// Falls back to VCS commit time from runtime/debug if not set or "unknown".
	BuildTime = ""
)

var (
	once      sync.Once
	infoOnce  map[string]string
	infoDirty bool
)

// releaseVersionRE matches strict semver releases: vX.Y.Z or X.Y.Z with no build metadata or git describe suffix.
// Rejects leading zeros in numeric components (e.g., v01.2.3) and caps each component at 10 digits.
var releaseVersionRE = regexp.MustCompile(`^v?(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})$`)

var commitRE = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

const maxBuildTimeLen = 40

// Info returns version information as a structured map.
// Computed once on first call.
func Info() map[string]string {
	once.Do(func() {
		version := normalizeVersion(Version)
		commit := Commit
		buildTime := BuildTime
		dirty := false

		// Treat "unknown" as unset to enable fallbacks
		if commit == "" || commit == "unknown" {
			bi, ok := debug.ReadBuildInfo()
			if ok {
				for _, setting := range bi.Settings {
					switch setting.Key {
					case "vcs.revision":
						if commit == "" || commit == "unknown" {
							commit = setting.Value
						}
					case "vcs.time":
						if buildTime == "" || buildTime == "unknown" {
							buildTime = setting.Value
						}
					case "vcs.modified":
						if setting.Value == "true" {
							dirty = true
						}
					}
				}
			}
		}

		if !commitRE.MatchString(commit) {
			commit = "unknown"
		}
		if _, err := time.Parse(time.RFC3339, buildTime); err != nil || len(buildTime) > maxBuildTimeLen {
			buildTime = "unknown"
		}
		infoDirty = dirty && commit != "unknown"

		infoOnce = map[string]string{
			"version":    version,
			"commit":     commit,
			"build_time": buildTime,
		}
	})
	return infoOnce
}

// normalizeVersion returns the version if it looks like a release (semver vX.Y.Z) or "dev",
// otherwise returns "dev". This prevents branch names or build artifacts from leaking.
func normalizeVersion(v string) string {
	if v == "" || v == "dev" {
		return "dev"
	}
	if releaseVersionRE.MatchString(v) {
		return v
	}
	// Anything else (branch names, descriptive strings, etc.) becomes "dev"
	return "dev"
}

// ShortCommit returns the first 12 characters of the commit SHA, plus "-dirty" for a modified tree.
func ShortCommit() string {
	commit := Info()["commit"]
	if commit == "unknown" {
		return commit
	}
	if len(commit) > 12 {
		commit = commit[:12]
	}
	if infoDirty {
		commit += "-dirty"
	}
	return commit
}

// String returns a human-readable version string.
func String() string {
	info := Info()
	return fmt.Sprintf("%s (commit %s, built %s)", info["version"], info["commit"], info["build_time"])
}

// NeedsAttention returns true if the version information suggests a problem.
func NeedsAttention() bool {
	info := Info()
	return info["commit"] == "unknown"
}
