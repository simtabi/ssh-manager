// Package version carries the build version.
//
// There are three ways this binary gets built, and all three have to end up
// reporting something true:
//
//   - a release, where GoReleaser stamps all three vars through -ldflags;
//   - `make build`, which stamps Version from `git describe`;
//   - `go install github.com/simtabi/ssh-manager/src/v3/cmd/sshmgr@latest`,
//     which applies no ldflags at all.
//
// The third is the one the README tells people to use, and it used to report the
// hardcoded default - "2.0.0-dev", from a binary built out of v3 sources. Go
// already records the real answer in the binary (`go version -m` shows it), so
// nothing needed to be threaded through the build: it just had to be read.
package version

import (
	"runtime/debug"
	"strings"
)

// devDefault is the value that means "nothing has stamped this yet". It is
// deliberately not a version number: a made-up one is indistinguishable from a
// real release to everyone downstream, which is how a v3 binary came to call
// itself 2.0.0.
const devDefault = "dev"

// Version is the ssh-manager version. Release builds override it through
// -ldflags "-X .../internal/version.Version=..."; otherwise it is recovered from
// the build info Go embeds.
var Version = devDefault

// Commit is the short git commit the binary was built from. Release builds stamp
// it via -ldflags; otherwise it comes from the VCS stamp Go embeds when building
// inside a repository.
var Commit = ""

// Date is the build/commit date (RFC 3339), stamped or recovered the same way.
var Date = ""

func init() { recoverFromBuildInfo(debug.ReadBuildInfo) }

// recoverFromBuildInfo fills in whatever ldflags did not.
//
// ldflags always win: a release stamps an exact version, and the module version
// for a tagged build says the same thing anyway. This only supplies values that
// are otherwise absent, so it can never contradict a deliberate stamp.
func recoverFromBuildInfo(read func() (*debug.BuildInfo, bool)) {
	bi, ok := read()
	if !ok {
		return
	}
	// "(devel)" is what a plain `go build` in a working tree reports - it is not
	// a version, so it is no better than the default it would replace.
	if Version == devDefault {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			Version = v
		}
	}
	var dirty bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if Commit == "" {
				Commit = shortHash(s.Value)
			}
		case "vcs.time":
			if Date == "" {
				Date = s.Value
			}
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	// An uncommitted tree must never look like a clean build of the commit it
	// sits on - that is the difference between a bug report you can reproduce
	// and one you cannot.
	if dirty && !strings.HasSuffix(Version, "-dirty") {
		Version += "-dirty"
	}
}

func shortHash(h string) string {
	if len(h) > 7 {
		return h[:7]
	}
	return h
}
