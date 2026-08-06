package version

import (
	"runtime/debug"
	"testing"
)

// info builds a fake BuildInfo reader, so these tests exercise the recovery
// logic rather than whatever produced the test binary itself.
func info(mainVersion string, settings map[string]string) func() (*debug.BuildInfo, bool) {
	bi := &debug.BuildInfo{Main: debug.Module{Version: mainVersion}}
	for k, v := range settings {
		bi.Settings = append(bi.Settings, debug.BuildSetting{Key: k, Value: v})
	}
	return func() (*debug.BuildInfo, bool) { return bi, true }
}

// restore puts the package vars back, since recoverFromBuildInfo writes them.
func restore(t *testing.T) {
	t.Helper()
	v, c, d := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = v, c, d })
}

// The case the README's install command produces: no ldflags at all, and the
// module version is the only truth available. This reported "2.0.0-dev" from a
// binary built out of v3 sources.
func TestAGoInstallBuildReportsTheModuleVersion(t *testing.T) {
	restore(t)
	Version, Commit, Date = devDefault, "", ""

	recoverFromBuildInfo(info("v3.0.1", nil))

	if Version != "v3.0.1" {
		t.Errorf("Version = %q, want the module version v3.0.1", Version)
	}
}

// A stamped version always wins. A release says exactly what it is, and a
// recovered value must never be able to contradict it.
func TestALdflagsStampIsNeverOverwritten(t *testing.T) {
	restore(t)
	Version, Commit, Date = "v3.0.1", "abc1234", "2026-08-06T00:00:00Z"

	recoverFromBuildInfo(info("v9.9.9", map[string]string{
		"vcs.revision": "ffffffffffffffff", "vcs.time": "1999-01-01T00:00:00Z",
	}))

	if Version != "v3.0.1" || Commit != "abc1234" || Date != "2026-08-06T00:00:00Z" {
		t.Errorf("a stamped build was overwritten: %s %s %s", Version, Commit, Date)
	}
}

// "(devel)" is what a plain `go build` in a working tree reports. It is not a
// version, so accepting it would replace one placeholder with a worse one.
func TestDevelIsNotTreatedAsAVersion(t *testing.T) {
	restore(t)
	Version, Commit, Date = devDefault, "", ""

	recoverFromBuildInfo(info("(devel)", nil))

	if Version != devDefault {
		t.Errorf("Version = %q, want it left at the default", Version)
	}
}

// Building inside a repository gives commit and time even with no ldflags, which
// is what makes a locally built binary identifiable.
func TestTheVCSStampSuppliesCommitAndDate(t *testing.T) {
	restore(t)
	Version, Commit, Date = devDefault, "", ""

	recoverFromBuildInfo(info("(devel)", map[string]string{
		"vcs.revision": "60ce5f9c4ee6aaaabbbb", "vcs.time": "2026-08-06T19:32:00Z",
	}))

	if Commit != "60ce5f9" {
		t.Errorf("Commit = %q, want the short hash", Commit)
	}
	if Date != "2026-08-06T19:32:00Z" {
		t.Errorf("Date = %q", Date)
	}
}

// An uncommitted tree must not look like a clean build of the commit it sits on.
// That distinction is what makes a bug report reproducible.
func TestADirtyTreeSaysSo(t *testing.T) {
	restore(t)
	Version, Commit, Date = devDefault, "", ""

	recoverFromBuildInfo(info("v3.0.1", map[string]string{"vcs.modified": "true"}))

	if Version != "v3.0.1-dirty" {
		t.Errorf("Version = %q, want a -dirty suffix", Version)
	}
}

// ...and it says so once, not once per call.
func TestDirtyIsNotAppendedTwice(t *testing.T) {
	restore(t)
	Version, Commit, Date = devDefault, "", ""

	read := info("v3.0.1", map[string]string{"vcs.modified": "true"})
	recoverFromBuildInfo(read)
	recoverFromBuildInfo(read)

	if Version != "v3.0.1-dirty" {
		t.Errorf("Version = %q, want a single -dirty suffix", Version)
	}
}

// No build info at all (some linkers, some test harnesses) must leave the vars
// alone rather than panic on a nil dereference.
func TestMissingBuildInfoIsSurvivable(t *testing.T) {
	restore(t)
	Version, Commit, Date = devDefault, "", ""

	recoverFromBuildInfo(func() (*debug.BuildInfo, bool) { return nil, false })

	if Version != devDefault || Commit != "" || Date != "" {
		t.Errorf("absent build info changed the vars: %s %s %s", Version, Commit, Date)
	}
}
