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

// A `go install module@version` build has no VCS stamp - it is built from the
// proxy's zip, not a checkout - so the commit and time have to come out of the
// pseudo-version, which already ends in both.
func TestAPseudoVersionSuppliesCommitAndDate(t *testing.T) {
	restore(t)
	Version, Commit, Date = devDefault, "", ""

	recoverFromBuildInfo(info("v3.0.0-20260806194517-4f11416c835a", nil))

	if Commit != "4f11416" {
		t.Errorf("Commit = %q, want the hash from the pseudo-version", Commit)
	}
	if Date != "2026-08-06T19:45:17Z" {
		t.Errorf("Date = %q, want the timestamp as RFC 3339", Date)
	}
	if IsDev() {
		t.Error("a published pseudo-version is not a dev build")
	}
}

// All three pseudo-version shapes end the same way, and nothing else may be
// mistaken for one - a release version has dashes in it too.
func TestOnlyRealPseudoVersionsAreParsed(t *testing.T) {
	for _, tc := range []struct {
		in         string
		wantOK     bool
		date, hash string
	}{
		{"v3.0.0-20260806194517-4f11416c835a", true, "2026-08-06T19:45:17Z", "4f11416c835a"},
		{"v3.0.1-0.20260806194517-4f11416c835a", true, "2026-08-06T19:45:17Z", "4f11416c835a"},
		{"v3.0.1-rc.1.0.20260806194517-4f11416c835a", true, "2026-08-06T19:45:17Z", "4f11416c835a"},
		{"v3.0.1", false, "", ""},
		{"v3.0.1-rc.1", false, "", ""},
		{"v3.0.0-12-g60ce5f9", false, "", ""},                 // git describe, not a pseudo-version
		{"v3.0.0-2026080619451-4f11416c835a", false, "", ""},  // 13-digit stamp
		{"v3.0.0-20260806194517-zzzzzzzzzzzz", false, "", ""}, // not hex
	} {
		date, hash, ok := splitPseudoVersion(tc.in)
		if ok != tc.wantOK {
			t.Errorf("%s: ok = %v, want %v", tc.in, ok, tc.wantOK)
			continue
		}
		if ok && (date != tc.date || hash != tc.hash) {
			t.Errorf("%s: got (%s, %s), want (%s, %s)", tc.in, date, hash, tc.date, tc.hash)
		}
	}
}

// IsDev must be true only when nothing supplied a version at all.
func TestIsDevOnlyForAnUnstampedBuild(t *testing.T) {
	restore(t)
	for v, want := range map[string]bool{
		"dev": true, "dev-dirty": true,
		"v3.0.1": false, "v3.0.0-20260806194517-4f11416c835a": false, "v3.0.1-dirty": false,
	} {
		Version = v
		if got := IsDev(); got != want {
			t.Errorf("IsDev(%q) = %v, want %v", v, got, want)
		}
	}
}
