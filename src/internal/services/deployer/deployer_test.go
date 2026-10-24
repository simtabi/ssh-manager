package deployer

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/inventory"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/reconciler"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/rotator"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/paths"
)

// Parity reference: v1's deploy tests. The contracts it pinned:
// a deployment is recorded in the inventory keyed by fingerprint, deploying
// twice leaves one entry per target (not two), and a provider with no
// credentials degrades to manual with the account URL in the detail - still
// needs-redeploy, because a manual paste is not confirmation.
//
// v1 stubbed ssh-copy-id to test the generic-ssh path offline. Here the
// same contracts are checked through a web-panel provider, which deploys via the
// manual route with no network at all, plus a closed loopback port for the
// unreachable case.

// ploi is a web-panel provider in the shipped catalog: category "web-panel",
// so Deploy returns the manual outcome without touching the network.
const manifestJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519", "rotate_after_days": 365},
  "profiles": {
    "panel": {"key_scope": "shared", "key_name": "panel_all-ed25519", "hosts": [
      {"alias": "one", "hostname": "one.example", "user": "x", "provider": "ploi"},
      {"alias": "two", "hostname": "two.example", "user": "x", "provider": "ploi"}
    ]}
  }
}`

type fixture struct {
	p   paths.Paths
	m   *manifest.Manifest
	inv *inventory.Inventory
}

func newFixture(t *testing.T, raw string) fixture {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	p := paths.Paths{SSHDir: filepath.Join(base, ".ssh"), ConfigDir: filepath.Join(base, "cfg")}
	inv := inventory.New()
	if _, err := reconciler.New(p, &m, inv, false).Reconcile(false, ""); err != nil {
		t.Fatal(err)
	}
	return fixture{p: p, m: &m, inv: inv}
}

// recordFor finds the inventory record whose path ends in keyName.
func recordFor(t *testing.T, inv *inventory.Inventory, keyName string) inventory.KeyRecord {
	t.Helper()
	for _, rec := range inv.Keys {
		if strings.HasSuffix(rec.Path, "/"+keyName) {
			return rec
		}
	}
	t.Fatalf("no inventory record for %s", keyName)
	return inventory.KeyRecord{}
}

func TestDeployRecordsEveryHostUsingTheKey(t *testing.T) {
	f := newFixture(t, manifestJSON)

	report, err := New(f.p, f.m, f.inv).Deploy("panel_all-ed25519", "")
	if err != nil {
		t.Fatal(err)
	}
	// A shared key means every host in the profile is a target.
	if len(report.Records) != 2 {
		t.Fatalf("got %d records, want one per host: %+v", len(report.Records), report.Records)
	}
	if report.Fingerprint == "" {
		t.Error("the report should carry the key's fingerprint")
	}

	rec := recordFor(t, f.inv, "panel_all-ed25519")
	if len(rec.Deployments) != 2 {
		t.Fatalf("inventory has %d deployments, want one per target", len(rec.Deployments))
	}
	targets := map[string]bool{}
	for _, d := range rec.Deployments {
		targets[d.Target] = true
		if d.Date == nil || *d.Date == "" {
			t.Errorf("deployment %s has no date", d.Target)
		}
	}
	if !targets["one"] || !targets["two"] {
		t.Errorf("deployments = %+v, want both hosts", rec.Deployments)
	}
}

// The idempotence contract from v1: deploying twice leaves one entry per
// target, not a growing list.
func TestDeployTwiceLeavesOneEntryPerTarget(t *testing.T) {
	f := newFixture(t, manifestJSON)
	d := New(f.p, f.m, f.inv)

	if _, err := d.Deploy("panel_all-ed25519", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Deploy("panel_all-ed25519", ""); err != nil {
		t.Fatal(err)
	}
	rec := recordFor(t, f.inv, "panel_all-ed25519")
	count := map[string]int{}
	for _, dep := range rec.Deployments {
		count[dep.Target]++
	}
	for target, n := range count {
		if n != 1 {
			t.Errorf("target %s recorded %d times, want 1", target, n)
		}
	}
}

// A manual deploy is not confirmation, so the key stays needs-redeploy - which
// is what keeps it in the audit's "needs attention" list until someone verifies.
func TestManualDeployStillNeedsRedeploy(t *testing.T) {
	f := newFixture(t, manifestJSON)

	report, err := New(f.p, f.m, f.inv).Deploy("panel_all-ed25519", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range report.Records {
		if r.Method != "manual" {
			t.Errorf("a web-panel provider deploys manually, got %q", r.Method)
		}
		if r.Verified {
			t.Error("a manual paste is not verification")
		}
		if r.Detail == "" {
			t.Error("a manual outcome should tell the user where to paste")
		}
	}
	if !recordFor(t, f.inv, "panel_all-ed25519").NeedsRedeploy() {
		t.Error("a manually deployed key still needs redeploy")
	}
	if report.AnyError() {
		t.Error("manual is a route, not a failure")
	}
}

// Naming a target narrows the deploy to that host alone.
func TestTargetAliasNarrowsToOneHost(t *testing.T) {
	f := newFixture(t, manifestJSON)

	report, err := New(f.p, f.m, f.inv).Deploy("panel_all-ed25519", "two")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Records) != 1 || report.Records[0].Target != "two" {
		t.Fatalf("records = %+v, want just the named host", report.Records)
	}
	if _, err := New(f.p, f.m, f.inv).Deploy("panel_all-ed25519", "nosuchhost"); err == nil {
		t.Error("an unknown target alias should be an error, not a silent no-op")
	}
}

// An unreachable server-category host is recorded as such and reported as an
// error, rather than counted as a successful deploy.
func TestUnreachableServerIsRecordedAsAnError(t *testing.T) {
	// A closed loopback port refuses instantly instead of timing out.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf(`{
	  "version": 1, "defaults": {"key_type": "ed25519"},
	  "profiles": {"srv": {"key_scope": "per_service", "hosts": [
	    {"alias": "box", "hostname": "127.0.0.1", "user": "deploy", "port": %d}
	  ]}}
	}`, port)
	f := newFixture(t, raw)

	report, err := New(f.p, f.m, f.inv).Deploy("srv_box-ed25519", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Records) != 1 {
		t.Fatalf("records = %+v", report.Records)
	}
	rec := report.Records[0]
	if rec.Method != "unreachable" || rec.Verified || !rec.Error {
		t.Errorf("an unreachable host should be an unverified error: %+v", rec)
	}
	if !report.AnyError() {
		t.Error("AnyError should be true so the command exits non-zero")
	}
	// It is still recorded, so the next run can tell it was attempted.
	inv := recordFor(t, f.inv, "srv_box-ed25519")
	if len(inv.Deployments) != 1 || inv.Deployments[0].Method != "unreachable" {
		t.Errorf("deployments = %+v", inv.Deployments)
	}
	if !inv.NeedsRedeploy() {
		t.Error("an unreachable target leaves the key needing redeploy")
	}
}

func TestDeployRejectsUnknownAndUnmintedKeys(t *testing.T) {
	f := newFixture(t, manifestJSON)

	if _, err := New(f.p, f.m, f.inv).Deploy("no-such-key", ""); err == nil {
		t.Error("an unknown key selector should error")
	}

	// A key the manifest knows but that has not been minted: the error has to
	// name the command that fixes it.
	if err := os.Remove(filepath.Join(f.p.SSHDir, "profiles", "panel", "panel_all-ed25519.pub")); err != nil {
		t.Fatal(err)
	}
	_, err := New(f.p, f.m, f.inv).Deploy("panel_all-ed25519", "")
	if err == nil {
		t.Fatal("deploying an unminted key should error")
	}
	if !strings.Contains(err.Error(), "reconcile") {
		t.Errorf("the error should point at reconcile: %v", err)
	}
}

func TestReportFormatNamesTargetsAndOutcome(t *testing.T) {
	f := newFixture(t, manifestJSON)
	report, err := New(f.p, f.m, f.inv).Deploy("panel_all-ed25519", "")
	if err != nil {
		t.Fatal(err)
	}
	text := report.Format()
	for _, want := range []string{"panel_all-ed25519", "one", "two", "MANUAL/needs-redeploy"} {
		if !strings.Contains(text, want) {
			t.Errorf("report should mention %q:\n%s", want, text)
		}
	}
}

// A key whose type and rotation interval differ from the manifest defaults.
const overriddenJSON = `{
  "version": 1,
  "defaults": {"key_type": "ed25519", "rotate_after_days": 365},
  "profiles": {
    "panel": {"key_scope": "shared", "key_name": "panel_all-rsa",
      "keys": [{"name": "panel_all-rsa", "type": "rsa", "rotate_after_days": 90}],
      "hosts": [{"alias": "one", "hostname": "one.example", "user": "x", "provider": "ploi"}]}
  }
}`

// Deploying a key the inventory has no record for creates one. It used to be
// written with a hard-coded ed25519 and 365 days whatever the manifest said, so
// an rsa key on a 90-day rotation was reported as the wrong type and expired
// nine months late. And a record left at the same path by the key this one
// replaced stayed beside it, two records claiming one file.
func TestDeployRecordsAnUnrecordedKeyAsTheManifestDeclaresIt(t *testing.T) {
	f := newFixture(t, overriddenJSON)
	ident := f.m.IdentityFile("panel", "panel_all-rsa")
	stale := inventory.New()
	stale.Record("SHA256:stale", inventory.KeyRecord{Profile: "panel", Path: ident, Type: "rsa", RotateAfterDays: 90})
	f.inv.Keys = stale.Keys // the key on disk is unrecorded; a predecessor's record remains

	report, err := New(f.p, f.m, f.inv).Deploy("panel_all-rsa", "")
	if err != nil {
		t.Fatal(err)
	}
	var atPath []string
	for fp, rec := range f.inv.Keys {
		if rec.Path == ident {
			atPath = append(atPath, fp)
		}
	}
	if len(atPath) != 1 || atPath[0] != report.Fingerprint {
		t.Errorf("records at %s = %v, want only the deployed key %s", ident, atPath, report.Fingerprint)
	}
	rec := f.inv.Keys[report.Fingerprint]
	if rec.Type != "rsa" || rec.RotateAfterDays != 90 {
		t.Errorf("record = type %q, rotate %d; want the manifest's rsa, 90", rec.Type, rec.RotateAfterDays)
	}
}

// `keygen --force` archives the outgoing key to old/, and `rollback` restores
// it. The restored key must still have its record: overwrite used to delete
// it, so after the rollback the active key was unrecorded.
func TestRollbackAfterKeygenForceKeepsTheActiveKeyRecorded(t *testing.T) {
	f := newFixture(t, manifestJSON)
	ref := manifest.KeyRef{Profile: "panel", KeyName: "panel_all-ed25519"}
	ident := f.m.IdentityFile(ref.Profile, ref.KeyName)
	var original string
	for fp, rec := range f.inv.Keys {
		if rec.Path == ident {
			original = fp
		}
	}
	if _, err := reconciler.New(f.p, f.m, f.inv, false).Mint("", "", map[manifest.KeyRef]bool{ref: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := rotator.New(f.p, f.m, f.inv).Rollback(ref.String()); err != nil {
		t.Fatal(err)
	}
	rec, ok := f.inv.Keys[original]
	if !ok {
		t.Fatalf("the restored key %s has no inventory record: %+v", original, f.inv.Keys)
	}
	if rec.Path != ident {
		t.Errorf("the restored key's record is at %s, want %s", rec.Path, ident)
	}
}
