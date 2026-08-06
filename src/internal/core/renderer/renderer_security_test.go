package renderer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
)

func loadManifest(t *testing.T, raw string) *manifest.Manifest {
	t.Helper()
	var m manifest.Manifest
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	return &m
}

// oneHostManifest renders exactly one host block ("example") plus the global
// block. rawOptions is inlined as the host's raw_options object.
func oneHostManifest(t *testing.T, rawOptions string) *manifest.Manifest {
	t.Helper()
	raw := `{"version":1,"defaults":{"key_type":"ed25519","global_options":{"AddKeysToAgent":"yes"}},"profiles":{
	  "p":{"key_scope":"per_service","hosts":[
	    {"alias":"example","hostname":"example.com","user":"git","key_name":"k-ed25519","raw_options":` + rawOptions + `}
	  ]}}}`
	return loadManifest(t, raw)
}

func globalOptionsManifest(t *testing.T, globalOptions string) *manifest.Manifest {
	t.Helper()
	raw := `{"version":1,"defaults":{"key_type":"ed25519","global_options":` + globalOptions + `},"profiles":{}}`
	return loadManifest(t, raw)
}

// Without IdentitiesOnly, ssh offers every identity held by the agent to each
// server it reaches, disclosing the whole key inventory. It used to be supplied
// only by defaults.global_options, so emptying that map switched the protection
// off silently; it now belongs to the host block itself.
func TestHostBlockAlwaysBindsIdentitiesOnly(t *testing.T) {
	out, err := RenderRootConfig(oneHostManifest(t, "{}"), false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "    IdentitiesOnly yes\n") {
		t.Errorf("host block is missing IdentitiesOnly:\n%s", out)
	}
}

// An explicit per-host value is a deliberate choice and is preserved, but it must
// not produce two IdentitiesOnly lines: ssh takes the first and the file would
// misrepresent what is in force.
func TestExplicitIdentitiesOnlyIsNotDuplicated(t *testing.T) {
	out, err := RenderRootConfig(oneHostManifest(t, `{"IdentitiesOnly":"no"}`), false)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out, "IdentitiesOnly"); n != 1 {
		t.Errorf("want exactly one IdentitiesOnly line, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "    IdentitiesOnly no\n") {
		t.Errorf("explicit value not honoured:\n%s", out)
	}
}

// sshmgr hashes the names it writes, but ssh appends plaintext entries of its own
// whenever the user accepts an unknown host, so the store drifts back to a
// readable inventory unless the rendered config says otherwise.
func TestHostStarAlwaysHashesKnownHosts(t *testing.T) {
	got, err := RenderRootConfig(globalOptionsManifest(t, `{"AddKeysToAgent":"yes"}`), false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "HashKnownHosts yes") {
		t.Errorf("Host * should pin HashKnownHosts:\n%s", got)
	}
}

// An explicit value is a deliberate choice and must be honoured, not duplicated.
func TestExplicitHashKnownHostsIsNotDuplicated(t *testing.T) {
	got, err := RenderRootConfig(globalOptionsManifest(t, `{"HashKnownHosts":"no"}`), false)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(got, "HashKnownHosts"); n != 1 {
		t.Errorf("expected one HashKnownHosts line, got %d:\n%s", n, got)
	}
	if !strings.Contains(got, "HashKnownHosts no") {
		t.Errorf("the explicit value should win:\n%s", got)
	}
}

func TestIdentitiesOnlyFollowsIdentityFile(t *testing.T) {
	out, err := RenderRootConfig(oneHostManifest(t, "{}"), false)
	if err != nil {
		t.Fatal(err)
	}
	identity := strings.Index(out, "IdentityFile ")
	only := strings.Index(out, "IdentitiesOnly ")
	if identity == -1 || only == -1 || only < identity {
		t.Errorf("IdentitiesOnly should follow IdentityFile:\n%s", out)
	}
}

// Host * must render after every per-host block, never before: OpenSSH takes
// the first value it obtains for a keyword, so a global block placed above a
// host block would silently win over that host's more specific directives.
func TestHostStarIsAlwaysLast(t *testing.T) {
	out, err := RenderRootConfig(oneHostManifest(t, "{}"), false)
	if err != nil {
		t.Fatal(err)
	}
	star := strings.Index(out, "Host *")
	host := strings.Index(out, "Host example")
	if star == -1 || host == -1 || star < host {
		t.Errorf("Host * must render after the per-host block:\n%s", out)
	}
}
