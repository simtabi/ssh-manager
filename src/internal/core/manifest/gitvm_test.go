package manifest

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const gitManifest = `{
  "version": 1,
  "defaults": {"git": {"mode": "profile", "profile": "imanimanyara", "orgs": {"simtabi": "imanimanyara", "adelsaiq": "dannielagumo"}}},
  "profiles": {
    "imanimanyara": {"category": "personal", "hosts": [
      {"alias": "github-imanimanyara", "hostname": "github.com", "user": "git", "key_name": "imanimanyara_github-ed25519"}]},
    "dannielagumo": {"category": "clients", "hosts": [
      {"alias": "github-dannielagumo", "hostname": "github.com", "user": "git", "key_name": "dannielagumo_github-ed25519"}]},
    "devbox": {"category": "personal", "hosts": [
      {"alias": "devbox", "hostname": "devbox", "user": "imani", "key_name": "devbox_docker-ed25519",
       "vm": {"hypervisor": "parallels", "name": "Ubuntu 24.04"}}]}
  }
}`

func TestGitDefaultsAndVMLoadAndResolve(t *testing.T) {
	m, err := loadJSON(t, gitManifest)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Defaults.Git.EffectiveMode(); got != GitModeProfile {
		t.Errorf("mode=%q", got)
	}
	for owner, want := range map[string]string{"simtabi": "imanimanyara", "SimTabi": "imanimanyara",
		"adelsaiq": "dannielagumo", "laranail": "imanimanyara"} {
		if got, err := ProfileForOwner(m, owner); err != nil || got != want {
			t.Errorf("owner %s -> %q, %v; want %q", owner, got, err, want)
		}
	}
	if h, ok := GitHubHostOf(m, "dannielagumo"); !ok || h.Alias != "github-dannielagumo" {
		t.Errorf("GitHubHostOf = %v, %v", h, ok)
	}
	if _, ok := GitHubHostOf(m, "devbox"); ok {
		t.Error("devbox has no GitHub host")
	}
	vm := m.Profiles["devbox"].Hosts[0].VM
	if vm == nil || vm.Hypervisor != HypervisorParallels || vm.Name != "Ubuntu 24.04" {
		t.Errorf("vm=%+v", vm)
	}
}

func TestProfileForOwnerRefusesToGuess(t *testing.T) {
	m, err := loadJSON(t, strings.Replace(gitManifest,
		`"git": {"mode": "profile", "profile": "imanimanyara", "orgs": {"simtabi": "imanimanyara", "adelsaiq": "dannielagumo"}}`,
		`"git": {}`, 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProfileForOwner(m, "laranail"); err == nil || !strings.Contains(err.Error(), "several profiles") {
		t.Errorf("err=%v: two GitHub profiles and no mapping must not pick one", err)
	}
	if got := m.Defaults.Git.EffectiveMode(); got != GitModeProfile {
		t.Errorf("empty mode = %q, want profile", got)
	}
	var none *GitDefaults
	if none.EffectiveMode() != GitModeProfile {
		t.Error("absent git defaults must mean profile mode")
	}
}

func TestGitAndVMValidation(t *testing.T) {
	cases := []struct{ name, from, to, want string }{
		{"unknown mode", `"mode": "profile"`, `"mode": "carrier-pigeon"`, "defaults.git.mode"},
		{"missing profile", `"profile": "imanimanyara"`, `"profile": "ghost"`, "does not exist"},
		{"profile without GitHub", `"profile": "imanimanyara"`, `"profile": "devbox"`, "no github.com host"},
		{"org to missing profile", `"adelsaiq": "dannielagumo"`, `"adelsaiq": "nobody"`, "does not exist"},
		{"ssh mode needs a profile", `"mode": "profile", "profile": "imanimanyara"`, `"mode": "ssh"`, "needs defaults.git.profile"},
		{"alias github.com shadowed", `"alias": "github-imanimanyara"`, `"alias": "github.com"`, "clashes with the Host github.com"},
		{"unknown hypervisor", `"hypervisor": "parallels"`, `"hypervisor": "virtualbox"`, "vm.hypervisor"},
		{"empty vm name", `"name": "Ubuntu 24.04"`, `"name": " "`, "vm.name is empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(gitManifest, c.from) {
				t.Fatalf("fixture lacks %q", c.from)
			}
			_, err := loadJSON(t, strings.Replace(gitManifest, c.from, c.to, 1))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err=%v, want %q", err, c.want)
			}
		})
	}
}

// A manifest written before 3.3.0 must save back without a "git" or "vm" key: the new fields are
// omitted when unset, so no existing file changes shape.
func TestUnsetGitAndVMAddNoKeys(t *testing.T) {
	m, err := loadJSON(t, categorizedManifest)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"git":{`, `"vm":{`} {
		if strings.Contains(string(b), k) {
			t.Errorf("an unset field wrote %s: %s", k, b)
		}
	}
	m2, err := loadJSON(t, gitManifest)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := json.Marshal(m2)
	for _, k := range []string{`"git":{"mode":"profile"`, `"vm":{"hypervisor":"parallels"`} {
		if !strings.Contains(string(b2), k) {
			t.Errorf("set field lost on save, want %s in %s", k, b2)
		}
	}
}

// The schema had drifted: category, key_store, op_vault, keys and onepassword_agent were valid
// in the code and rejected by the schema's additionalProperties:false. Every JSON field of every
// manifest type must appear in the schema, and nothing else.
func TestSchemaListsEveryManifestField(t *testing.T) {
	raw, err := os.ReadFile("../../../config/schema/manifest.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	props := func(path ...string) []string {
		var node any = s
		for _, p := range path {
			node = node.(map[string]any)[p]
		}
		var keys []string
		for k := range node.(map[string]any)["properties"].(map[string]any) {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return keys
	}
	tags := func(v any) []string {
		var keys []string
		t := reflect.TypeOf(v)
		for i := 0; i < t.NumField(); i++ {
			if tag := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]; tag != "" && tag != "-" {
				keys = append(keys, tag)
			}
		}
		sort.Strings(keys)
		return keys
	}
	checks := []struct {
		name   string
		schema []string
		code   []string
	}{
		{"defaults", props("properties", "defaults"), tags(Defaults{})},
		{"defaults.git", props("properties", "defaults", "properties", "git"), tags(GitDefaults{})},
		{"profile", props("properties", "profiles", "additionalProperties"), tags(Profile{})},
		{"profile.keys[]", props("properties", "profiles", "additionalProperties", "properties", "keys", "items"), tags(KeySpec{})},
		{"host", props("properties", "profiles", "additionalProperties", "properties", "hosts", "items"), tags(Host{})},
		{"host.vm", props("properties", "profiles", "additionalProperties", "properties", "hosts", "items", "properties", "vm"), tags(VMSpec{})},
	}
	if len(checks) < 6 {
		t.Fatal("inspected fewer types than exist")
	}
	for _, c := range checks {
		if !reflect.DeepEqual(c.schema, c.code) {
			t.Errorf("%s: schema %v, code %v", c.name, c.schema, c.code)
		}
	}
}
