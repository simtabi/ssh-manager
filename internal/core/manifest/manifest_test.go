package manifest

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// loadJSON writes s to a temp manifest and loads it.
func loadJSON(t *testing.T, s string) (*Manifest, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestLoadRealManifest(t *testing.T) {
	m, err := Load("../../../config/manifest.json")
	if err != nil {
		t.Fatalf("load shipped manifest: %v", err)
	}
	if m.Version != 1 || m.Defaults.KeyType != "ed25519" {
		t.Fatalf("defaults wrong: version=%d key_type=%q", m.Version, m.Defaults.KeyType)
	}
	// JSON number coerced to string, matching Python str(60).
	if got := m.Defaults.GlobalOptions.Get("ServerAliveInterval"); got != "60" {
		t.Fatalf("ServerAliveInterval = %q, want \"60\"", got)
	}
	if !m.Defaults.ExpiryCheck.Enabled || m.Defaults.ExpiryCheck.DebounceHours != 24 {
		t.Fatal("expiry_check defaults not applied")
	}
	resolved, err := m.IterResolved()
	if err != nil {
		t.Fatalf("IterResolved: %v", err)
	}
	if len(resolved) != 6 { // 4 dev/personal/simtabi/work hosts; school is empty
		t.Fatalf("resolved count = %d, want 6", len(resolved))
	}
	byKey := map[string]string{}
	for _, r := range resolved {
		byKey[r.KeyName] = r.IdentityFile
	}
	want := map[string]string{
		"work_unc-ed25519":                  "~/.ssh/profiles/work/work_unc-ed25519",
		"personal_github-ed25519":           "~/.ssh/profiles/personal/personal_github-ed25519",
		"development_oribi-db-psql-ed25519": "~/.ssh/profiles/development/development_oribi-db-psql-ed25519",
	}
	for k, v := range want {
		if byKey[k] != v {
			t.Errorf("identity_file[%s] = %q, want %q", k, byKey[k], v)
		}
	}
	if got := m.NonEmptyProfiles(); len(got) != 4 {
		t.Errorf("NonEmptyProfiles = %v, want 4 (school excluded)", got)
	}
}

func TestValidationRejections(t *testing.T) {
	cases := map[string]string{
		"unknown field":     `{"profiles":{"p":{"hosts":[{"alias":"a","hostname":"h","user":"u","bogus":1}]}}}`,
		"dangerous opt":     `{"profiles":{"p":{"hosts":[{"alias":"a","hostname":"h","user":"u","raw_options":{"ProxyCommand":"x"}}]}}}`,
		"unsafe alias":      `{"profiles":{"p":{"hosts":[{"alias":"a/b","hostname":"h","user":"u"}]}}}`,
		"glob alias":        `{"profiles":{"p":{"hosts":[{"alias":"*","hostname":"h","user":"u"}]}}}`,
		"leading-dash user": `{"profiles":{"p":{"hosts":[{"alias":"a","hostname":"h","user":"-x"}]}}}`,
		"bad key_scope":     `{"profiles":{"p":{"key_scope":"weird","hosts":[]}}}`,
		"duplicate alias, same profile": `{"profiles":{"p":{"hosts":[
			{"alias":"gh","hostname":"h1","user":"u"},
			{"alias":"gh","hostname":"h2","user":"u"}
		]}}}`,
		"duplicate alias, across profiles": `{"profiles":{
			"work":{"hosts":[{"alias":"gh","hostname":"h1","user":"u"}]},
			"personal":{"hosts":[{"alias":"gh","hostname":"h2","user":"u"}]}
		}}`,
	}
	for name, js := range cases {
		if _, err := loadJSON(t, js); err == nil {
			t.Errorf("%s: expected a validation error, got nil", name)
		}
	}
}

// Under inline rendering every Host block lives in one file, so a duplicate
// alias is deterministically dead config (ssh takes the first, in manifest
// order) rather than a warning about filesystem-glob ordering. Load must
// refuse it outright.
func TestDuplicateAliasAcrossProfilesIsRejected(t *testing.T) {
	const js = `{"profiles":{
		"work":{"hosts":[{"alias":"gh","hostname":"h1","user":"u"}]},
		"personal":{"hosts":[{"alias":"gh","hostname":"h2","user":"u"}]}
	}}`
	_, err := loadJSON(t, js)
	if err == nil {
		t.Fatal("expected a validation error for a duplicate alias")
	}
	for _, want := range []string{`"gh"`, "personal", "work"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q: %v", want, err)
		}
	}
}

// A profile models an org and a key file is named for the person using it, so
// the same name legitimately appears in several profiles. The directory keeps
// them apart on disk; commands disambiguate with the profile/key selector.
func TestDuplicateKeyNameAcrossProfilesIsAllowed(t *testing.T) {
	m, err := loadJSON(t, dupKeyManifest)
	if err != nil {
		t.Fatalf("same key_name in two profiles should load: %v", err)
	}
	refs, err := m.KeyRefs()
	if err != nil {
		t.Fatal(err)
	}
	// personal + adelsaiq share the basename; simtabi is a third distinct key.
	if len(refs) != 3 {
		t.Fatalf("KeyRefs = %v, want one entry per distinct profile/key", refs)
	}
	for _, ref := range refs {
		want := "~/.ssh/profiles/" + ref.Profile + "/" + ref.KeyName
		if got := m.IdentityFile(ref.Profile, ref.KeyName); got != want {
			t.Errorf("identity for %s = %q, want %q", ref, got, want)
		}
	}
}

func TestResolveKeySelector(t *testing.T) {
	m, err := loadJSON(t, dupKeyManifest)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("composite form picks the named profile", func(t *testing.T) {
		ref, err := m.ResolveKeySelector("adelsaiq/imani_github-ed25519")
		if err != nil {
			t.Fatal(err)
		}
		if ref.Profile != "adelsaiq" {
			t.Errorf("profile = %q, want adelsaiq", ref.Profile)
		}
	})
	t.Run("bare name resolves when only one profile uses it", func(t *testing.T) {
		ref, err := m.ResolveKeySelector("simtabi_github-ed25519")
		if err != nil {
			t.Fatal(err)
		}
		if ref.String() != "simtabi/simtabi_github-ed25519" {
			t.Errorf("ref = %q", ref)
		}
	})
	t.Run("bare name shared by profiles is ambiguous", func(t *testing.T) {
		_, err := m.ResolveKeySelector("imani_github-ed25519")
		if err == nil {
			t.Fatal("expected an ambiguity error")
		}
		// The message must name the candidates - the caller has to retype one.
		for _, want := range []string{"adelsaiq/imani_github-ed25519", "personal/imani_github-ed25519"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not offer %q", err, want)
			}
		}
	})
	t.Run("rejects unknown key, profile, and pairing", func(t *testing.T) {
		for _, sel := range []string{"", "nope", "nosuch/imani_github-ed25519", "personal/nope"} {
			if _, err := m.ResolveKeySelector(sel); err == nil {
				t.Errorf("selector %q should have failed", sel)
			}
		}
	})
}

// One person (imani) working under two orgs, plus a third profile whose key name
// is unique - enough to exercise both the ambiguous and unambiguous paths.
const dupKeyManifest = `{"profiles":{
	"personal":{"hosts":[{"alias":"github-imani","hostname":"github.com","user":"git","key_name":"imani_github-ed25519"}]},
	"adelsaiq":{"hosts":[{"alias":"github-danniela","hostname":"github.com","user":"git","key_name":"imani_github-ed25519"}]},
	"simtabi":{"hosts":[{"alias":"github-simtabi","hostname":"github.com","user":"git","key_name":"simtabi_github-ed25519"}]}}}`

// A profile declares two keys: one its host uses, one no host references yet.
// The unwired key is the whole point of the list - it exists nowhere else in the
// manifest, so KeyRefs is the only thing that can surface it.
const declaredKeysManifest = `{"profiles":{
	"adelsaiq":{"key_scope":"per_service",
		"keys":[
			{"name":"imani_github-ed25519","type":"ed25519","rotate_after_days":180},
			{"name":"imani_spare-ed25519"}
		],
		"hosts":[{"alias":"github-danniela","hostname":"github.com","user":"git","key_name":"imani_github-ed25519"}]},
	"personal":{"hosts":[{"alias":"github-imani","hostname":"github.com","user":"git","key_name":"imani_github-ed25519"}]}}}`

func TestDeclaredKeysAreUnionedIntoKeyRefs(t *testing.T) {
	m, err := loadJSON(t, declaredKeysManifest)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := m.KeyRefs()
	if err != nil {
		t.Fatal(err)
	}
	// Host-derived first within a profile, then the declared-only key; profiles
	// in file order (adelsaiq before personal).
	want := []KeyRef{
		{Profile: "adelsaiq", KeyName: "imani_github-ed25519"},
		{Profile: "adelsaiq", KeyName: "imani_spare-ed25519"},
		{Profile: "personal", KeyName: "imani_github-ed25519"},
	}
	if len(refs) != len(want) {
		t.Fatalf("KeyRefs = %v, want %v", refs, want)
	}
	for i, w := range want {
		if refs[i] != w {
			t.Errorf("KeyRefs[%d] = %v, want %v", i, refs[i], w)
		}
	}
	// A key nothing references is still selectable by name, unambiguously.
	ref, err := m.ResolveKeySelector("imani_spare-ed25519")
	if err != nil {
		t.Fatalf("unwired key should resolve: %v", err)
	}
	if ref.Profile != "adelsaiq" {
		t.Errorf("profile = %q, want adelsaiq", ref.Profile)
	}
	hosts, err := m.HostsForKey(ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 0 {
		t.Errorf("unwired key has %d hosts, want 0", len(hosts))
	}
}

func TestDeclaredKeyOverridesInheritDefaults(t *testing.T) {
	m, err := loadJSON(t, declaredKeysManifest)
	if err != nil {
		t.Fatal(err)
	}
	declared := KeyRef{Profile: "adelsaiq", KeyName: "imani_github-ed25519"}
	if got := m.RotateAfterDaysFor(declared); got != 180 {
		t.Errorf("rotate_after_days = %d, want the declared 180", got)
	}
	if got := m.KeyTypeFor(declared); got != "ed25519" {
		t.Errorf("type = %q, want the declared ed25519", got)
	}
	// Declared with no overrides, and not declared at all, both inherit.
	for _, ref := range []KeyRef{
		{Profile: "adelsaiq", KeyName: "imani_spare-ed25519"},
		{Profile: "personal", KeyName: "imani_github-ed25519"},
	} {
		if got := m.RotateAfterDaysFor(ref); got != m.Defaults.RotateAfterDays {
			t.Errorf("%s rotate_after_days = %d, want the default %d", ref, got, m.Defaults.RotateAfterDays)
		}
		if got := m.KeyTypeFor(ref); got != m.Defaults.KeyType {
			t.Errorf("%s type = %q, want the default %q", ref, got, m.Defaults.KeyType)
		}
	}
	if _, ok := m.KeySpecFor(KeyRef{Profile: "personal", KeyName: "imani_github-ed25519"}); ok {
		t.Error("a host-derived key should have no spec")
	}
}

// A manifest that declares no keys must serialize as if the field did not exist,
// since every manifest written before it did is one of those and sshmgr rewrites
// the file on every edit. (Save normalizes other fields - null-filling, number
// coercion - so the contract is "no keys field, and stable across re-saves", not
// byte-equality with the hand-written source.)
func TestKeysOmittedWhenEmpty(t *testing.T) {
	m, err := Load("../../../config/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "out.json")
	if err := m.Save(out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(got), `"keys"`) {
		t.Error("saved manifest emits a keys field for profiles that declare none")
	}
	again, err := Load(out)
	if err != nil {
		t.Fatal(err)
	}
	out2 := filepath.Join(dir, "out2.json")
	if err := again.Save(out2); err != nil {
		t.Fatal(err)
	}
	round, _ := os.ReadFile(out2)
	if string(round) != string(got) {
		t.Error("save is not stable across a load/save round trip")
	}
	// Declared keys do serialize, with unset overrides omitted rather than nulled.
	m2, err := loadJSON(t, declaredKeysManifest)
	if err != nil {
		t.Fatal(err)
	}
	declaredOut := filepath.Join(dir, "declared.json")
	if err := m2.Save(declaredOut); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(declaredOut)
	for _, want := range []string{`"keys"`, `"imani_spare-ed25519"`, `"rotate_after_days": 180`} {
		if !contains(string(b), want) {
			t.Errorf("serialized manifest missing %s", want)
		}
	}
	if contains(string(b), `"type": null`) {
		t.Error("an unset key override should be omitted, not emitted as null")
	}
}

func TestDeclaredKeyValidation(t *testing.T) {
	cases := map[string]string{
		"unsafe key name":  `{"profiles":{"p":{"keys":[{"name":"../escape"}],"hosts":[]}}}`,
		"empty key name":   `{"profiles":{"p":{"keys":[{"name":""}],"hosts":[]}}}`,
		"duplicate key":    `{"profiles":{"p":{"keys":[{"name":"a-ed25519"},{"name":"a-ed25519"}],"hosts":[]}}}`,
		"unknown type":     `{"profiles":{"p":{"keys":[{"name":"a-ed25519","type":"quantum"}],"hosts":[]}}}`,
		"negative rotate":  `{"profiles":{"p":{"keys":[{"name":"a-ed25519","rotate_after_days":-1}],"hosts":[]}}}`,
		"unknown subfield": `{"profiles":{"p":{"keys":[{"name":"a-ed25519","bogus":1}],"hosts":[]}}}`,
	}
	for name, js := range cases {
		if _, err := loadJSON(t, js); err == nil {
			t.Errorf("%s: expected a validation error, got nil", name)
		}
	}
	// The same key name in two profiles stays legal - profiles are orgs.
	if _, err := loadJSON(t, `{"profiles":{
		"a":{"keys":[{"name":"imani_github-ed25519"}],"hosts":[]},
		"b":{"keys":[{"name":"imani_github-ed25519"}],"hosts":[]}}}`); err != nil {
		t.Errorf("per-profile uniqueness should allow the same name in two profiles: %v", err)
	}
}

func TestSharedAndPerServiceResolution(t *testing.T) {
	m, err := loadJSON(t, `{"profiles":{"team":{"key_scope":"shared","key_name":"team_all-ed25519",
		"hosts":[{"alias":"a","hostname":"h1","user":"u"},{"alias":"b","hostname":"h2","user":"u"}]}}}`)
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.IterResolved()
	if err != nil {
		t.Fatal(err)
	}
	for _, rk := range r { // both hosts share the one key
		if rk.KeyName != "team_all-ed25519" {
			t.Errorf("shared host key = %q, want team_all-ed25519", rk.KeyName)
		}
	}
	// per_service with no explicit key_name derives from profile+alias
	m2, _ := loadJSON(t, `{"profiles":{"work":{"hosts":[{"alias":"sc.its.unc.edu","hostname":"h","user":"u"}]}}}`)
	r2, _ := m2.IterResolved()
	if r2[0].KeyName != "work_sc-its-unc-edu-ed25519" {
		t.Errorf("derived key = %q, want work_sc-its-unc-edu-ed25519", r2[0].KeyName)
	}
}

// TestSerializationEmitsAllFieldsInFileOrder locks the byte-parity contract with
// pydantic model_dump: unset pointers -> null, no tags -> [], raw_options -> {},
// and profiles in manifest (file) order, not sorted.
func TestSerializationEmitsAllFieldsInFileOrder(t *testing.T) {
	// "work" before "alpha" - a Go map would sort these the other way.
	m, err := loadJSON(t, `{
	  "version": 1,
	  "profiles": {
	    "work": {"key_scope": "per_service", "hosts": [
	      {"alias": "gh", "hostname": "github.com", "user": "git"}
	    ]},
	    "alpha": {"key_scope": "shared", "key_name": "id_a", "hosts": []}
	  }
	}`)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.json")
	if err := m.Save(out); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	s := string(b)
	for _, want := range []string{
		`"provider": null`, `"token_env": null`, `"tags": []`, `"raw_options": {}`,
		`"vpn_name": null`, `"key_name": null`,
	} {
		if !contains(s, want) {
			t.Errorf("serialized manifest missing %s", want)
		}
	}
	// Profiles must appear in file order: "work" before "alpha".
	wi, ai := index(s, `"work"`), index(s, `"alpha"`)
	if wi < 0 || ai < 0 || wi > ai {
		t.Errorf("profiles not in file order (work before alpha): work@%d alpha@%d", wi, ai)
	}
}

func contains(s, sub string) bool { return index(s, sub) >= 0 }

func index(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// Control characters are refused everywhere a value reaches the rendered config.
// python-final:src/ssh_manager/core/manifest.py::_reject_control.
//
// This is config injection, not tidiness. Every one of these fields is written
// into ~/.ssh/config as `Keyword value`, so a newline in a hostname would end
// the line and start a new directive - a manifest entry could add ProxyCommand
// to a host block that never declared one.
func TestControlCharactersAreRejectedEverywhere(t *testing.T) {
	injections := map[string]string{
		"newline":         "evil.com\\n    ProxyCommand touch /tmp/pwned",
		"carriage return": "evil.com\\r    ProxyCommand x",
		"NUL":             "evil.com\\u0000x",
		"bell":            "evil.com\\u0007",
		"escape":          "evil.com\\u001b[31m",
	}
	for name, payload := range injections {
		// hostname
		if _, err := loadJSON(t, `{"profiles":{"p":{"hosts":[
			{"alias":"a","hostname":"`+payload+`","user":"u"}]}}}`); err == nil {
			t.Errorf("%s in hostname was accepted", name)
		}
		// user
		if _, err := loadJSON(t, `{"profiles":{"p":{"hosts":[
			{"alias":"a","hostname":"h","user":"`+payload+`"}]}}}`); err == nil {
			t.Errorf("%s in user was accepted", name)
		}
		// alias - becomes the `Host` line itself
		if _, err := loadJSON(t, `{"profiles":{"p":{"hosts":[
			{"alias":"`+payload+`","hostname":"h","user":"u"}]}}}`); err == nil {
			t.Errorf("%s in alias was accepted", name)
		}
	}
}

// hostname and user must not start with a dash or contain whitespace: both are
// passed to ssh, where a leading dash reads as a flag and whitespace splits the
// argument. python-final:...::_safe_value.
func TestHostnameAndUserRejectFlagsAndWhitespace(t *testing.T) {
	bad := map[string]string{
		"leading dash": "-oProxyCommand=x",
		"space":        "host name",
		"tab":          "host\\tname",
	}
	for name, value := range bad {
		if _, err := loadJSON(t, `{"profiles":{"p":{"hosts":[
			{"alias":"a","hostname":"`+value+`","user":"u"}]}}}`); err == nil {
			t.Errorf("%s in hostname was accepted", name)
		}
		if _, err := loadJSON(t, `{"profiles":{"p":{"hosts":[
			{"alias":"a","hostname":"h","user":"`+value+`"}]}}}`); err == nil {
			t.Errorf("%s in user was accepted", name)
		}
	}
	// A dash inside the value is fine - plenty of real hostnames have one.
	if _, err := loadJSON(t, `{"profiles":{"p":{"hosts":[
		{"alias":"a","hostname":"my-host.example.com","user":"deploy-bot"}]}}}`); err != nil {
		t.Errorf("an ordinary hostname was rejected: %v", err)
	}
}

// A profile name becomes a directory under profiles/, so it is held to the same
// rules as a key name.
func TestProfileNamesAreSafePathSegments(t *testing.T) {
	for _, bad := range []string{"..", ".", "a/b", `a\b`, "*", "-lead", "with space", ""} {
		js := `{"profiles":{"` + bad + `":{"key_scope":"per_service","hosts":[]}}}`
		if _, err := loadJSON(t, js); err == nil {
			t.Errorf("profile name %q was accepted; it becomes a directory", bad)
		}
	}
	if _, err := loadJSON(t, `{"profiles":{"ad-elsaiq":{"key_scope":"per_service","hosts":[]}}}`); err != nil {
		t.Errorf("an ordinary profile name was rejected: %v", err)
	}
}

// Options that can run a command or pull in more config are refused in both
// places they can appear - the per-host map and the global one. Only raw_options
// was covered before.
func TestDangerousOptionsRejectedInGlobalOptionsToo(t *testing.T) {
	for _, opt := range []string{"ProxyCommand", "LocalCommand", "Match", "Include",
		"KnownHostsCommand", "PKCS11Provider", "RemoteCommand", "PermitLocalCommand"} {
		global := `{"defaults":{"global_options":{"` + opt + `":"x"}},"profiles":{}}`
		if _, err := loadJSON(t, global); err == nil {
			t.Errorf("%s was accepted in global_options", opt)
		}
		host := `{"profiles":{"p":{"hosts":[{"alias":"a","hostname":"h","user":"u",
			"raw_options":{"` + opt + `":"x"}}]}}}`
		if _, err := loadJSON(t, host); err == nil {
			t.Errorf("%s was accepted in raw_options", opt)
		}
	}
	// Case-insensitively, since ssh keywords are.
	if _, err := loadJSON(t, `{"profiles":{"p":{"hosts":[{"alias":"a","hostname":"h","user":"u",
		"raw_options":{"pRoXyCoMmAnD":"x"}}]}}}`); err == nil {
		t.Error("a differently-cased ProxyCommand was accepted")
	}
	// ProxyJump is a host, not a command, and stays allowed.
	if _, err := loadJSON(t, `{"profiles":{"p":{"hosts":[{"alias":"a","hostname":"h","user":"u",
		"raw_options":{"ProxyJump":"bastion"}}]}}}`); err != nil {
		t.Errorf("ProxyJump should be allowed: %v", err)
	}
}

// Option values are stringified the way pydantic did, because they are written
// into the config verbatim. python-final:...::_stringify_raw.
func TestOptionValuesAreStringifiedLikePydantic(t *testing.T) {
	m, err := loadJSON(t, `{"defaults":{"global_options":{
		"ServerAliveInterval":60,"Compression":true,"BatchMode":false,"Nothing":null}},
		"profiles":{}}`)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"ServerAliveInterval": "60",
		"Compression":         "True",  // Python str(True)
		"BatchMode":           "False", // Python str(False)
		"Nothing":             "None",  // Python str(None)
	}
	for k, v := range want {
		if got := m.Defaults.GlobalOptions.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

// The deliberate relaxation, and why it is safe.
//
// python-final:src/ssh_manager/core/manifest.py::_v_key_name_uniqueness
// *rejected* a key_name used by two profiles at load. Its stated reason:
// "rotate/deploy/rollback resolve a key_name back to its host(s) and assume
// they all share ONE profile dir; if two profiles reused a name, rotating one
// would mint into one profile's dir yet deploy to the other profile's hosts -
// orphaning/locking them out."
//
// v2 removes the ban because it removed the hazard: a key is identified by
// KeyRef{profile,key}, and every lifecycle op resolves through it, so a name
// shared by two profiles never selects the wrong directory. This is a widening
// - a manifest Python refused now loads, and nothing that loaded before breaks.
// Recorded as deviation D8.
func TestSharedKeyNameLoadsAndStaysProfileScoped(t *testing.T) {
	m, err := loadJSON(t, dupKeyManifest)
	if err != nil {
		t.Fatalf("a name shared by two profiles must load in v2: %v", err)
	}

	// The hazard the Python named: resolving the shared name must never hand
	// back one profile's hosts under the other profile's directory.
	for _, profile := range []string{"personal", "adelsaiq"} {
		ref := KeyRef{Profile: profile, KeyName: "imani_github-ed25519"}
		hosts, err := m.HostsForKey(ref)
		if err != nil {
			t.Fatal(err)
		}
		if len(hosts) != 1 {
			t.Fatalf("%s: got %d hosts, want only its own", profile, len(hosts))
		}
		want := "~/.ssh/profiles/" + profile + "/imani_github-ed25519"
		if got := m.IdentityFile(ref.Profile, ref.KeyName); got != want {
			t.Errorf("%s identity = %q, want %q", profile, got, want)
		}
	}

	// And the bare name is refused as a selector rather than silently picking
	// one, which is what makes the relaxation safe at the command surface.
	if _, err := m.ResolveKeySelector("imani_github-ed25519"); err == nil {
		t.Error("a bare name shared by two profiles must not resolve silently")
	}
}

// The manifest is the user's whole configuration and Save rewrites it in place
// on every edit. It claimed atomic persistence while using os.WriteFile, which
// truncates first: a crash mid-write left a truncated manifest, and WriteFile
// also kept whatever mode the file already had, so a loosened manifest stayed
// loose through every subsequent save. The inventory had the same pair of bugs
// and has had a test since; this is the more consequential of the two files.
func TestManifestSaveIsAtomicAndReassertsMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	m := Starter(false)
	m.SetProfile("work", Profile{KeyScope: "per_service", Hosts: []Host{
		{Alias: "gh", Hostname: "github.com", User: "git", Port: 22},
	}})
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	// Loosen it the way an errant umask, a restore or a hand edit would.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	m.SetProfile("personal", Profile{KeyScope: "shared", KeyName: strPtr("id_personal")})
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := fi.Mode().Perm(); mode != 0o600 {
			t.Errorf("mode = %04o after save, want 0600: the manifest maps every host and login", mode)
		}
	}
	// Nothing left beside it: the temp file was renamed over, not abandoned.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("save left residue: %v", entries)
	}
	// And what it wrote loads, validates, and holds both profiles.
	back, err := Load(path)
	if err != nil {
		t.Fatalf("the saved manifest does not load: %v", err)
	}
	if names := back.ProfileNames(); len(names) != 2 || names[0] != "work" || names[1] != "personal" {
		t.Errorf("profiles = %v, want [work personal] in file order", names)
	}
}

func strPtr(s string) *string { return &s }
