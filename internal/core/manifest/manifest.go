// Package manifest is the ssh-manager manifest domain model, ported from
// src/ssh_manager/core/manifest.py. The manifest is the single source of truth;
// this package loads/validates it and exposes the per-host key resolution the
// renderer and reconciler depend on (per_service default, shared opt-in).
package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/simtabi/ssh-manager/internal/core/key"
)

const (
	schemaVersion = 1
	sshToken      = "~/.ssh" // IdentityFile paths render in the ~ form
)

var controlChars = regexp.MustCompile(`[\x00-\x1f\x7f]`)

// dangerousOptions run a command, load an object, or pull in further config and
// are never allowed in raw_options / global_options (ProxyJump is a host, allowed).
var dangerousOptions = map[string]bool{
	"proxycommand": true, "localcommand": true, "permitlocalcommand": true,
	"remotecommand": true, "match": true, "include": true,
	"knownhostscommand": true, "pkcs11provider": true, "securitykeyprovider": true,
}

var keyScopes = map[string]bool{"per_service": true, "shared": true}

// DefaultGlobalOptions are the canonical Host* defaults used by Starter.
var DefaultGlobalOptions = map[string]string{
	"AddKeysToAgent": "yes", "IgnoreUnknown": "UseKeychain", "UseKeychain": "yes",
	"IdentitiesOnly": "yes", "ServerAliveInterval": "60",
}

// OrderedOptions is an SSH-option map that preserves JSON key order (the renderer
// emits options in that order) and stringifies values like Python's str().
type OrderedOptions struct {
	keys []string
	vals map[string]string
}

func (o *OrderedOptions) UnmarshalJSON(b []byte) error {
	o.keys = nil
	o.vals = map[string]string{}
	dec := json.NewDecoder(bytes.NewReader(b))
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if t == nil {
		return nil // null -> empty
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("options must be a JSON object")
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return err
		}
		k := kt.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
		if _, seen := o.vals[k]; !seen {
			o.keys = append(o.keys, k)
		}
		o.vals[k] = stringifyJSON(raw)
	}
	_, err = dec.Token() // consume '}'
	return err
}

// MarshalJSON emits the options in their preserved order.
func (o OrderedOptions) MarshalJSON() ([]byte, error) {
	if len(o.keys) == 0 {
		return []byte("{}"), nil
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(o.vals[k])
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// Len, Keys, and Get expose the options in order.
func (o OrderedOptions) Len() int            { return len(o.keys) }
func (o OrderedOptions) Keys() []string      { return o.keys }
func (o OrderedOptions) Get(k string) string { return o.vals[k] }

func stringifyJSON(raw json.RawMessage) string {
	s := strings.TrimSpace(string(raw))
	if len(s) >= 1 && s[0] == '"' {
		var str string
		_ = json.Unmarshal(raw, &str)
		return str
	}
	switch s {
	case "true":
		return "True" // match Python str(True)
	case "false":
		return "False"
	case "null":
		return "None"
	}
	return s // number token, e.g. "60"
}

// Host is a single SSH host entry.
type Host struct {
	Alias       string         `json:"alias"`
	Hostname    string         `json:"hostname"`
	User        string         `json:"user"`
	Port        int            `json:"port"`
	Provider    *string        `json:"provider,omitempty"`
	TokenEnv    *string        `json:"token_env,omitempty"`
	KeyName     *string        `json:"key_name,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	RequiresVPN bool           `json:"requires_vpn"`
	VPNName     *string        `json:"vpn_name,omitempty"`
	VPNURL      *string        `json:"vpn_url,omitempty"`
	RawOptions  OrderedOptions `json:"raw_options,omitempty"`
}

func (h *Host) UnmarshalJSON(b []byte) error {
	type alias Host
	aux := alias{Port: 22}
	if err := decodeStrict(b, &aux); err != nil {
		return err
	}
	*h = Host(aux)
	return nil
}

// Profile groups hosts that share an identity.
type Profile struct {
	KeyScope string  `json:"key_scope"`
	KeyName  *string `json:"key_name,omitempty"`
	Hosts    []Host  `json:"hosts"`
}

func (p *Profile) UnmarshalJSON(b []byte) error {
	type alias Profile
	aux := alias{KeyScope: "per_service"}
	if err := decodeStrict(b, &aux); err != nil {
		return err
	}
	*p = Profile(aux)
	return nil
}

// ExpiryCheck is the notifier policy.
type ExpiryCheck struct {
	Enabled       bool `json:"enabled"`
	DebounceHours int  `json:"debounce_hours"`
	DesktopNotify bool `json:"desktop_notify"`
}

func newExpiryCheck() ExpiryCheck {
	return ExpiryCheck{Enabled: true, DebounceHours: 24, DesktopNotify: true}
}

func (e *ExpiryCheck) UnmarshalJSON(b []byte) error {
	type alias ExpiryCheck
	aux := alias(newExpiryCheck())
	if err := decodeStrict(b, &aux); err != nil {
		return err
	}
	*e = ExpiryCheck(aux)
	return nil
}

// Defaults are manifest-wide defaults.
type Defaults struct {
	KeyType         string         `json:"key_type"`
	KeyScope        string         `json:"key_scope"`
	RotateAfterDays int            `json:"rotate_after_days"`
	WarnBeforeDays  []int          `json:"warn_before_days"`
	ExpiryCheck     ExpiryCheck    `json:"expiry_check"`
	GlobalOptions   OrderedOptions `json:"global_options"`
}

func newDefaults() Defaults {
	return Defaults{
		KeyType: "ed25519", KeyScope: "per_service", RotateAfterDays: 365,
		WarnBeforeDays: []int{30, 14, 7, 1}, ExpiryCheck: newExpiryCheck(),
		GlobalOptions: OrderedOptions{},
	}
}

func (d *Defaults) UnmarshalJSON(b []byte) error {
	type alias Defaults
	aux := alias(newDefaults())
	if err := decodeStrict(b, &aux); err != nil {
		return err
	}
	*d = Defaults(aux)
	return nil
}

// ResolvedKey pairs a host with its resolved key name + IdentityFile path.
type ResolvedKey struct {
	Profile      string
	Host         Host
	KeyName      string
	IdentityFile string
}

// Manifest is the whole manifest.
type Manifest struct {
	Version  int                `json:"version"`
	Defaults Defaults           `json:"defaults"`
	Profiles map[string]Profile `json:"profiles"`
}

func (m *Manifest) UnmarshalJSON(b []byte) error {
	type alias Manifest
	aux := alias{Version: schemaVersion, Defaults: newDefaults(), Profiles: map[string]Profile{}}
	if err := decodeStrict(b, &aux); err != nil {
		return err
	}
	*m = Manifest(aux)
	return nil
}

// decodeStrict decodes with DisallowUnknownFields (pydantic extra="forbid").
func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// --- validation (mirrors the pydantic validators) --------------------------

func rejectControl(field, value string) error {
	if controlChars.MatchString(value) {
		return fmt.Errorf("%s contains a control character or newline", field)
	}
	return nil
}

func safeSegment(field, value string) error {
	if err := rejectControl(field, value); err != nil {
		return err
	}
	bad := value == "" || value == "." || value == ".." ||
		strings.ContainsAny(value, `/\*?`) || strings.HasPrefix(value, "-")
	if !bad {
		for _, r := range value {
			if unicode.IsSpace(r) {
				bad = true
				break
			}
		}
	}
	if bad {
		return fmt.Errorf("%s=%q is not a safe name "+
			"(no empty/'.'/'..'/'/'/'\\'/leading '-'/whitespace/'*'/'?')", field, value)
	}
	return nil
}

func safeValue(field, value string) error {
	if err := rejectControl(field, value); err != nil {
		return err
	}
	if strings.HasPrefix(value, "-") {
		return fmt.Errorf("%s=%q must not start with '-'", field, value)
	}
	for _, r := range value {
		if unicode.IsSpace(r) {
			return fmt.Errorf("%s=%q must not contain whitespace", field, value)
		}
	}
	return nil
}

func checkOptions(field string, opts OrderedOptions) error {
	for _, k := range opts.keys {
		v := opts.vals[k]
		if err := rejectControl(fmt.Sprintf("%s key %q", field, k), k); err != nil {
			return err
		}
		if err := rejectControl(fmt.Sprintf("%s[%s]", field, k), v); err != nil {
			return err
		}
		if dangerousOptions[strings.ToLower(k)] {
			return fmt.Errorf("%s key %q is not allowed (it can execute commands)", field, k)
		}
	}
	return nil
}

func checkKeyScope(value string) error {
	if !keyScopes[value] {
		return fmt.Errorf("key_scope must be one of [per_service shared] (got %q)", value)
	}
	return nil
}

func (m *Manifest) validate() error {
	if err := checkOptions("global_options", m.Defaults.GlobalOptions); err != nil {
		return err
	}
	if err := checkKeyScope(m.Defaults.KeyScope); err != nil {
		return err
	}
	for name, p := range m.Profiles {
		if err := safeSegment("profile name", name); err != nil {
			return err
		}
		if err := checkKeyScope(p.KeyScope); err != nil {
			return err
		}
		if p.KeyName != nil {
			if err := safeSegment("profile key_name", *p.KeyName); err != nil {
				return err
			}
		}
		for _, h := range p.Hosts {
			if err := safeSegment("alias", h.Alias); err != nil {
				return err
			}
			if h.KeyName != nil {
				if err := safeSegment("key_name", *h.KeyName); err != nil {
					return err
				}
			}
			if err := safeValue("hostname", h.Hostname); err != nil {
				return err
			}
			if err := safeValue("user", h.User); err != nil {
				return err
			}
			if err := checkOptions("raw_options", h.RawOptions); err != nil {
				return err
			}
		}
	}
	return m.validateKeyNameUniqueness()
}

func (m *Manifest) validateKeyNameUniqueness() error {
	owner := map[string]string{}
	for _, pname := range m.sortedProfileNames() {
		for _, h := range m.Profiles[pname].Hosts {
			kname, err := m.ResolvedKeyName(pname, h)
			if err != nil {
				continue // unresolvable key reported at use-time
			}
			if prev, ok := owner[kname]; ok && prev != pname {
				return fmt.Errorf("key_name %q is used by both profile %q and %q; "+
					"a key_name must be unique across profiles", kname, prev, pname)
			}
			owner[kname] = pname
		}
	}
	return nil
}

func (m *Manifest) sortedProfileNames() []string {
	names := make([]string, 0, len(m.Profiles))
	for n := range m.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// --- key resolution --------------------------------------------------------

// ResolvedKeyName resolves a host's key name (per_service derives it; shared uses
// the profile key_name).
func (m *Manifest) ResolvedKeyName(profileName string, host Host) (string, error) {
	profile, ok := m.Profiles[profileName]
	if !ok {
		return "", fmt.Errorf("no such profile: %q", profileName)
	}
	if profile.KeyScope == "shared" {
		if profile.KeyName == nil || *profile.KeyName == "" {
			return "", fmt.Errorf("profile %q is shared but sets no key_name", profileName)
		}
		return *profile.KeyName, nil
	}
	if host.KeyName != nil && *host.KeyName != "" {
		return *host.KeyName, nil
	}
	return key.DeriveKeyName(profileName, host.Alias, m.Defaults.KeyType)
}

// IdentityFile is the rendered ~ form path for a key (always forward slashes).
func (m *Manifest) IdentityFile(profileName, keyName string) string {
	return sshToken + "/profiles/" + profileName + "/" + keyName
}

// KnownHostsFile is the per-profile host-key trust store path.
func (m *Manifest) KnownHostsFile(profileName string) string {
	return sshToken + "/profiles/" + profileName + "/known_hosts"
}

// IterResolved returns every host with its resolved key, in profile-name order.
func (m *Manifest) IterResolved() ([]ResolvedKey, error) {
	var out []ResolvedKey
	for _, pname := range m.sortedProfileNames() {
		for _, h := range m.Profiles[pname].Hosts {
			kname, err := m.ResolvedKeyName(pname, h)
			if err != nil {
				return nil, err
			}
			out = append(out, ResolvedKey{
				Profile: pname, Host: h, KeyName: kname,
				IdentityFile: m.IdentityFile(pname, kname),
			})
		}
	}
	return out, nil
}

// NonEmptyProfiles lists profiles that have at least one host (name order).
func (m *Manifest) NonEmptyProfiles() []string {
	var out []string
	for _, n := range m.sortedProfileNames() {
		if len(m.Profiles[n].Hosts) > 0 {
			out = append(out, n)
		}
	}
	return out
}

// --- repository ------------------------------------------------------------

// Load reads and validates a manifest from path.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("manifest not found: %s (run: sshmgr init)", path)
		}
		return nil, fmt.Errorf("manifest could not be read: %s: %w", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest failed validation: %s: %w", path, err)
	}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("manifest failed validation: %w", err)
	}
	return &m, nil
}

// Save writes the manifest as indented JSON.
func (m *Manifest) Save(path string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
