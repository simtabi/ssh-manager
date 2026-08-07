// Package manifest is the ssh-manager manifest domain model. The manifest is
// the single source of truth;
// this package loads/validates it and exposes the per-host key resolution the
// renderer and reconciler depend on (per_service default, shared opt-in).
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/key"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/fs"
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

// IsDangerousOption reports whether an SSH option key can execute commands / pull
// in config (dropped on import, rejected by validation). Case-insensitive.
func IsDangerousOption(key string) bool { return dangerousOptions[strings.ToLower(key)] }

var keyScopes = map[string]bool{"per_service": true, "shared": true}

// DefaultGlobalOptions are the canonical Host* defaults used by Starter.
var DefaultGlobalOptions = map[string]string{
	"AddKeysToAgent": "yes", "IgnoreUnknown": "UseKeychain", "UseKeychain": "yes",
	"IdentitiesOnly": "yes", "ServerAliveInterval": "60",
}

// OrderedOptions is an SSH-option map that preserves JSON key order (the renderer
// emits options in that order) and stringifies values the way v1 did.
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

// NewOrderedOptions builds an OrderedOptions from ordered key/value pairs (later
// duplicates overwrite the value but keep the first position).
func NewOrderedOptions(pairs [][2]string) OrderedOptions {
	o := OrderedOptions{vals: map[string]string{}}
	for _, p := range pairs {
		if _, seen := o.vals[p[0]]; !seen {
			o.keys = append(o.keys, p[0])
		}
		o.vals[p[0]] = p[1]
	}
	return o
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
		return "True" // the spelling v1 wrote for a true value
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

// MarshalJSON emits every field in declaration order (null for unset pointers, []
// for no tags), matching the files v1 and v2 wrote. raw_options serializes
// {} when empty via OrderedOptions.
func (h Host) MarshalJSON() ([]byte, error) {
	type wire struct {
		Alias       string         `json:"alias"`
		Hostname    string         `json:"hostname"`
		User        string         `json:"user"`
		Port        int            `json:"port"`
		Provider    *string        `json:"provider"`
		TokenEnv    *string        `json:"token_env"`
		KeyName     *string        `json:"key_name"`
		Tags        []string       `json:"tags"`
		RequiresVPN bool           `json:"requires_vpn"`
		VPNName     *string        `json:"vpn_name"`
		VPNURL      *string        `json:"vpn_url"`
		RawOptions  OrderedOptions `json:"raw_options"`
	}
	tags := h.Tags
	if tags == nil {
		tags = []string{}
	}
	return json.Marshal(wire{
		Alias: h.Alias, Hostname: h.Hostname, User: h.User, Port: h.Port,
		Provider: h.Provider, TokenEnv: h.TokenEnv, KeyName: h.KeyName, Tags: tags,
		RequiresVPN: h.RequiresVPN, VPNName: h.VPNName, VPNURL: h.VPNURL, RawOptions: h.RawOptions,
	})
}

// KeySpec declares a key as a first-class member of its profile, independent of
// any host that uses it. Type and rotate_after_days are optional and inherit the
// manifest defaults when unset (see KeyTypeFor / RotateAfterDaysFor).
//
// Declaring is optional in both directions: a host whose key_name names a key
// absent from the list still implicitly declares it, so every pre-`keys`
// manifest loads and renders unchanged. The list exists so a profile can own a
// key no host references yet - a second identity for the same org, or a key
// minted ahead of the host it will serve - which previously could not be
// expressed at all, since a key existed only as a property of a host.
type KeySpec struct {
	Name string `json:"name"`
	// Unset (rather than defaulted-on-load) so re-saving a manifest does not
	// bake today's defaults into every key, freezing them against a later
	// change to defaults.key_type / defaults.rotate_after_days.
	Type            *string `json:"type,omitempty"`
	RotateAfterDays *int    `json:"rotate_after_days,omitempty"`
}

func (k *KeySpec) UnmarshalJSON(b []byte) error {
	type alias KeySpec
	var aux alias
	if err := decodeStrict(b, &aux); err != nil {
		return err
	}
	*k = KeySpec(aux)
	return nil
}

// Profile groups hosts that share an identity, plus the keys it owns.
type Profile struct {
	KeyScope string    `json:"key_scope"`
	KeyName  *string   `json:"key_name,omitempty"`
	Keys     []KeySpec `json:"keys,omitempty"`
	Hosts    []Host    `json:"hosts"`
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

// MarshalJSON emits key_scope, key_name (null when unset), and hosts ([] when
// none) in declaration order, matching those files. keys is the one field
// emitted only when non-empty: it is a v2 addition with no counterpart there, and
// omitting it keeps a manifest that declares no keys - i.e. every manifest
// written before this field existed - byte-identical across a load/save cycle.
func (p Profile) MarshalJSON() ([]byte, error) {
	type wire struct {
		KeyScope string    `json:"key_scope"`
		KeyName  *string   `json:"key_name"`
		Keys     []KeySpec `json:"keys,omitempty"`
		Hosts    []Host    `json:"hosts"`
	}
	hosts := p.Hosts
	if hosts == nil {
		hosts = []Host{}
	}
	return json.Marshal(wire{KeyScope: p.KeyScope, KeyName: p.KeyName, Keys: p.Keys, Hosts: hosts})
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

// MarshalJSON emits warn_before_days as [] when empty (not null) and global_options
// as {} via OrderedOptions, in declaration order.
func (d Defaults) MarshalJSON() ([]byte, error) {
	type wire struct {
		KeyType         string         `json:"key_type"`
		KeyScope        string         `json:"key_scope"`
		RotateAfterDays int            `json:"rotate_after_days"`
		WarnBeforeDays  []int          `json:"warn_before_days"`
		ExpiryCheck     ExpiryCheck    `json:"expiry_check"`
		GlobalOptions   OrderedOptions `json:"global_options"`
	}
	warn := d.WarnBeforeDays
	if warn == nil {
		warn = []int{}
	}
	return json.Marshal(wire{
		KeyType: d.KeyType, KeyScope: d.KeyScope, RotateAfterDays: d.RotateAfterDays,
		WarnBeforeDays: warn, ExpiryCheck: d.ExpiryCheck, GlobalOptions: d.GlobalOptions,
	})
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

	// profileOrder is the JSON insertion order of profile keys. The renderer
	// emits in name order, but the read views (query.groups) iterate the manifest
	// in file order, so we preserve it to match v1's list/view output order.
	profileOrder []string
}

func (m *Manifest) UnmarshalJSON(b []byte) error {
	type alias Manifest
	aux := alias{Version: schemaVersion, Defaults: newDefaults(), Profiles: map[string]Profile{}}
	if err := decodeStrict(b, &aux); err != nil {
		return err
	}
	*m = Manifest(aux)
	var top map[string]json.RawMessage
	if json.Unmarshal(b, &top) == nil {
		if pr, ok := top["profiles"]; ok {
			m.profileOrder = objectKeyOrder(pr)
		}
	}
	return nil
}

// MarshalJSON emits {version, defaults, profiles} with profiles in manifest (file)
// order - a Go map would otherwise marshal its keys sorted. Compact output;
// Save re-indents it to two spaces, the indentation those files used.
func (m Manifest) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(`{"version":`)
	vb, err := json.Marshal(m.Version)
	if err != nil {
		return nil, err
	}
	b.Write(vb)
	b.WriteString(`,"defaults":`)
	db, err := json.Marshal(m.Defaults)
	if err != nil {
		return nil, err
	}
	b.Write(db)
	b.WriteString(`,"profiles":{`)
	for i, name := range m.ProfileNames() {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(name)
		b.Write(kb)
		b.WriteByte(':')
		pb, err := json.Marshal(m.Profiles[name])
		if err != nil {
			return nil, err
		}
		b.Write(pb)
	}
	b.WriteString("}}")
	return b.Bytes(), nil
}

// objectKeyOrder returns a JSON object's keys in their textual order (nil if raw
// is not an object), the same token-stream technique OrderedOptions uses.
func objectKeyOrder(raw json.RawMessage) []string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	t, err := dec.Token()
	if err != nil {
		return nil
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil
	}
	var keys []string
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return keys
		}
		keys = append(keys, kt.(string))
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			return keys
		}
	}
	return keys
}

// ProfileNames returns profile names in manifest (file) order. Falls back to
// name order for a programmatically built manifest with no captured order.
func (m *Manifest) ProfileNames() []string {
	if len(m.profileOrder) == len(m.Profiles) {
		return m.profileOrder
	}
	return m.sortedProfileNames()
}

// SetProfile adds or replaces a profile, preserving file order (a new profile is
// appended, as v1 did).
func (m *Manifest) SetProfile(name string, p Profile) {
	if _, ok := m.Profiles[name]; !ok {
		m.profileOrder = append(m.profileOrder, name)
	}
	if m.Profiles == nil {
		m.Profiles = map[string]Profile{}
	}
	m.Profiles[name] = p
}

// DeleteProfile removes a profile and its order entry.
func (m *Manifest) DeleteProfile(name string) {
	delete(m.Profiles, name)
	for i, n := range m.profileOrder {
		if n == name {
			m.profileOrder = append(m.profileOrder[:i], m.profileOrder[i+1:]...)
			break
		}
	}
}

// Validate re-runs the manifest validators (so a bad edit can't be persisted).
func (m *Manifest) Validate() error { return m.validate() }

// decodeStrict decodes with DisallowUnknownFields: an unknown key is a typo or
// a newer file, and silently dropping it loses configuration the user wrote.
func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// --- validation --------------------------------------------------------------

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

// checkAliasCollisions rejects a Host alias declared more than once anywhere in
// the manifest, in any profile.
//
// Under inline rendering every Host block lives in one file, so a duplicate
// alias is no longer a doctor warning about which per-profile file Include
// happened to expand first - it is dead config, deterministically: ssh takes
// the first Host block it sees for that alias and silently ignores every
// other one, in manifest (file) order. That is unambiguous enough to reject
// outright rather than merely report.
func checkAliasCollisions(m *Manifest) error {
	count := map[string]int{}
	profiles := map[string]map[string]bool{}
	for _, pname := range m.sortedProfileNames() {
		for _, h := range m.Profiles[pname].Hosts {
			count[h.Alias]++
			if profiles[h.Alias] == nil {
				profiles[h.Alias] = map[string]bool{}
			}
			profiles[h.Alias][pname] = true
		}
	}
	aliases := make([]string, 0, len(count))
	for a := range count {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		if count[alias] < 2 {
			continue
		}
		profs := make([]string, 0, len(profiles[alias]))
		for p := range profiles[alias] {
			profs = append(profs, p)
		}
		sort.Strings(profs)
		return fmt.Errorf("alias %q is declared more than once (profiles: %s) - "+
			"every Host block renders into one file, so only the first would take effect",
			alias, strings.Join(profs, ", "))
	}
	return nil
}

// checkDeclaredKeys validates one profile's keys list. Names are path segments
// (they become file names under profiles/<profile>/) and unique within the
// profile - not globally, since a profile models an org and the same person's
// key name legitimately recurs across orgs.
func checkDeclaredKeys(profileName string, p Profile) error {
	seen := map[string]bool{}
	for _, k := range p.Keys {
		if err := safeSegment("key name", k.Name); err != nil {
			return err
		}
		if seen[k.Name] {
			return fmt.Errorf("profile %q declares key %q more than once", profileName, k.Name)
		}
		seen[k.Name] = true
		if k.Type != nil && !key.IsKnownAlgo(*k.Type) {
			return fmt.Errorf("key %q in profile %q has an unknown type %q", k.Name, profileName, *k.Type)
		}
		if k.RotateAfterDays != nil && *k.RotateAfterDays < 0 {
			return fmt.Errorf("key %q in profile %q has a negative rotate_after_days", k.Name, profileName)
		}
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
	if err := checkAliasCollisions(m); err != nil {
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
		if err := checkDeclaredKeys(name, p); err != nil {
			return err
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

// KeyRef names one key: the profile that owns it plus the file name inside that
// profile's directory. Key names are unique per profile, not globally - a person
// working under two orgs uses the same file name in both profile directories.
type KeyRef struct {
	Profile string
	KeyName string
}

// String renders the composite "profile/key" selector form.
func (r KeyRef) String() string { return r.Profile + "/" + r.KeyName }

// ResolveKeySelector turns a user-supplied key selector into a single KeyRef.
// It accepts the composite "profile/key" form, or a bare key name when exactly
// one profile uses it. A bare name matched by several profiles is an error
// listing the candidates, because the caller would otherwise operate on one
// profile's files while touching another's hosts.
func (m *Manifest) ResolveKeySelector(selector string) (KeyRef, error) {
	if selector == "" {
		return KeyRef{}, errors.New("no key given")
	}
	refs, err := m.KeyRefs()
	if err != nil {
		return KeyRef{}, err
	}
	if pname, kname, ok := strings.Cut(selector, "/"); ok {
		for _, r := range refs {
			if r.Profile == pname && r.KeyName == kname {
				return r, nil
			}
		}
		if _, exists := m.Profiles[pname]; !exists {
			return KeyRef{}, fmt.Errorf("no such profile: %q", pname)
		}
		return KeyRef{}, fmt.Errorf("no key %q in profile %q", kname, pname)
	}
	var matches []KeyRef
	for _, r := range refs {
		if r.KeyName == selector {
			matches = append(matches, r)
		}
	}
	switch len(matches) {
	case 0:
		return KeyRef{}, fmt.Errorf("no such key: %q", selector)
	case 1:
		return matches[0], nil
	default:
		names := make([]string, 0, len(matches))
		for _, r := range matches {
			names = append(names, r.String())
		}
		return KeyRef{}, fmt.Errorf("key %q is ambiguous - it exists in %d profiles; "+
			"use one of: %s", selector, len(matches), strings.Join(names, ", "))
	}
}

// KeyRefs lists every distinct key in the manifest - the union of the keys each
// profile declares and the keys its hosts resolve to - deduplicated per profile
// so that hosts sharing one key yield a single ref. Refs are grouped by profile
// in manifest (file) order; within a profile, host-derived keys come first in
// host order, then any declared key no host uses.
//
// The union is what makes a declared key real: it has no Host block, so walking
// IterResolved alone (which iterates hosts) leaves it invisible to reconcile,
// validate, doctor, list and expiry - present in the manifest, never minted,
// never checked.
func (m *Manifest) KeyRefs() ([]KeyRef, error) {
	resolved, err := m.IterResolved()
	if err != nil {
		return nil, err
	}
	fromHosts := map[string][]string{}
	for _, rk := range resolved {
		fromHosts[rk.Profile] = append(fromHosts[rk.Profile], rk.KeyName)
	}
	seen := map[KeyRef]bool{}
	var out []KeyRef
	add := func(profile, keyName string) {
		ref := KeyRef{Profile: profile, KeyName: keyName}
		if seen[ref] {
			return
		}
		seen[ref] = true
		out = append(out, ref)
	}
	for _, pname := range m.ProfileNames() {
		for _, kname := range fromHosts[pname] {
			add(pname, kname)
		}
		for _, spec := range m.Profiles[pname].Keys {
			add(pname, spec.Name)
		}
	}
	return out, nil
}

// KeySpecFor returns the profile's declaration for one key, if it has one. A
// key that only exists because a host names it has no spec and inherits every
// default.
func (m *Manifest) KeySpecFor(ref KeyRef) (KeySpec, bool) {
	for _, spec := range m.Profiles[ref.Profile].Keys {
		if spec.Name == ref.KeyName {
			return spec, true
		}
	}
	return KeySpec{}, false
}

// KeyTypeFor resolves the algorithm to mint a key with: the declared type when
// the profile declares one, else the manifest default.
func (m *Manifest) KeyTypeFor(ref KeyRef) string {
	if spec, ok := m.KeySpecFor(ref); ok && spec.Type != nil && *spec.Type != "" {
		return *spec.Type
	}
	return m.Defaults.KeyType
}

// RotateAfterDaysFor resolves a key's rotation interval the same way.
func (m *Manifest) RotateAfterDaysFor(ref KeyRef) int {
	if spec, ok := m.KeySpecFor(ref); ok && spec.RotateAfterDays != nil {
		return *spec.RotateAfterDays
	}
	return m.Defaults.RotateAfterDays
}

// HostsForKey returns the hosts that use one key, scoped to its own profile.
func (m *Manifest) HostsForKey(ref KeyRef) ([]Host, error) {
	resolved, err := m.IterResolved()
	if err != nil {
		return nil, err
	}
	var hosts []Host
	for _, rk := range resolved {
		if rk.Profile == ref.Profile && rk.KeyName == ref.KeyName {
			hosts = append(hosts, rk.Host)
		}
	}
	return hosts, nil
}

// KnownHostsFile is the single, user-wide host-key trust store path. Every
// rendered host block points at this same file: splitting it per profile gave
// up cross-profile duplicate detection for no isolation ssh itself enforces
// (any profile's ssh invocation can read any other profile's known_hosts), so
// there is exactly one store, tagged and reference-counted per line instead of
// separated by directory.
func (m *Manifest) KnownHostsFile() string {
	return sshToken + "/known_hosts"
}

// IterResolved returns every host with its resolved key, in manifest (file)
// order - the order v1 resolved them in. Order
// is observable in order-preserving consumers like doctor's unpinned-host list;
// the rendered config is order-independent (the root config uses Include).
func (m *Manifest) IterResolved() ([]ResolvedKey, error) {
	var out []ResolvedKey
	for _, pname := range m.ProfileNames() {
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

// NonEmptyProfiles lists profiles that have at least one host, in manifest (file)
// order - the order v1 listed non-empty profiles in.
func (m *Manifest) NonEmptyProfiles() []string {
	var out []string
	for _, n := range m.ProfileNames() {
		if len(m.Profiles[n].Hosts) > 0 {
			out = append(out, n)
		}
	}
	return out
}

// --- repository ------------------------------------------------------------

// defaultGlobalOptions is the starter SSH global-options block (declaration order
// matters - it is the rendered order). Mirrors manifest.DEFAULT_GLOBAL_OPTIONS.
var defaultGlobalOptions = [][2]string{
	{"AddKeysToAgent", "yes"},
	{"IgnoreUnknown", "UseKeychain"},
	{"UseKeychain", "yes"},
	{"IdentitiesOnly", "yes"},
	{"ServerAliveInterval", "60"},
}

// Starter returns a minimal valid manifest for `sshmgr init` - defaults and no
// profiles. Off macOS, the UseKeychain option is dropped. Mirrors Manifest.starter.
func Starter(emitUseKeychain bool) *Manifest {
	pairs := defaultGlobalOptions
	if !emitUseKeychain {
		filtered := make([][2]string, 0, len(pairs))
		for _, p := range pairs {
			if p[0] != "UseKeychain" {
				filtered = append(filtered, p)
			}
		}
		pairs = filtered
	}
	d := newDefaults()
	d.GlobalOptions = NewOrderedOptions(pairs)
	return &Manifest{Version: schemaVersion, Defaults: d, Profiles: map[string]Profile{}}
}

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

// Save writes the manifest as indented JSON, atomically.
//
// Via a temp file and a rename, not os.WriteFile: WriteFile truncates the target
// first, so a crash or a full disk mid-write leaves a truncated manifest - and
// the manifest is the only description of every profile, host and key, with
// nothing to rebuild it from. It also keeps whatever mode the file already had,
// while this re-asserts 0600 on every write.
func (m *Manifest) Save(path string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return fs.WriteTextAtomic(path, string(b)+"\n", 0o600)
}
