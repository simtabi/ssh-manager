package editor

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/util/log"
)

// HostSpec is one compact host declaration: `<alias> <host>[:port] <user> [role]`,
// e.g. `dani-prd-web-00 206.189.185.129 ploi web`. The role, when given, is
// stored as a tag. Port 0 means "not given": 22 on add, unchanged on update.
type HostSpec struct {
	Alias    string   `json:"alias"`
	Hostname string   `json:"host"`
	User     string   `json:"user"`
	Port     int      `json:"port,omitempty"`
	Role     string   `json:"role,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

// AllTags is the role followed by any extra tags, de-duplicated, in order.
func (s HostSpec) AllTags() []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range append([]string{s.Role}, s.Tags...) {
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// ParseHostSpec parses one spec from its whitespace-separated fields.
func ParseHostSpec(fields []string) (HostSpec, error) {
	if len(fields) < 3 || len(fields) > 4 {
		return HostSpec{}, fmt.Errorf("host spec %q: want `<alias> <host>[:port] <user> [role]` "+
			"(3 or 4 fields, got %d)", strings.Join(fields, " "), len(fields))
	}
	host, port, err := splitHostPort(fields[1])
	if err != nil {
		return HostSpec{}, fmt.Errorf("host spec %q: %w", strings.Join(fields, " "), err)
	}
	s := HostSpec{Alias: fields[0], Hostname: host, User: fields[2], Port: port}
	if len(fields) == 4 {
		s.Role = fields[3]
	}
	return s, s.check()
}

// ParseHostSpecLine parses one spec written as a single string.
func ParseHostSpecLine(line string) (HostSpec, error) { return ParseHostSpec(strings.Fields(line)) }

// ParseHostSpecs reads many specs. Text is one spec per line, with blank lines
// and `#` comments skipped. Input whose first non-space byte is `[` is read as a
// JSON array whose items are either spec strings or objects
// ({"alias","host","user","port","role","tags"}).
func ParseHostSpecs(r io.Reader) ([]HostSpec, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if t := bytes.TrimSpace(b); len(t) > 0 && t[0] == '[' {
		return parseJSONSpecs(t)
	}
	var out []HostSpec
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		s, err := ParseHostSpecLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

func parseJSONSpecs(b []byte) ([]HostSpec, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("host specs: %w", err)
	}
	out := make([]HostSpec, 0, len(raw))
	for i, item := range raw {
		var line string
		if json.Unmarshal(item, &line) == nil {
			s, err := ParseHostSpecLine(line)
			if err != nil {
				return nil, fmt.Errorf("item %d: %w", i, err)
			}
			out = append(out, s)
			continue
		}
		var s HostSpec
		dec := json.NewDecoder(bytes.NewReader(item))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&s); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		if s.Port == 0 && strings.Contains(s.Hostname, ":") {
			h, p, err := splitHostPort(s.Hostname)
			if err != nil {
				return nil, fmt.Errorf("item %d: %w", i, err)
			}
			s.Hostname, s.Port = h, p
		}
		if err := s.check(); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		out = append(out, s)
	}
	return out, nil
}

// splitHostPort accepts host, host:port, [v6] and [v6]:port. A bare IPv6
// address (more than one colon, no brackets) is taken as a host with no port.
func splitHostPort(v string) (string, int, error) {
	if strings.Count(v, ":") > 1 && !strings.HasPrefix(v, "[") {
		return v, 0, nil
	}
	if !strings.Contains(v, ":") {
		return strings.Trim(v, "[]"), 0, nil
	}
	if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
		return v[1 : len(v)-1], 0, nil
	}
	h, ps, err := net.SplitHostPort(v)
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.Atoi(ps)
	if err != nil || p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("port %q must be 1-65535", ps)
	}
	return h, p, nil
}

func (s HostSpec) check() error {
	for _, f := range []struct{ name, v string }{{"alias", s.Alias}, {"host", s.Hostname}, {"user", s.User}} {
		if strings.TrimSpace(f.v) == "" {
			return fmt.Errorf("%s is empty", f.name)
		}
	}
	if s.Port < 0 || s.Port > 65535 {
		return fmt.Errorf("port %d must be 1-65535", s.Port)
	}
	return nil
}

// ApplyAction is what ApplyHosts did (or would do) to one host.
type ApplyAction string

const (
	HostAdded     ApplyAction = "added"
	HostUpdated   ApplyAction = "updated"
	HostUnchanged ApplyAction = "unchanged"
)

// ApplyResult is one host's outcome; Changes lists the fields that moved.
type ApplyResult struct {
	Alias   string
	Action  ApplyAction
	Changes []string
}

// ApplyHosts upserts specs into a profile: a missing alias is added the way
// `host add` adds it, an existing one is edited the way `host edit` edits it
// (hostname, user, port when given) and has its role/tags merged in - never
// removed. The whole batch is validated by the manifest's own rules and
// saved once, so a bad spec leaves the manifest untouched. dryRun reports
// without saving.
func (e *Editor) ApplyHosts(profile string, specs []HostSpec, dryRun bool) ([]ApplyResult, error) {
	m, err := e.load()
	if err != nil {
		return nil, err
	}
	res, err := applyHostsIn(m, profile, specs)
	if err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if dryRun {
		return res, nil
	}
	changed := false
	for _, r := range res {
		changed = changed || r.Action != HostUnchanged
	}
	if !changed {
		return res, nil
	}
	if err := m.Save(e.p.Manifest()); err != nil {
		return nil, err
	}
	for _, r := range res {
		if r.Action != HostUnchanged {
			log.Audit(e.p.AuditLog(), "host.apply", log.Field{Key: "profile", Value: profile},
				log.Field{Key: "alias", Value: r.Alias}, log.Field{Key: "action", Value: string(r.Action)})
		}
	}
	return res, nil
}

func applyHostsIn(m *manifest.Manifest, profile string, specs []HostSpec) ([]ApplyResult, error) {
	if _, ok := m.Profiles[profile]; !ok {
		return nil, fmt.Errorf("unknown profile: %q", profile)
	}
	seen := map[string]bool{}
	var out []ApplyResult
	for _, s := range specs {
		if err := s.check(); err != nil {
			return nil, fmt.Errorf("%s: %w", s.Alias, err)
		}
		if seen[s.Alias] {
			return nil, fmt.Errorf("host %q is given more than once", s.Alias)
		}
		seen[s.Alias] = true
		tags := s.AllTags()
		idx, cur, err := findHost(m, profile, s.Alias)
		if err != nil {
			f := HostFields{Hostname: &s.Hostname, User: &s.User, Tags: tags}
			if s.Port != 0 {
				f.Port = &s.Port
			}
			if err := addHostTo(m, profile, s.Alias, f); err != nil {
				return nil, err
			}
			out = append(out, ApplyResult{Alias: s.Alias, Action: HostAdded})
			continue
		}
		var changes []string
		f := HostFields{}
		if cur.Hostname != s.Hostname {
			f.Hostname = &s.Hostname
			changes = append(changes, fmt.Sprintf("hostname %s -> %s", cur.Hostname, s.Hostname))
		}
		if cur.User != s.User {
			f.User = &s.User
			changes = append(changes, fmt.Sprintf("user %s -> %s", cur.User, s.User))
		}
		if s.Port != 0 && cur.Port != s.Port {
			f.Port = &s.Port
			changes = append(changes, fmt.Sprintf("port %d -> %d", cur.Port, s.Port))
		}
		if err := editHostIn(m, profile, s.Alias, f); err != nil {
			return nil, err
		}
		var added []string
		p := m.Profiles[profile]
		h := p.Hosts[idx]
		for _, t := range tags {
			if !containsStr(h.Tags, t) {
				h.Tags = append(h.Tags, t)
				added = append(added, t)
			}
		}
		if len(added) > 0 {
			p.Hosts[idx] = h
			m.SetProfile(profile, p)
			changes = append(changes, "tags +"+strings.Join(added, ",+"))
		}
		act := HostUnchanged
		if len(changes) > 0 {
			act = HostUpdated
		}
		out = append(out, ApplyResult{Alias: s.Alias, Action: act, Changes: changes})
	}
	return out, nil
}

func containsStr(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
