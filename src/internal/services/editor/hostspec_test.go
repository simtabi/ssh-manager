package editor

import (
	"strings"
	"testing"
)

func TestParseHostSpec(t *testing.T) {
	cases := []struct {
		in         string
		host, role string
		port       int
		bad        bool
	}{
		{in: "dani-prd-web-00 206.189.185.129 ploi web", host: "206.189.185.129", role: "web"},
		{in: "db 137.184.219.1 ploi", host: "137.184.219.1"},
		{in: "b 10.0.0.5:2222 admin", host: "10.0.0.5", port: 2222},
		{in: "v6 2001:db8::1 root", host: "2001:db8::1"},
		{in: "v6p [2001:db8::1]:2200 root", host: "2001:db8::1", port: 2200},
		{in: "x host", bad: true},
		{in: "x a b c d", bad: true},
		{in: "x h:99999 u", bad: true},
		{in: "x h:abc u", bad: true},
	}
	for _, c := range cases {
		s, err := ParseHostSpecLine(c.in)
		if c.bad {
			if err == nil {
				t.Errorf("%q: want an error, got %+v", c.in, s)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if s.Hostname != c.host || s.Port != c.port || s.Role != c.role {
			t.Errorf("%q: got %+v", c.in, s)
		}
	}
}

func TestParseHostSpecsTextAndJSON(t *testing.T) {
	text := "# servers\n\ndani-prd-web-00 206.189.185.129 ploi web  # web\ndani-prd-db-00 137.184.219.1 ploi db\n"
	s, err := ParseHostSpecs(strings.NewReader(text))
	if err != nil || len(s) != 2 || s[1].Role != "db" {
		t.Fatalf("text: %v %+v", err, s)
	}
	if _, err := ParseHostSpecs(strings.NewReader("ok h u\nbroken\n")); err == nil ||
		!strings.Contains(err.Error(), "line 2") {
		t.Errorf("a bad line should be named by number, got %v", err)
	}
	js := `["a 1.1.1.1 u web", {"alias":"b","host":"2.2.2.2:2022","user":"u","role":"db","tags":["prd"]}]`
	s, err = ParseHostSpecs(strings.NewReader(js))
	if err != nil || len(s) != 2 || s[1].Port != 2022 || s[1].Hostname != "2.2.2.2" {
		t.Fatalf("json: %v %+v", err, s)
	}
	if got := strings.Join(s[1].AllTags(), ","); got != "db,prd" {
		t.Errorf("tags=%s", got)
	}
	if _, err := ParseHostSpecs(strings.NewReader(`[{"alias":"b","hostname":"x","user":"u"}]`)); err == nil {
		t.Error("an unknown JSON field should be refused")
	}
}

func TestApplyHostsUpserts(t *testing.T) {
	ed, p := setup(t)
	specs := []HostSpec{
		{Alias: "gh", Hostname: "github.com", User: "git"},
		{Alias: "web", Hostname: "1.2.3.4", User: "ploi", Role: "web"},
	}
	res, err := ed.ApplyHosts("work", specs, false)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Action != HostUnchanged || res[1].Action != HostAdded {
		t.Fatalf("first apply: %+v", res)
	}
	h := reload(t, p).Profiles["work"].Hosts[1]
	if h.Hostname != "1.2.3.4" || h.Port != 22 || len(h.Tags) != 1 || h.Tags[0] != "web" {
		t.Fatalf("added host: %+v", h)
	}

	// Update: new IP and port, extra tag merged, role kept once.
	specs[1] = HostSpec{Alias: "web", Hostname: "5.6.7.8", User: "ploi", Port: 2222, Role: "web", Tags: []string{"prd"}}
	res, err = ed.ApplyHosts("work", specs[1:], false)
	if err != nil || res[0].Action != HostUpdated || len(res[0].Changes) != 3 {
		t.Fatalf("update: %v %+v", err, res)
	}
	h = reload(t, p).Profiles["work"].Hosts[1]
	if h.Hostname != "5.6.7.8" || h.Port != 2222 || strings.Join(h.Tags, ",") != "web,prd" {
		t.Fatalf("updated host: %+v", h)
	}

	// Port omitted on update leaves it alone.
	res, _ = ed.ApplyHosts("work", []HostSpec{{Alias: "web", Hostname: "5.6.7.8", User: "ploi"}}, false)
	if res[0].Action != HostUnchanged {
		t.Errorf("re-apply without port should be unchanged: %+v", res)
	}
}

func TestApplyHostsDryRunAndAtomicity(t *testing.T) {
	ed, p := setup(t)
	if _, err := ed.ApplyHosts("work", []HostSpec{{Alias: "n", Hostname: "h", User: "u"}}, true); err != nil {
		t.Fatal(err)
	}
	if len(reload(t, p).Profiles["work"].Hosts) != 1 {
		t.Error("dry run wrote the manifest")
	}
	// One spec the manifest refuses (whitespace-free check: config syntax) fails the batch.
	bad := []HostSpec{{Alias: "ok", Hostname: "h", User: "u"}, {Alias: "bad", Hostname: "h\"x", User: "u"}}
	if _, err := ed.ApplyHosts("work", bad, false); err == nil {
		t.Fatal("an invalid host should fail the batch")
	}
	if len(reload(t, p).Profiles["work"].Hosts) != 1 {
		t.Error("a failed batch saved part of itself")
	}
	dup := []HostSpec{{Alias: "a", Hostname: "h", User: "u"}, {Alias: "a", Hostname: "h", User: "u"}}
	if _, err := ed.ApplyHosts("work", dup, false); err == nil {
		t.Error("a repeated alias should be refused")
	}
	if _, err := ed.ApplyHosts("nope", dup[:1], false); err == nil {
		t.Error("an unknown profile should be refused")
	}
}
