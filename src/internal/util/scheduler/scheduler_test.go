package scheduler

import (
	"reflect"
	"strings"
	"testing"
)

func TestBuildPlist(t *testing.T) {
	p := buildPlist("ssh_manager.expiry", `"/opt/my apps/sshmgr" audit --notify`)
	for _, want := range []string{
		"<key>Label</key><string>ssh_manager.expiry</string>",
		"        <string>/opt/my apps/sshmgr</string>", // quoted path stays one arg
		"        <string>audit</string>",
		"        <string>--notify</string>",
		"<key>Hour</key><integer>9</integer><key>Minute</key><integer>0</integer>",
		"<key>RunAtLoad</key><false/>",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("plist missing %q\n%s", want, p)
		}
	}
}

func TestBuildService(t *testing.T) {
	s := buildService("/x/sshmgr audit --notify")
	if !strings.Contains(s, "ExecStart=/x/sshmgr audit --notify") {
		t.Errorf("service unit wrong:\n%s", s)
	}
	if !strings.Contains(buildService("a %p b"), "ExecStart=a %%p b") {
		t.Error("a literal %% should be escaped in ExecStart")
	}
}

func TestShlexSplit(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`/usr/bin/sshmgr audit --notify`, []string{"/usr/bin/sshmgr", "audit", "--notify"}},
		{`"/opt/my apps/sshmgr" audit`, []string{"/opt/my apps/sshmgr", "audit"}},
	}
	for _, c := range cases {
		if got := shlexSplit(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("shlexSplit(%q)=%v want %v", c.in, got, c.want)
		}
	}
}
