package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/preflight"
)

func TestStaleProxiesReportsOnlyMissingSshmgrPaths(t *testing.T) {
	ssh := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfg := "Host devbox\n    ProxyCommand \"/gone/after/upgrade/sshmgr\" vm proxy devbox\n\n" +
		"Host lab\n    ProxyCommand \"" + self + "\" vm proxy lab\n\n" +
		"Host jump\n    ProxyCommand ssh -W %h:%p bastion\n"
	if err := os.WriteFile(filepath.Join(ssh, "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	got := staleProxies(ssh, manifest.Starter(false))
	if len(got) != 1 || !strings.Contains(got[0], "/gone/after/upgrade/sshmgr") {
		t.Fatalf("stale = %v, want only the missing path", got)
	}
	base := Report{ConfigInSync: true, Preflight: preflight.Report{RuntimeOK: true}}
	if !base.OK() {
		t.Fatal("the baseline report must pass, or the next check proves nothing")
	}
	base.StaleProxy = got
	if base.OK() {
		t.Error("a stale ProxyCommand must fail the verdict")
	}
	if !strings.Contains((Report{StaleProxy: got}).Format(), "sshmgr config render") {
		t.Error("the report must say how to fix it")
	}
}
