package hypervisor

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeCLIs puts stand-ins on PATH (and nothing else, so a real hypervisor on the machine is never
// called). Each maps a substring of the argument list to the output printed for it.
func fakeCLIs(t *testing.T, clis map[string]map[string]string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-ins are shell scripts")
	}
	dir := t.TempDir()
	for name, answers := range clis {
		var b strings.Builder
		b.WriteString("#!/bin/sh\nargs=\"$*\"\nprintf '%s\\n' \"$args\" >> \"" + filepath.Join(dir, name+".calls") + "\"\ncase \"$args\" in\n")
		for match, out := range answers {
			b.WriteString("  *\"" + match + "\"*) printf '%s' '" + strings.ReplaceAll(out, "'", `'\''`) + "'; exit 0 ;;\n")
		}
		b.WriteString("esac\necho \"unexpected: $args\" >&2\nexit 3\n")
		if err := os.WriteFile(filepath.Join(dir, name), []byte(b.String()), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	return dir
}

func calls(t *testing.T, dir, cli string) string {
	b, _ := os.ReadFile(filepath.Join(dir, cli+".calls"))
	return string(b)
}

const (
	prlJSON   = `[{"uuid":"{1}","status":"running","ip_configured":"10.211.55.5","name":"Ubuntu 24.04"},{"uuid":"{2}","status":"stopped","ip_configured":"-","name":"Win"}]`
	vmpalJSON = `{"vms":[{"activity":null,"guest":"windows","id":"9418298F-2162-4358-8509-716AADE904EB","internetAddress":"10.0.2.15","localAddress":"192.168.128.2","name":"Windows VM 1","state":"running"}]}`
	limaJSON  = `{"name":"default","status":"Running","sshLocalPort":60022}` + "\n" + `{"name":"old","status":"Stopped","sshLocalPort":0}` + "\n"
	utmList   = "UUID                                 Status   Name\n6D1A-AAAA                            started  Debian 12\n7E2B-BBBB                            stopped  Arch\n"
	podmanJS  = `[{"Name":"podman-machine-default","Running":true,"Port":53210}]`
	orbJSON   = `[{"name":"ubuntu","state":"running"}]`
	vmrunList = "Total running VMs: 1\n/Users/me/VMs/dev.vmwarevm/dev.vmx\n"
)

func TestDriversListAndResolve(t *testing.T) {
	dir := fakeCLIs(t, map[string]map[string]string{
		"prlctl":  {"list --all --full --json": prlJSON},
		"vmpal":   {"list --json": vmpalJSON},
		"limactl": {"list --json": limaJSON},
		"utmctl":  {"list": utmList, "ip-address Debian 12": "fe80::1\n192.168.64.7\n"},
		"podman":  {"machine list --format json": podmanJS},
		"orb":     {"list -f json": orbJSON},
		"vmrun":   {"getGuestIPAddress": "172.16.0.9\n", "list": vmrunList},
	})
	cases := []struct {
		hv, vm, want string
		vms          int
	}{
		{"parallels", "Ubuntu 24.04", "10.211.55.5:22", 2},
		{"vmpal", "Windows VM 1", "192.168.128.2:22", 1},
		{"vmpal", "9418298F-2162-4358-8509-716AADE904EB", "192.168.128.2:22", 1},
		{"lima", "default", "127.0.0.1:60022", 2},
		{"utm", "Debian 12", "192.168.64.7:22", 2},
		{"podman", "podman-machine-default", "127.0.0.1:53210", 1},
		{"vmware", "/Users/me/VMs/dev.vmwarevm/dev.vmx", "172.16.0.9:22", 1},
	}
	for _, c := range cases {
		d, err := For(c.hv)
		if err != nil {
			t.Fatal(err)
		}
		if !Available(d) {
			t.Fatalf("%s: stand-in not found", c.hv)
		}
		vms, err := d.List()
		if err != nil || len(vms) != c.vms {
			t.Errorf("%s List = %v, %v; want %d", c.hv, vms, err, c.vms)
		}
		ep, err := d.Address(c.vm)
		if err != nil || ep.HostPort() != c.want {
			t.Errorf("%s Address(%s) = %v, %v; want %s", c.hv, c.vm, ep, err, c.want)
		}
	}
	// The UTM name has a space; it must arrive as one argument after ip-address.
	if !strings.Contains(calls(t, dir, "utmctl"), "ip-address Debian 12") {
		t.Errorf("utmctl calls: %s", calls(t, dir, "utmctl"))
	}
}

func TestStoppedOrMissingVMsSayWhy(t *testing.T) {
	fakeCLIs(t, map[string]map[string]string{
		"prlctl":  {"list --all --full --json": prlJSON},
		"limactl": {"list --json": limaJSON},
	})
	for hv, vm := range map[string]string{"parallels": "Win", "lima": "old"} {
		d, _ := For(hv)
		if _, err := d.Address(vm); err == nil || !strings.Contains(err.Error(), "topped") {
			t.Errorf("%s/%s: %v", hv, vm, err)
		}
		if _, err := d.Address("nope"); err == nil || !strings.Contains(err.Error(), "no VM named") {
			t.Errorf("%s missing VM: %v", hv, err)
		}
	}
}

func TestOwnKeyHypervisorsDoNotHandOverAddresses(t *testing.T) {
	fakeCLIs(t, map[string]map[string]string{"orb": {"list -f json": orbJSON}})
	d, _ := For("orbstack")
	if vms, err := d.List(); err != nil || len(vms) != 1 || !vms[0].Running {
		t.Errorf("orb List = %v, %v", vms, err)
	}
	if _, err := d.Address("ubuntu"); !errors.Is(err, ErrOwnKeys) {
		t.Errorf("orbstack Address err = %v, want ErrOwnKeys", err)
	}
	pd, _ := For("podman")
	if _, err := pd.Exec("x", "true"); !errors.Is(err, ErrOwnKeys) {
		t.Errorf("podman Exec err = %v", err)
	}
	vw, _ := For("vmware")
	if _, err := vw.Exec("x", "true"); !errors.Is(err, ErrNotSupported) {
		t.Errorf("vmware Exec err = %v", err)
	}
}

func TestEveryDriverReportsNotInstalled(t *testing.T) {
	fakeCLIs(t, nil)
	if len(All()) != 7 {
		t.Fatalf("%d drivers, want 7", len(All()))
	}
	for _, d := range All() {
		// vmrun and utmctl also have fixed app paths; those exist only with the app installed.
		if Available(d) && d.Name() != "vmware" && d.Name() != "utm" {
			t.Errorf("%s found with an empty PATH", d.Name())
			continue
		}
		if Available(d) {
			continue
		}
		if _, err := d.List(); err == nil || !strings.Contains(err.Error(), "not installed") {
			t.Errorf("%s List with no CLI: %v", d.Name(), err)
		}
	}
	if _, err := For("virtualbox"); err == nil {
		t.Error("unknown hypervisor accepted")
	}
}

func TestExecPassesArgvThrough(t *testing.T) {
	dir := fakeCLIs(t, map[string]map[string]string{
		"vmpal":   {"exec": "ok"},
		"prlctl":  {"exec": "ok"},
		"limactl": {"shell": "ok"},
	})
	for hv, cli := range map[string]string{"vmpal": "vmpal", "parallels": "prlctl", "lima": "limactl"} {
		d, _ := For(hv)
		if _, err := d.Exec("box", "sh", "-c", "echo hi"); err != nil {
			t.Errorf("%s Exec: %v", hv, err)
		}
		if got := calls(t, dir, cli); !strings.Contains(got, "box") || !strings.Contains(got, "sh -c echo hi") {
			t.Errorf("%s calls: %s", hv, got)
		}
	}
}
