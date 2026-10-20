// Package hypervisor finds local VMs and their current SSH address through each hypervisor's own
// CLI, so a devbox's Host block need not carry an IP that changes on every boot.
package hypervisor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
)

// VM is one machine a hypervisor reports.
type VM struct {
	Name    string
	State   string
	Running bool
}

// Endpoint is where a VM's SSH server answers right now.
type Endpoint struct {
	Host string
	Port int
}

// ErrOwnKeys means the hypervisor runs its own SSH access and keys (OrbStack, Podman): sshmgr lists
// the machine and can point a Docker context at it, but does not take its keys over.
var ErrOwnKeys = errors.New("this hypervisor manages its own SSH access and keys")

// ErrNotSupported means the hypervisor's CLI cannot do this without more than sshmgr has (VMware
// runs guest commands only with guest credentials).
var ErrNotSupported = errors.New("not supported by this hypervisor's CLI")

// Driver is one hypervisor.
type Driver interface {
	Name() string
	// CLI is the command the driver runs, "" when it cannot be found.
	CLI() string
	List() ([]VM, error)
	Address(vm string) (Endpoint, error)
	Start(vm string) error
	// Exec runs argv inside the VM (for installing a key without SSH); ErrNotSupported or ErrOwnKeys
	// when the CLI cannot.
	Exec(vm string, argv ...string) ([]byte, error)
}

// For returns the driver for a manifest hypervisor name.
func For(name string) (Driver, error) {
	for _, d := range All() {
		if d.Name() == name {
			return d, nil
		}
	}
	return nil, fmt.Errorf("unknown hypervisor %q", name)
}

// All returns every driver, in the documented order.
func All() []Driver {
	return []Driver{parallels{}, vmpal{}, vmware{}, utm{}, lima{}, orbstack{}, podman{}}
}

// Available reports whether d's CLI was found.
func Available(d Driver) bool { return d.CLI() != "" }

func lookup(names ...string) string {
	for _, n := range names {
		if strings.ContainsRune(n, os.PathSeparator) {
			if fi, err := os.Stat(n); err == nil && !fi.IsDir() {
				return n
			}
			continue
		}
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

func run(cli string, timeout time.Duration, args ...string) ([]byte, error) {
	if cli == "" {
		return nil, errors.New("not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, cli, args...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return out, fmt.Errorf("%s %s: %s", cli, strings.Join(args, " "), strings.TrimSpace(string(ee.Stderr)))
		}
		return out, fmt.Errorf("%s %s: %w", cli, strings.Join(args, " "), err)
	}
	return out, nil
}

const quick, slow = 20 * time.Second, 6 * time.Minute

// --- Parallels Desktop -------------------------------------------------------------------------

type parallels struct{}

func (parallels) Name() string { return manifest.HypervisorParallels }
func (parallels) CLI() string  { return lookup("prlctl") }

type prlVM struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	IPConfigured string `json:"ip_configured"`
}

func (d parallels) list() ([]prlVM, error) {
	out, err := run(d.CLI(), quick, "list", "--all", "--full", "--json")
	if err != nil {
		return nil, err
	}
	var vms []prlVM
	return vms, json.Unmarshal(out, &vms)
}

func (d parallels) List() ([]VM, error) {
	raw, err := d.list()
	var vms []VM
	for _, v := range raw {
		vms = append(vms, VM{Name: v.Name, State: v.Status, Running: v.Status == "running"})
	}
	return vms, err
}

func (d parallels) Address(vm string) (Endpoint, error) {
	raw, err := d.list()
	if err != nil {
		return Endpoint{}, err
	}
	for _, v := range raw {
		if v.Name == vm {
			if v.Status != "running" {
				return Endpoint{}, fmt.Errorf("%s is %s", vm, v.Status)
			}
			if v.IPConfigured == "" || v.IPConfigured == "-" {
				return Endpoint{}, fmt.Errorf("%s reports no IP yet (Parallels Tools not running?)", vm)
			}
			return Endpoint{Host: v.IPConfigured, Port: 22}, nil
		}
	}
	return Endpoint{}, fmt.Errorf("no VM named %q", vm)
}

func (d parallels) Start(vm string) error { _, err := run(d.CLI(), slow, "start", vm); return err }
func (d parallels) Exec(vm string, argv ...string) ([]byte, error) {
	return run(d.CLI(), slow, append([]string{"exec", vm}, argv...)...)
}

// --- VMPal -------------------------------------------------------------------------------------

type vmpal struct{}

func (vmpal) Name() string { return manifest.HypervisorVMPal }
func (vmpal) CLI() string  { return lookup("vmpal") }

type vmpalVM struct {
	Name         string `json:"name"`
	ID           string `json:"id"`
	State        string `json:"state"`
	LocalAddress string `json:"localAddress"`
}

func (d vmpal) list() ([]vmpalVM, error) {
	out, err := run(d.CLI(), quick, "list", "--json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		VMs []vmpalVM `json:"vms"`
	}
	return doc.VMs, json.Unmarshal(out, &doc)
}

func (d vmpal) List() ([]VM, error) {
	raw, err := d.list()
	var vms []VM
	for _, v := range raw {
		vms = append(vms, VM{Name: v.Name, State: v.State, Running: v.State == "running"})
	}
	return vms, err
}

func (d vmpal) Address(vm string) (Endpoint, error) {
	raw, err := d.list()
	if err != nil {
		return Endpoint{}, err
	}
	for _, v := range raw {
		if v.Name == vm || v.ID == vm {
			if v.State != "running" {
				return Endpoint{}, fmt.Errorf("%s is %s", vm, v.State)
			}
			if v.LocalAddress == "" {
				return Endpoint{}, fmt.Errorf("%s reports no local address", vm)
			}
			return Endpoint{Host: v.LocalAddress, Port: 22}, nil
		}
	}
	return Endpoint{}, fmt.Errorf("no VM named %q", vm)
}

func (d vmpal) Start(vm string) error {
	_, err := run(d.CLI(), slow, "start", vm, "--wait")
	return err
}
func (d vmpal) Exec(vm string, argv ...string) ([]byte, error) {
	return run(d.CLI(), slow, append([]string{"exec", vm, "--"}, argv...)...)
}

// --- VMware Fusion / Workstation ---------------------------------------------------------------

type vmware struct{}

func (vmware) Name() string { return manifest.HypervisorVMware }
func (vmware) CLI() string {
	return lookup("vmrun", "/Applications/VMware Fusion.app/Contents/Library/vmrun")
}

// List reports running VMs only: vmrun knows nothing about a stopped .vmx it was not handed.
// A VM is named by the path of its .vmx file.
func (d vmware) List() ([]VM, error) {
	out, err := run(d.CLI(), quick, "list")
	if err != nil {
		return nil, err
	}
	var vms []VM
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); strings.HasSuffix(strings.ToLower(line), ".vmx") {
			vms = append(vms, VM{Name: line, State: "running", Running: true})
		}
	}
	return vms, nil
}

func (d vmware) Address(vm string) (Endpoint, error) {
	out, err := run(d.CLI(), slow, "getGuestIPAddress", vm, "-wait")
	if err != nil {
		return Endpoint{}, err
	}
	ip := strings.TrimSpace(string(out))
	if ip == "" || strings.HasPrefix(ip, "Error") {
		return Endpoint{}, fmt.Errorf("%s: no guest IP (%s)", vm, ip)
	}
	return Endpoint{Host: ip, Port: 22}, nil
}

func (d vmware) Start(vm string) error {
	_, err := run(d.CLI(), slow, "start", vm, "nogui")
	return err
}

// Exec: vmrun runs guest programs only with -gu/-gp guest credentials, which sshmgr does not hold.
func (vmware) Exec(string, ...string) ([]byte, error) { return nil, ErrNotSupported }

// --- UTM ---------------------------------------------------------------------------------------

type utm struct{}

func (utm) Name() string { return manifest.HypervisorUTM }
func (utm) CLI() string {
	return lookup("utmctl", "/Applications/UTM.app/Contents/MacOS/utmctl")
}

// List parses `utmctl list`: a header, then "UUID  Status  Name" with the name possibly spaced.
func (d utm) List() ([]VM, error) {
	out, err := run(d.CLI(), quick, "list")
	if err != nil {
		return nil, err
	}
	var vms []VM
	for i, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 3 {
			continue
		}
		vms = append(vms, VM{Name: strings.Join(f[2:], " "), State: f[1], Running: f[1] == "started"})
	}
	return vms, nil
}

func (d utm) Address(vm string) (Endpoint, error) {
	out, err := run(d.CLI(), quick, "ip-address", vm)
	if err != nil {
		return Endpoint{}, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		// The first IPv4 address; IPv6 link-local entries need a zone sshmgr cannot know.
		if ip := strings.TrimSpace(line); ip != "" && strings.Count(ip, ".") == 3 {
			return Endpoint{Host: ip, Port: 22}, nil
		}
	}
	return Endpoint{}, fmt.Errorf("%s: no IPv4 address (is the QEMU guest agent running?)", vm)
}

func (d utm) Start(vm string) error { _, err := run(d.CLI(), slow, "start", vm); return err }
func (d utm) Exec(vm string, argv ...string) ([]byte, error) {
	return run(d.CLI(), slow, append([]string{"exec", vm, "--cmd"}, argv...)...)
}

// --- Lima --------------------------------------------------------------------------------------

type lima struct{}

func (lima) Name() string { return manifest.HypervisorLima }
func (lima) CLI() string  { return lookup("limactl") }

type limaVM struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	SSHLocalPort int    `json:"sshLocalPort"`
}

// list parses `limactl list --json`, one JSON object per line.
func (d lima) list() ([]limaVM, error) {
	out, err := run(d.CLI(), quick, "list", "--json")
	if err != nil {
		return nil, err
	}
	var vms []limaVM
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var v limaVM
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			return nil, err
		}
		vms = append(vms, v)
	}
	return vms, nil
}

func (d lima) List() ([]VM, error) {
	raw, err := d.list()
	var vms []VM
	for _, v := range raw {
		vms = append(vms, VM{Name: v.Name, State: v.Status, Running: v.Status == "Running"})
	}
	return vms, err
}

// Address is Lima's forwarded port on loopback, not the guest IP.
func (d lima) Address(vm string) (Endpoint, error) {
	raw, err := d.list()
	if err != nil {
		return Endpoint{}, err
	}
	for _, v := range raw {
		if v.Name == vm {
			if v.Status != "Running" || v.SSHLocalPort == 0 {
				return Endpoint{}, fmt.Errorf("%s is %s", vm, v.Status)
			}
			return Endpoint{Host: "127.0.0.1", Port: v.SSHLocalPort}, nil
		}
	}
	return Endpoint{}, fmt.Errorf("no VM named %q", vm)
}

func (d lima) Start(vm string) error { _, err := run(d.CLI(), slow, "start", vm); return err }
func (d lima) Exec(vm string, argv ...string) ([]byte, error) {
	return run(d.CLI(), slow, append([]string{"shell", vm, "--"}, argv...)...)
}

// --- OrbStack and Podman: listed, and their own SSH --------------------------------------------

type orbstack struct{}

func (orbstack) Name() string { return manifest.HypervisorOrbStack }
func (orbstack) CLI() string  { return lookup("orb") }

func (d orbstack) List() ([]VM, error) {
	out, err := run(d.CLI(), quick, "list", "-f", "json")
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Name  string `json:"name"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}
	var vms []VM
	for _, v := range raw {
		vms = append(vms, VM{Name: v.Name, State: v.State, Running: v.State == "running"})
	}
	return vms, nil
}

// Address: OrbStack's own ssh config (`ssh <machine>@orb`) already reaches its machines.
func (orbstack) Address(string) (Endpoint, error)       { return Endpoint{}, ErrOwnKeys }
func (d orbstack) Start(vm string) error                { _, err := run(d.CLI(), slow, "start", vm); return err }
func (orbstack) Exec(string, ...string) ([]byte, error) { return nil, ErrOwnKeys }

type podman struct{}

func (podman) Name() string { return manifest.HypervisorPodman }
func (podman) CLI() string  { return lookup("podman") }

type podmanMachine struct {
	Name    string `json:"Name"`
	Running bool   `json:"Running"`
	Port    int    `json:"Port"`
}

func (d podman) list() ([]podmanMachine, error) {
	out, err := run(d.CLI(), quick, "machine", "list", "--format", "json")
	if err != nil {
		return nil, err
	}
	var ms []podmanMachine
	return ms, json.Unmarshal(out, &ms)
}

func (d podman) List() ([]VM, error) {
	raw, err := d.list()
	var vms []VM
	for _, m := range raw {
		state := "stopped"
		if m.Running {
			state = "running"
		}
		vms = append(vms, VM{Name: m.Name, State: state, Running: m.Running})
	}
	return vms, err
}

// Address is the machine's forwarded SSH port, for reference; podman itself connects with its own key.
func (d podman) Address(vm string) (Endpoint, error) {
	raw, err := d.list()
	if err != nil {
		return Endpoint{}, err
	}
	for _, m := range raw {
		if m.Name == vm {
			if !m.Running {
				return Endpoint{}, fmt.Errorf("%s is stopped", vm)
			}
			return Endpoint{Host: "127.0.0.1", Port: m.Port}, nil
		}
	}
	return Endpoint{}, fmt.Errorf("no machine named %q", vm)
}

func (d podman) Start(vm string) error {
	_, err := run(d.CLI(), slow, "machine", "start", vm)
	return err
}
func (podman) Exec(string, ...string) ([]byte, error) { return nil, ErrOwnKeys }

// HostPort renders an endpoint for ssh -W style use.
func (e Endpoint) HostPort() string { return e.Host + ":" + strconv.Itoa(e.Port) }
