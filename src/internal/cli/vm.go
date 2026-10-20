package cli

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/core/hypervisor"
	"github.com/simtabi/ssh-manager/src/v3/internal/core/manifest"
	"github.com/simtabi/ssh-manager/src/v3/internal/services/editor"
)

func newVMCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vm",
		Short: "Local VMs as SSH hosts: list them, add one, and connect through the hypervisor",
		Long: "A VM's IP changes, so a VM host renders ProxyCommand \"<sshmgr>\" vm proxy <alias>:\n" +
			"each connection asks the hypervisor for the VM's current address. Supported:\n" +
			strings.Join(manifest.Hypervisors, ", ") + ". OrbStack and Podman run their own SSH and keys;\n" +
			"they are listed, and get a Docker context, but sshmgr does not take their keys over.",
	}
	cmd.AddCommand(newVMListCmd(), newVMAddCmd(), newVMProxyCmd(), newVMDockerContextCmd())
	return cmd
}

func newVMListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every hypervisor's VMs, and which manifest host uses each",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			used := map[string]string{} // hypervisor/vm -> profile/alias
			if m, err := loadManifestFor(c); err == nil {
				for _, name := range m.ProfileNames() {
					for _, h := range m.Profiles[name].Hosts {
						if h.VM != nil {
							used[h.VM.Hypervisor+"/"+h.VM.Name] = name + "/" + h.Alias
						}
					}
				}
			}
			out := c.OutOrStdout()
			for _, d := range hypervisor.All() {
				if !hypervisor.Available(d) {
					_, _ = fmt.Fprintf(out, "%-10s not installed\n", d.Name())
					continue
				}
				vms, err := d.List()
				if err != nil {
					_, _ = fmt.Fprintf(out, "%-10s error: %v\n", d.Name(), err)
					continue
				}
				if len(vms) == 0 {
					_, _ = fmt.Fprintf(out, "%-10s no VMs\n", d.Name())
				}
				for _, v := range vms {
					host := used[d.Name()+"/"+v.Name]
					if host != "" {
						host = "  host " + host
					}
					_, _ = fmt.Fprintf(out, "%-10s %-30s %s%s\n", d.Name(), v.Name, v.State, host)
				}
			}
			return nil
		},
	}
}

func newVMAddCmd() *cobra.Command {
	var hv, vmName, user, keyName string
	c := &cobra.Command{
		Use:   "add <profile> <alias>",
		Short: "Add a VM as a host: its address comes from the hypervisor at connect time",
		Args:  cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			if hv == manifest.HypervisorOrbStack || hv == manifest.HypervisorPodman {
				return fmt.Errorf("%s manages its own SSH access and keys; use `sshmgr vm docker-context` instead of a host", hv)
			}
			p, err := resolvePaths(c)
			if err != nil {
				return err
			}
			// HostName is the alias: ProxyCommand ignores it, and a real address would only go stale.
			alias := args[1]
			f := editor.HostFields{
				Hostname: &alias, User: &user,
				KeyName: strPtrIf(c, "key-name", keyName),
				VM:      &manifest.VMSpec{Hypervisor: hv, Name: vmName},
			}
			snapshotBeforeMutation(p)
			if err := editor.New(p).AddHost(args[0], alias, f); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(c.OutOrStdout(), "added VM host %s to %s (%s %q); run `sshmgr reconcile` to mint its key, "+
				"then install the public key in the guest\n", alias, args[0], hv, vmName)
			return applyManifestEdit(c, p)
		},
	}
	c.Flags().StringVar(&hv, "hypervisor", "", strings.Join(manifest.Hypervisors, ", "))
	c.Flags().StringVar(&vmName, "vm", "", "the VM's name as the hypervisor lists it (`sshmgr vm list`)")
	c.Flags().StringVarP(&user, "user", "u", "", "guest user")
	c.Flags().StringVar(&keyName, "key-name", "", "use this key instead of the derived <profile>_<alias>-<algo> name")
	_ = c.MarkFlagRequired("hypervisor")
	_ = c.MarkFlagRequired("vm")
	_ = c.MarkFlagRequired("user")
	return c
}

// vmHost finds the manifest host alias with a vm spec.
func vmHost(m *manifest.Manifest, alias string) (manifest.Host, error) {
	for _, name := range m.ProfileNames() {
		for _, h := range m.Profiles[name].Hosts {
			if h.Alias == alias {
				if h.VM == nil {
					return h, fmt.Errorf("%s is not a VM host", alias)
				}
				return h, nil
			}
		}
	}
	return manifest.Host{}, fmt.Errorf("no host %q", alias)
}

// startWait bounds how long `vm proxy` waits for a VM it had to start.
var startWait = 3 * time.Minute

func newVMProxyCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "proxy <alias>",
		Short:  "ProxyCommand for a VM host: resolve its address now, start it if stopped, relay stdio",
		Args:   cobra.ExactArgs(1),
		Hidden: true, // ssh runs it; nobody types it
		RunE: func(c *cobra.Command, args []string) error {
			m, err := loadManifestFor(c)
			if err != nil {
				return err
			}
			h, err := vmHost(m, args[0])
			if err != nil {
				return err
			}
			d, err := hypervisor.For(h.VM.Hypervisor)
			if err != nil {
				return err
			}
			if !hypervisor.Available(d) {
				return fmt.Errorf("%s: %s is not installed", args[0], d.Name())
			}
			ep, err := d.Address(h.VM.Name)
			if err != nil && !errors.Is(err, hypervisor.ErrOwnKeys) {
				// Stopped: start it and wait for an address. ssh shows this on stderr.
				_, _ = fmt.Fprintf(c.ErrOrStderr(), "sshmgr: %v; starting %s %q\n", err, d.Name(), h.VM.Name)
				if serr := d.Start(h.VM.Name); serr != nil {
					return fmt.Errorf("start %q: %w", h.VM.Name, serr)
				}
				deadline := time.Now().Add(startWait)
				for ep, err = d.Address(h.VM.Name); err != nil && time.Now().Before(deadline); ep, err = d.Address(h.VM.Name) {
					time.Sleep(2 * time.Second)
				}
			}
			if err != nil {
				return err
			}
			port := ep.Port
			if h.Port != 0 && h.Port != 22 {
				port = h.Port // an explicit port in the manifest wins over the hypervisor's default 22
			}
			return relay(net.JoinHostPort(ep.Host, fmt.Sprint(port)), c.InOrStdin(), c.OutOrStdout())
		},
	}
}

// relay connects to addr and copies stdin to it and it to stdout until either side closes.
func relay(addr string, in io.Reader, out io.Writer) error {
	conn, err := net.DialTimeout("tcp", addr, 20*time.Second)
	if err != nil {
		return err
	}
	return relayConn(conn, in, out)
}

// relayConn is relay over an open connection, split out so it can be tested without a listener.
func relayConn(conn net.Conn, in io.Reader, out io.Writer) error {
	defer func() { _ = conn.Close() }()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, in)
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite() // tell the server we are done sending; keep reading its reply
		}
	}()
	_, err := io.Copy(out, conn)
	if f, ok := in.(*os.File); ok && f == os.Stdin {
		return err // stdin may never close; returning ends the process
	}
	wg.Wait()
	return err
}

func newVMDockerContextCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "docker-context <alias>",
		Short: "Create or update a Docker context ssh://<alias> for a VM host",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			m, err := loadManifestFor(c)
			if err != nil {
				return err
			}
			h, err := vmHost(m, args[0])
			if err != nil {
				return err
			}
			if _, err := exec.LookPath("docker"); err != nil {
				return fmt.Errorf("docker CLI not found")
			}
			endpoint := "host=ssh://" + h.Alias
			verb := "create"
			if exec.Command("docker", "context", "inspect", h.Alias).Run() == nil {
				verb = "update"
			}
			out, err := exec.Command("docker", "context", verb, h.Alias, "--docker", endpoint).CombinedOutput()
			if err != nil {
				return fmt.Errorf("docker context %s: %v: %s", verb, err, strings.TrimSpace(string(out)))
			}
			_, _ = fmt.Fprintf(c.OutOrStdout(), "docker context %s %s -> ssh://%s (use: docker --context %s ps)\n",
				verb+"d", h.Alias, h.Alias, h.Alias)
			return nil
		},
	}
}
