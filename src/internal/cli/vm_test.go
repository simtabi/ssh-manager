package cli

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// stubBin writes an executable shell stand-in into dir.
func stubBin(t *testing.T, dir, name, script string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-ins are shell scripts")
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestVMAddRendersTheProxyCommandAndRefusesOwnKeyHypervisors(t *testing.T) {
	p := editHome(t)
	run(t, "profile", "add", "devbox")
	run(t, "vm", "add", "devbox", "devbox", "--hypervisor", "vmpal", "--vm", "Ubuntu 24.04", "-u", "imani")
	cfg, err := os.ReadFile(filepath.Join(p.SSHDir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), "Host devbox\n") || !strings.Contains(string(cfg), " vm proxy devbox\n") {
		t.Errorf("rendered config lacks the VM host's ProxyCommand:\n%s", cfg)
	}
	if _, err := runErr(t, "vm", "add", "devbox", "orb", "--hypervisor", "orbstack", "--vm", "ubuntu", "-u", "me"); err == nil ||
		!strings.Contains(err.Error(), "own SSH") {
		t.Errorf("orbstack host: %v", err)
	}
	if _, err := runErr(t, "vm", "add", "devbox", "vb", "--hypervisor", "virtualbox", "--vm", "x", "-u", "me"); err == nil {
		t.Error("an unknown hypervisor was accepted")
	}
}

func TestVMListShowsHostsAndMissingHypervisors(t *testing.T) {
	editHome(t)
	run(t, "profile", "add", "devbox")
	run(t, "vm", "add", "devbox", "devbox", "--hypervisor", "vmpal", "--vm", "Ubuntu 24.04", "-u", "imani")
	bin := t.TempDir()
	stubBin(t, bin, "vmpal", `printf '%s' '{"vms":[{"name":"Ubuntu 24.04","id":"A","state":"stopped","localAddress":""}]}'`)
	t.Setenv("PATH", bin)
	out := run(t, "vm", "list")
	if !strings.Contains(out, "vmpal") || !strings.Contains(out, "Ubuntu 24.04") || !strings.Contains(out, "host devbox/devbox") {
		t.Errorf("vm list:\n%s", out)
	}
	if !strings.Contains(out, "lima       not installed") {
		t.Errorf("a missing hypervisor must say so:\n%s", out)
	}
}

// vm proxy starts a stopped VM, waits for its address, and relays bytes. It needs a local listener,
// which some sandboxes forbid; it skips there and runs in CI.
func TestVMProxyStartsAStoppedVMAndRelays(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen locally here: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(c, c) // echo
		_ = c.Close()
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	editHome(t)
	run(t, "profile", "add", "devbox")
	run(t, "vm", "add", "devbox", "devbox", "--hypervisor", "vmpal", "--vm", "box", "-u", "imani")
	// Pin the port in the manifest so the relay reaches the test listener, not 22.
	run(t, "host", "edit", "devbox", "devbox", "-p", strconv.Itoa(port))

	bin := t.TempDir()
	started := filepath.Join(bin, "started")
	stubBin(t, bin, "vmpal", `case "$1" in
  start) : > "`+started+`" ;;
  list) if [ -f "`+started+`" ]; then
          printf '%s' '{"vms":[{"name":"box","id":"B","state":"running","localAddress":"127.0.0.1"}]}'
        else
          printf '%s' '{"vms":[{"name":"box","id":"B","state":"stopped","localAddress":""}]}'
        fi ;;
esac`)
	t.Setenv("PATH", bin)
	old := startWait
	startWait = 10 * time.Second
	defer func() { startWait = old }()

	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetIn(strings.NewReader("ping"))
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs([]string{"vm", "proxy", "devbox"})
	if err := root.Execute(); err != nil {
		t.Fatalf("vm proxy: %v\n%s", err, errOut.String())
	}
	if out.String() != "ping" {
		t.Errorf("relayed %q, want ping", out.String())
	}
	if _, err := os.Stat(started); err != nil || !strings.Contains(errOut.String(), "starting vmpal") {
		t.Errorf("the stopped VM was not started (stderr %q)", errOut.String())
	}
}

func TestVMDockerContextCreatesThenUpdates(t *testing.T) {
	editHome(t)
	run(t, "profile", "add", "devbox")
	run(t, "vm", "add", "devbox", "devbox", "--hypervisor", "lima", "--vm", "default", "-u", "imani")
	bin := t.TempDir()
	log := filepath.Join(bin, "docker.log")
	exists := filepath.Join(bin, "exists")
	stubBin(t, bin, "docker", `printf '%s\n' "$*" >> "`+log+`"
case "$2" in
  inspect) [ -f "`+exists+`" ] ;;
  create) : > "`+exists+`" ;;
esac`)
	t.Setenv("PATH", bin)
	if out := run(t, "vm", "docker-context", "devbox"); !strings.Contains(out, "created devbox -> ssh://devbox") {
		t.Errorf("first run: %s", out)
	}
	if out := run(t, "vm", "docker-context", "devbox"); !strings.Contains(out, "updated devbox") {
		t.Errorf("second run: %s", out)
	}
	b, _ := os.ReadFile(log)
	if !strings.Contains(string(b), "context create devbox --docker host=ssh://devbox") {
		t.Errorf("docker calls:\n%s", b)
	}
	if _, err := runErr(t, "vm", "docker-context", "nope"); err == nil {
		t.Error("an unknown alias was accepted")
	}
}

// The relay itself, over an in-memory pipe: what goes in reaches the far side, and what the far side
// sends comes out, with no listener needed.
func TestRelayConnCopiesBothWays(t *testing.T) {
	near, far := net.Pipe()
	go func() {
		buf := make([]byte, 4)
		if _, err := io.ReadFull(far, buf); err == nil {
			_, _ = far.Write([]byte(strings.ToUpper(string(buf))))
		}
		_ = far.Close()
	}()
	var out bytes.Buffer
	if err := relayConn(near, strings.NewReader("ping"), &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "PING" {
		t.Errorf("relayed %q, want PING", out.String())
	}
}
