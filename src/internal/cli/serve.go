package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/simtabi/ssh-manager/src/v3/internal/platform"
	"github.com/simtabi/ssh-manager/src/v3/internal/version"
	"github.com/simtabi/ssh-manager/src/v3/internal/web"
)

// Seams for tests: the sandbox and CI cannot always bind a socket, and a test
// must not open a browser or wait for Ctrl-C.
var (
	serveListen  web.ListenFunc = net.Listen
	serveBrowser                = openBrowser
	serveContext                = func(parent context.Context) (context.Context, context.CancelFunc) {
		return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	}
)

func newServeCmd() *cobra.Command {
	var (
		addr        string
		port        int
		allowRemote bool
		allowHosts  []string
		readOnly    bool
		noOpen      bool
		tokenFile   string
	)
	cmd := &cobra.Command{
		Use:     "serve",
		Aliases: []string{"ui"},
		Short:   "Open the web UI on this machine",
		Long: "Open the web UI on this machine: an overview, the profiles, hosts and keys, the\n" +
			"snapshots, the operation history, and the doctor and audit reports.\n\n" +
			"Changes - adding, editing and deleting profiles, hosts and keys, and re-rendering\n" +
			"the config - are previewed first: the page shows exactly what each would write,\n" +
			"and confirming makes it only if nothing moved since. The lock is held only while\n" +
			"a change is checked and made, so a running server does not hold up a command.\n" +
			"--read-only serves no change at all.\n\n" +
			"Listens on 127.0.0.1, port " + strconv.Itoa(web.DefaultPort) + " by default. If that port is taken it takes the\n" +
			"next free one and prints the address it bound; --port pins a port and fails if it\n" +
			"is taken. The printed address carries a one-time token that signs the browser in;\n" +
			"without it every page answers 401.\n\n" +
			"A non-loopback --addr is refused unless --allow-remote is passed. Prefer an SSH\n" +
			"tunnel: ssh -L " + strconv.Itoa(web.DefaultPort) + ":127.0.0.1:" + strconv.Itoa(web.DefaultPort) + " <host>.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p, err := resolvePaths(c)
			if err != nil {
				return err
			}
			host, pinnedPort, hasPort, err := splitAddr(addr)
			if err != nil {
				return fmt.Errorf("--addr %q: %w", addr, err)
			}
			pinned := hasPort || c.Flags().Changed("port")
			if !hasPort {
				pinnedPort = port
			}
			if pinnedPort < 0 || pinnedPort > 65535 {
				return fmt.Errorf("--port %d: want 0-65535", pinnedPort)
			}
			if !web.IsLoopback(host) && !allowRemote {
				return fmt.Errorf("--addr %s is reachable from other machines; pass --allow-remote to mean it, "+
					"or tunnel instead: ssh -L %d:127.0.0.1:%d <host>", host, web.DefaultPort, web.DefaultPort)
			}

			ln, err := web.Listen(serveListen, host, pinnedPort, pinned, web.DefaultPortAttempts)
			if err != nil {
				return err
			}
			bound := ln.Addr().(*net.TCPAddr).Port

			token := web.NewToken()
			srv, err := web.New(web.Options{
				Engine:       web.AppEngine{P: p, Retain: snapshotRetain()},
				Token:        token,
				AllowedHosts: web.AllowedHosts(host, bound, allowHosts),
				AllowRemote:  allowRemote,
				ReadOnly:     readOnly,
				Version:      version.Version,
				BindAddr:     ln.Addr().String(),
			})
			if err != nil {
				_ = ln.Close()
				return err
			}

			url := fmt.Sprintf("http://%s/?token=%s", net.JoinHostPort(displayHost(host), strconv.Itoa(bound)), token)
			out := c.OutOrStdout()
			if bound != pinnedPort && pinnedPort != 0 {
				_, _ = fmt.Fprintf(out, "port %d is in use; listening on %d instead\n", pinnedPort, bound)
			}
			_, _ = fmt.Fprintf(out, "sshmgr web UI: %s\n", url)
			mode := "changes are previewed before they are made"
			if readOnly {
				mode = "read-only"
			}
			_, _ = fmt.Fprintf(out, "home %s (%s)\n", p.ConfigDir, mode)
			if allowRemote {
				_, _ = fmt.Fprintln(c.ErrOrStderr(), "warning: --allow-remote serves plain HTTP; put a TLS proxy in front, or use an SSH tunnel")
			}
			_, _ = fmt.Fprintln(out, "press Ctrl-C to stop")

			if tokenFile != "" {
				if err := writeTokenFile(tokenFile, url); err != nil {
					_ = ln.Close()
					return err
				}
			}
			if !noOpen && platform.StdinIsTerminal() {
				if err := serveBrowser(url); err != nil {
					_, _ = fmt.Fprintf(c.ErrOrStderr(), "could not open a browser (%s); open the address above yourself\n", err)
				}
			}

			ctx, stop := serveContext(c.Context())
			defer stop()
			return srv.Serve(ctx, ln)
		},
	}
	f := cmd.Flags()
	f.StringVar(&addr, "addr", "127.0.0.1", "address to listen on, host or host:port (a port here pins it, like --port)")
	f.IntVar(&port, "port", web.DefaultPort, "port to listen on; when not given and the default is taken, the next free port is used")
	f.BoolVar(&allowRemote, "allow-remote", false, "allow a non-loopback --addr (plain HTTP; prefer an SSH tunnel)")
	f.StringArrayVar(&allowHosts, "allow-host", nil, "extra Host header to accept with --allow-remote, e.g. a proxy's name (repeatable)")
	f.BoolVar(&readOnly, "read-only", false, "serve no route that changes anything, and show no form")
	f.BoolVar(&noOpen, "no-open", false, "do not open a browser")
	f.StringVar(&tokenFile, "token-file", "", "also write the sign-in address to this file, mode 0600, for scripts")
	return cmd
}

// splitAddr accepts "host" or "host:port".
func splitAddr(addr string) (host string, port int, hasPort bool, err error) {
	h, p, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		if addr == "" {
			return "", 0, false, errors.New("empty address")
		}
		return addr, 0, false, nil
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, false, fmt.Errorf("port %q is not a number", p)
	}
	return h, n, true, nil
}

// displayHost is the host to print: a wildcard bind is reachable here as
// 127.0.0.1, and that is one of the Host headers the server accepts.
func displayHost(host string) string {
	switch host {
	case "", "0.0.0.0", "::":
		return "127.0.0.1"
	}
	return host
}

// writeTokenFile writes the sign-in address owner-only: it is a credential
// for as long as the server runs.
func writeTokenFile(path, url string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, url); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// O_CREATE's mode is not applied to a file that already existed.
	return os.Chmod(path, 0o600)
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
