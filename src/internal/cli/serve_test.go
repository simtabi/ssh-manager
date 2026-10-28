package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/simtabi/ssh-manager/src/v3/internal/services/mutation"
)

// blockingListener stands in for a bound socket: Accept blocks until Close,
// so http.Server.Serve runs and Shutdown ends it, with no port bound. The
// sandbox these tests are written in cannot bind one.
type blockingListener struct {
	addr   *net.TCPAddr
	once   sync.Once
	closed chan struct{}
}

func (l *blockingListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *blockingListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *blockingListener) Addr() net.Addr { return l.addr }

// fakeServe refuses the taken ports with EADDRINUSE, "binds" the rest, opens no
// browser, and hands back a cancel that stands in for Ctrl-C.
func fakeServe(t *testing.T, taken ...int) (*[]string, context.CancelFunc) {
	t.Helper()
	var tried []string
	busy := map[int]bool{}
	for _, p := range taken {
		busy[p] = true
	}
	ctx, cancel := context.WithCancel(context.Background())
	prevListen, prevBrowser, prevCtx := serveListen, serveBrowser, serveContext
	serveListen = func(_, address string) (net.Listener, error) {
		tried = append(tried, address)
		host, port, _ := net.SplitHostPort(address)
		var p int
		_, _ = fmt.Sscan(port, &p)
		if busy[p] {
			return nil, &net.OpError{Op: "listen", Net: "tcp", Err: &os.SyscallError{Syscall: "bind", Err: syscall.EADDRINUSE}}
		}
		return &blockingListener{addr: &net.TCPAddr{IP: net.ParseIP(host), Port: p}, closed: make(chan struct{})}, nil
	}
	serveBrowser = func(string) error { return errors.New("no browser in tests") }
	serveContext = func(context.Context) (context.Context, context.CancelFunc) { return ctx, cancel }
	t.Cleanup(func() { serveListen, serveBrowser, serveContext = prevListen, prevBrowser, prevCtx; cancel() })
	return &tried, cancel
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// runServe runs serve until it says it is listening, then stops it.
func runServe(t *testing.T, stop context.CancelFunc, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd()
	var out syncBuffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"serve", "--no-open"}, args...))
	done := make(chan error, 1)
	go func() { done <- root.Execute() }()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case err := <-done:
			return out.String(), err
		case <-deadline:
			stop()
			t.Fatal("serve neither printed an address nor exited")
		case <-time.After(10 * time.Millisecond):
			if strings.Contains(out.String(), "press Ctrl-C to stop") {
				stop()
				select {
				case err := <-done:
					return out.String(), err
				case <-time.After(15 * time.Second):
					t.Fatal("serve did not stop when its context was cancelled")
				}
			}
		}
	}
}

var printedURL = regexp.MustCompile(`http://127\.0\.0\.1:(\d+)/\?token=[A-Za-z0-9_-]{43}`)

func TestServeTakesTheNextFreePortAndSaysSo(t *testing.T) {
	editHome(t)
	tried, stop := fakeServe(t, 7822)
	out, err := runServe(t, stop)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	m := printedURL.FindStringSubmatch(out)
	if m == nil || m[1] != "7823" {
		t.Fatalf("printed address is not the bound one:\n%s", out)
	}
	if !strings.Contains(out, "port 7822 is in use; listening on 7823 instead") || !strings.Contains(out, "read-only") {
		t.Errorf("the fallback or the read-only note was not announced:\n%s", out)
	}
	if strings.Join(*tried, " ") != "127.0.0.1:7822 127.0.0.1:7823" {
		t.Errorf("tried %v", *tried)
	}
}

func TestServePinnedPortFailsLoudly(t *testing.T) {
	editHome(t)
	tried, stop := fakeServe(t, 9000)
	out, err := runServe(t, stop, "--port", "9000")
	if err == nil || !strings.Contains(err.Error(), "port 9000 is already in use") {
		t.Fatalf("err %v:\n%s", err, out)
	}
	if len(*tried) != 1 {
		t.Errorf("a pinned port fell back: %v", *tried)
	}
}

func TestServeRefusesARemoteBindWithoutAllowRemote(t *testing.T) {
	editHome(t)
	tried, stop := fakeServe(t)
	_, err := runServe(t, stop, "--addr", "0.0.0.0")
	if err == nil || !strings.Contains(err.Error(), "ssh -L 7822:127.0.0.1:7822") {
		t.Fatalf("err %v", err)
	}
	if len(*tried) != 0 {
		t.Errorf("listened before refusing: %v", *tried)
	}
	out, err := runServe(t, stop, "--addr", "0.0.0.0", "--allow-remote")
	if err != nil || !strings.Contains(out, "plain HTTP") {
		t.Fatalf("--allow-remote: %v\n%s", err, out)
	}
}

func TestServeWritesTheTokenFilePrivately(t *testing.T) {
	editHome(t)
	_, stop := fakeServe(t)
	path := filepath.Join(t.TempDir(), "state", "serve.url")
	if out, err := runServe(t, stop, "--token-file", path); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !printedURL.Match(body) {
		t.Errorf("token file holds %q", body)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Errorf("token file mode %v", info.Mode().Perm())
		}
	}
}

// A running server takes no lock, so it never holds up a CLI command.
func TestServeDoesNotTakeTheLock(t *testing.T) {
	editHome(t)
	_, stop := fakeServe(t)
	if out, err := runServe(t, stop); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if lockHeld() {
		t.Error("serve took the advisory lock")
	}
}

func TestSplitAddr(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.1": "127.0.0.1 0 false", "127.0.0.1:9000": "127.0.0.1 9000 true",
		"[::1]:80": "::1 80 true", "localhost": "localhost 0 false",
	} {
		h, p, has, err := splitAddr(in)
		if err != nil || fmt.Sprintf("%s %d %v", h, p, has) != want {
			t.Errorf("splitAddr(%q) = %s %d %v %v", in, h, p, has, err)
		}
	}
	if _, _, _, err := splitAddr("127.0.0.1:http"); err == nil {
		t.Error("a non-numeric port was accepted")
	}
}

func lockHeld() bool { return mutation.Held() }
