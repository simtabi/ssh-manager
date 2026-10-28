// Package web is the `sshmgr serve` command's localhost web UI.
//
// Server-rendered html/template pages over the same services the CLI and the
// TUI call, with a little vanilla JavaScript and Tabler's CSS, all embedded in
// the binary: the page makes no network request beyond this server. It never
// imports internal/cli, which holds the TUI and process-wide state a
// long-lived server cannot share (imports_test.go holds it to that).
//
// Reading takes no lock. A change takes it only while it is checked and made
// (see services/change), never while a person reads its preview, so a running
// server does not hold up a CLI command.
package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// Options configures a Server.
type Options struct {
	// Engine reads the sshmgr home. Required.
	Engine Engine

	// Token is the launch token printed in the URL. Required.
	Token string

	// AllowedHosts are the Host header values answered (see AllowedHosts).
	AllowedHosts []string

	// AllowRemote records that the bind is not loopback; it lets a TLS
	// reverse proxy's X-Forwarded-Proto mark the session cookie Secure.
	AllowRemote bool

	// ReadOnly registers no route that changes anything, and hides the forms.
	ReadOnly bool

	// Version and BindAddr are shown in the footer.
	Version  string
	BindAddr string

	// Retain is how many snapshots a snapshot restore keeps when it snapshots
	// first, as SSH_MANAGER_SNAPSHOT_RETAIN sets for the CLI. 0 means 10.
	Retain int

	// Now is the clock. Nil means time.Now.
	Now func() time.Time
}

// Server is the web UI.
type Server struct {
	opts     Options
	pages    *pageSet
	assets   *assetSet
	sessions sessions
	handler  http.Handler
}

// New builds a Server. It parses every template once, so a template error is
// a startup error rather than a 500 on first visit.
func New(opts Options) (*Server, error) {
	if opts.Engine == nil {
		return nil, errors.New("web: an Engine is required")
	}
	if opts.Token == "" {
		return nil, errors.New("web: a Token is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	assets, err := loadAssets()
	if err != nil {
		return nil, err
	}
	pages, err := parsePages(assets)
	if err != nil {
		return nil, err
	}
	s := &Server{opts: opts, pages: pages, assets: assets}
	s.handler = securityHeaders(s.hostCheck(s.auth(s.sameOrigin(s.routes()))))
	return s, nil
}

// Handler returns the full middleware chain and routes.
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) now() time.Time { return s.opts.Now() }

// Serve answers on ln until ctx is cancelled, then shuts down with a
// ten-second grace for requests in flight.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	if err := srv.Shutdown(shutdown); err != nil {
		return err
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type ctxKey int

const sessionKey ctxKey = 0

func withSession(ctx context.Context, s *session) context.Context {
	return context.WithValue(ctx, sessionKey, s)
}

func sessionFrom(ctx context.Context) *session {
	s, _ := ctx.Value(sessionKey).(*session)
	return s
}
