package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// SessionCookie is the cookie a valid token is exchanged for.
const SessionCookie = "sshmgr_session"

// csrfField is the form field, and csrfHeader the request header, that carry
// the per-session CSRF token on every state-changing request.
const (
	csrfField  = "csrf"
	csrfHeader = "X-CSRF-Token"
)

// maxSessions bounds the session table. A session is only created by
// presenting the launch token, so this is a ceiling on memory, not a defence.
const maxSessions = 64

// ContentSecurityPolicy is sent on every response. Everything is same-origin;
// nothing is inline. img-src allows data: because Tabler's CSS draws its
// checkboxes and selects with data: SVG URLs.
const ContentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// NewToken returns 32 random bytes, base64url-encoded.
func NewToken() string {
	b := make([]byte, 32)
	// Since Go 1.24 crypto/rand.Read never returns an error: it ends the
	// program itself if the system's generator fails, rather than hand back a
	// predictable token.
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

type session struct {
	csrf    string
	created time.Time
}

type sessions struct {
	mu   sync.Mutex
	byID map[string]*session
}

func (s *sessions) create(now time.Time) (id string, sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byID == nil {
		s.byID = map[string]*session{}
	}
	if len(s.byID) >= maxSessions {
		var oldest string
		for k, v := range s.byID {
			if oldest == "" || v.created.Before(s.byID[oldest].created) {
				oldest = k
			}
		}
		delete(s.byID, oldest)
	}
	id = NewToken()
	sess = &session{csrf: NewToken(), created: now}
	s.byID[id] = sess
	return id, sess
}

func (s *sessions) get(id string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byID[id]
}

func equal(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// securityHeaders sets the headers every response carries, error pages
// included, so they are set before anything else can answer.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// hostCheck refuses any Host header outside the allowed set.
func (s *Server) hostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			s.renderError(w, r, http.StatusMisdirectedRequest, "Unknown host",
				"This server only answers to the address it printed when it started.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) hostAllowed(host string) bool {
	for _, h := range s.opts.AllowedHosts {
		if strings.EqualFold(h, host) {
			return true
		}
	}
	return false
}

// auth admits a request carrying a valid session cookie, exchanges a valid
// ?token= for one, and refuses everything else. Static assets are exempt:
// they are the vendored public Tabler files and the 401 page uses them.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			next.ServeHTTP(w, r)
			return
		}
		if tok := r.URL.Query().Get("token"); tok != "" {
			if !equal(tok, s.opts.Token) || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
				s.renderUnauthorized(w, r)
				return
			}
			id, _ := s.sessions.create(s.now())
			http.SetCookie(w, &http.Cookie{
				Name: SessionCookie, Value: id, Path: "/",
				HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.secure(r),
			})
			// Strip the token from the address bar and the history.
			clean := *r.URL
			q := clean.Query()
			q.Del("token")
			clean.RawQuery = q.Encode()
			http.Redirect(w, r, clean.RequestURI(), http.StatusSeeOther)
			return
		}
		c, err := r.Cookie(SessionCookie)
		if err != nil {
			s.renderUnauthorized(w, r)
			return
		}
		sess := s.sessions.get(c.Value)
		if sess == nil {
			s.renderUnauthorized(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(withSession(r.Context(), sess)))
	})
}

func (s *Server) secure(r *http.Request) bool {
	return r.TLS != nil || (s.opts.AllowRemote && r.Header.Get("X-Forwarded-Proto") == "https")
}

// sameOrigin enforces, for every request that can change state, that it came
// from this server's own pages: an Origin matching an allowed host (or, when
// a browser omits Origin, Sec-Fetch-Site: same-origin), and the session's
// CSRF token. SameSite=Strict already stops most cross-site requests; this is
// the second and third lock on the same door.
func (s *Server) sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if !s.originAllowed(r) {
			s.renderError(w, r, http.StatusForbidden, "Cross-origin request refused",
				"Changes can only be made from this server's own pages.")
			return
		}
		sess := sessionFrom(r.Context())
		token := r.Header.Get(csrfHeader)
		if token == "" {
			token = r.PostFormValue(csrfField)
		}
		if sess == nil || !equal(token, sess.csrf) {
			s.renderError(w, r, http.StatusForbidden, "Missing or stale form token",
				"Reload the page and try again.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" {
		return origin == "" && r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return s.hostAllowed(u.Host) && strings.EqualFold(u.Host, r.Host)
}
