// Package api is the admin HTTP API: first-run setup, sign-in with
// mandatory MFA, users and roles, API tokens, settings and the audit log.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/prezmc/dnserv/internal/analytics"
	"github.com/prezmc/dnserv/internal/auth"
	"github.com/prezmc/dnserv/internal/backup"
	"github.com/prezmc/dnserv/internal/cluster"
	"github.com/prezmc/dnserv/internal/config"
	"github.com/prezmc/dnserv/internal/filter"
	"github.com/prezmc/dnserv/internal/querylog"
	"github.com/prezmc/dnserv/internal/store"
	"github.com/prezmc/dnserv/internal/threat"
	"github.com/prezmc/dnserv/internal/virustotal"
)

// CookieName is the session cookie.
const CookieName = "dnserv_session"

// Issuer names the node in authenticator apps.
const Issuer = "DNServ"

// API serves /api/v1.
type API struct {
	Store    *store.Store
	Sessions *auth.Sessions
	Throttle *auth.Throttle
	// Base is the configuration before UI settings: file, environment and
	// defaults. Effective config = Store settings overlaid on Base.
	Base config.Config
	// Status returns the node's live status for the dashboard.
	Status func() any
	// AllowedOrigins are extra host[:port] values allowed to make changes,
	// for reverse proxies that rewrite Host.
	AllowedOrigins []string
	Log            *slog.Logger
	// QueryLog holds recent queries (nil disables the queries and devices
	// views).
	QueryLog *querylog.Log
	// CheckDomain explains how the filter treats a name.
	CheckDomain func(name string) filter.Match
	// AlsoOn lists every enabled list with a rule for a name, from the
	// saved list files (nil: unavailable).
	AlsoOn func(ctx context.Context, name string) []filter.ListHit
	// UpdateLists re-downloads every list now (runs in the background).
	UpdateLists func()
	// CacheFill says how full the answer cache is on this node and every
	// other one.
	CacheFill func(ctx context.Context) []CacheFill
	// ClearCache empties the answer cache on this node and every other
	// server, and reports what each one cleared.
	ClearCache func(ctx context.Context) []CacheCleared
	// ClearHistory deletes performance stats ("performance") or all query
	// history ("history") on this node and every other server.
	ClearHistory func(ctx context.Context, what string) []HistoryCleared
	// HTTPSStatus reports dashboard HTTPS on this node and the others
	// (nil: none, as in tests).
	HTTPSStatus func(ctx context.Context) []NodeHTTPS
	// LookupName asks the router for a device's name ("" if unknown).
	LookupName func(ctx context.Context, a netip.Addr) string

	// Cluster is this node's cluster membership (nil: not clustered, as
	// in tests).
	Cluster *cluster.Cluster
	// Analytics is this node's long-term query history (nil: analytics
	// views show only other nodes, or nothing).
	Analytics *analytics.Store
	// Intel scores domains for risk and names their type (nil: off).
	Intel *threat.Intel
	// VirusTotal looks up domains on request with the owner's key (nil:
	// unavailable).
	VirusTotal *virustotal.Client
	// Backups makes and stores this node's backups (nil: downloads and
	// stored backups are unavailable, as in tests).
	Backups *backup.Manager
	// smbDial is used to reach network shares (nil: a plain dialer; tests
	// set it).
	smbDial func(ctx context.Context, network, addr string) (net.Conn, error)

	names      namesCache
	passkeyCer ceremonies
	imp        imports

	// mfaSteps guards against reuse of authenticator codes when the
	// cluster can't record them (no leader). Per node, in memory.
	mfaMu    sync.Mutex
	mfaSteps map[string]int64

	now       func() time.Time
	setupOnce sync.Mutex
	setupCode string
}

// New creates the API. When there are no users yet it generates a one-time
// setup code and logs it, so only someone who can read the container's
// logs can claim the node.
func New(st *store.Store, sess *auth.Sessions, base config.Config, log *slog.Logger) *API {
	a := &API{Store: st, Sessions: sess, Throttle: auth.NewThrottle(), Base: base, Log: log, now: time.Now}
	if len(st.State().Users) == 0 {
		a.setupCode = auth.NewSetupCode()
		log.Warn("first-run setup: open the dashboard and enter this setup code", "setup_code", a.setupCode)
		fmt.Fprintf(os.Stderr, "\n"+
			"  +--------------------------------------------------+\n"+
			"  |  DNServ first-run setup                         |\n"+
			"  |                                                  |\n"+
			"  |  Open http://<this server>:8080 in a browser     |\n"+
			"  |  and enter this setup code:   %-19s|\n"+
			"  +--------------------------------------------------+\n\n", a.setupCode)
	}
	return a
}

// SetupCode returns the pending setup code, like "K7M2-9XQ4" ("" once an
// admin exists).
func (a *API) SetupCode() string {
	a.setupOnce.Lock()
	defer a.setupOnce.Unlock()
	return a.setupCode
}

// Effective returns the configuration in force.
func (a *API) Effective() config.Config { return a.Store.State().Settings.Overlay(a.Base) }

// Handler returns the API routes.
func (a *API) Handler() http.Handler {
	m := http.NewServeMux()
	// Setup and sign-in.
	m.HandleFunc("GET /api/v1/setup", a.getSetup)
	m.HandleFunc("POST /api/v1/setup", a.postSetup)
	m.HandleFunc("POST /api/v1/setup/check", a.checkSetupCode)
	m.HandleFunc("POST /api/v1/auth/login", a.login)
	m.HandleFunc("POST /api/v1/auth/mfa", a.stage(auth.StageMFA, a.mfa))
	m.HandleFunc("POST /api/v1/auth/totp/begin", a.stage(auth.StageEnroll, a.totpBegin))
	m.HandleFunc("POST /api/v1/auth/totp/confirm", a.stage(auth.StageEnroll, a.totpConfirm))
	m.HandleFunc("POST /api/v1/auth/logout", a.logout)
	m.HandleFunc("GET /api/v1/auth/me", a.me)
	m.HandleFunc("POST /api/v1/auth/password", a.authed("", a.changePassword))
	m.HandleFunc("PUT /api/v1/auth/dashboard", a.authed("", a.setDashboard))
	m.HandleFunc("GET /api/v1/auth/sessions", a.authed("", a.mySessions))
	m.HandleFunc("DELETE /api/v1/auth/sessions/{id}", a.authed("", a.revokeMySession))
	m.HandleFunc("POST /api/v1/auth/recovery-codes", a.authed("", a.newRecoveryCodes))
	m.HandleFunc("POST /api/v1/auth/authenticator/begin", a.authed("", a.replaceTOTPBegin))
	m.HandleFunc("POST /api/v1/auth/authenticator/confirm", a.authed("", a.replaceTOTPConfirm))
	a.passkeyRoutes(m)

	// Users (admin).
	m.HandleFunc("GET /api/v1/users", a.authed(store.PermUsers, a.listUsers))
	m.HandleFunc("POST /api/v1/users", a.authed(store.PermUsers, a.createUser))
	m.HandleFunc("PATCH /api/v1/users/{id}", a.authed(store.PermUsers, a.updateUser))
	m.HandleFunc("DELETE /api/v1/users/{id}", a.authed(store.PermUsers, a.deleteUser))
	m.HandleFunc("POST /api/v1/users/{id}/password", a.authed(store.PermUsers, a.setUserPassword))
	m.HandleFunc("POST /api/v1/users/{id}/reset-mfa", a.authed(store.PermUsers, a.resetMFA))
	m.HandleFunc("GET /api/v1/sessions", a.authed(store.PermUsers, a.allSessions))
	m.HandleFunc("DELETE /api/v1/sessions/{id}", a.authed(store.PermUsers, a.revokeAnySession))

	// API tokens.
	m.HandleFunc("GET /api/v1/tokens", a.authed("", a.listTokens))
	m.HandleFunc("POST /api/v1/tokens", a.authed("", a.createToken))
	m.HandleFunc("DELETE /api/v1/tokens/{id}", a.authed("", a.revokeToken))

	// Settings.
	m.HandleFunc("GET /api/v1/settings", a.authed(store.PermDashboard, a.getSettings))
	m.HandleFunc("PATCH /api/v1/settings", a.authed("", a.patchSettings))
	m.HandleFunc("POST /api/v1/settings/reset", a.authed("", a.resetSettings))
	m.HandleFunc("POST /api/v1/domains", a.authed(store.PermAllowBlock, a.domainAction))
	m.HandleFunc("POST /api/v1/lists/update", a.authed(store.PermLists, a.updateLists))
	m.HandleFunc("POST /api/v1/cache/clear", a.authed(store.PermLists, a.clearCache))
	m.HandleFunc("POST /api/v1/analytics/clear", a.authed(store.PermUsers, a.clearHistory))
	a.routesHTTPS(m)
	m.HandleFunc("GET /api/v1/domains/check", a.authed(store.PermDashboard, a.checkDomain))

	// Devices and recent queries.
	m.HandleFunc("GET /api/v1/devices", a.authed(store.PermDashboard, a.listDevices))
	m.HandleFunc("POST /api/v1/devices", a.authed(store.PermDevices, a.saveDevice))
	m.HandleFunc("PUT /api/v1/devices/{id}", a.authed(store.PermDevices, a.saveDevice))
	m.HandleFunc("DELETE /api/v1/devices/{id}", a.authed(store.PermDevices, a.deleteDevice))
	m.HandleFunc("GET /api/v1/queries", a.authed(store.PermQueryLog, a.queries))
	m.HandleFunc("GET /api/v1/groups", a.authed(store.PermDashboard, a.listGroups))
	m.HandleFunc("GET /api/v1/services", a.authed(store.PermDashboard, func(w http.ResponseWriter, r *http.Request, p *Principal) {
		writeJSON(w, http.StatusOK, map[string]any{"services": filter.Services})
	}))
	m.HandleFunc("POST /api/v1/groups", a.authed(store.PermDevices, a.saveGroup))
	m.HandleFunc("PUT /api/v1/groups/{id}", a.authed(store.PermDevices, a.saveGroup))
	m.HandleFunc("DELETE /api/v1/groups/{id}", a.authed(store.PermDevices, a.deleteGroup))

	// Cluster.
	a.clusterRoutes(m)
	a.backupRoutes(m)
	a.analyticsRoutes(m)
	a.importRoutes(m)

	// Status and audit.
	a.pauseRoutes(m)
	m.HandleFunc("GET /api/v1/status", a.authed(store.PermDashboard, a.status))
	m.HandleFunc("GET /api/v1/audit", a.authed(store.PermAudit, a.audit))

	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { writeErr(w, http.StatusNotFound, "no such endpoint") })
	return secureHeaders(m)
}

// --- principals and middleware ---

// Principal is who is making a request.
type Principal struct {
	User    *store.User
	Session *auth.Session // nil for API tokens
	Token   *store.Token  // nil for browser sessions
}

// Can reports whether the principal holds perm. A token is limited to both
// its own permissions and its owner's current ones.
func (p *Principal) Can(perm string) bool {
	if p == nil || !p.User.Has(perm) {
		return false
	}
	if p.Token != nil {
		return store.HasPerm(p.Token.Perms, perm)
	}
	return true
}

// Actor is the name recorded in the audit log.
func (p *Principal) Actor() string {
	if p.Token != nil {
		return p.User.Username + " (token " + p.Token.Name + ")"
	}
	return p.User.Username
}

type handler func(w http.ResponseWriter, r *http.Request, p *Principal)

// authed requires a fully signed-in session or a valid API token, CSRF
// protection for browser writes, and perm (unless empty).
func (a *API) authed(perm string, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, status, msg := a.principal(r)
		if p == nil {
			writeErr(w, status, msg)
			return
		}
		if perm != "" && !p.Can(perm) {
			writeErr(w, http.StatusForbidden, "you don't have permission for this")
			return
		}
		h(w, r, p)
	}
}

func (a *API) principal(r *http.Request) (*Principal, int, string) {
	st := a.Store.State()
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		t, u := a.checkToken(st, strings.TrimPrefix(h, "Bearer "))
		if t == nil {
			return nil, http.StatusUnauthorized, "invalid or expired API token"
		}
		return &Principal{User: u, Token: t}, 0, ""
	}
	s, u := a.session(r, st)
	if s == nil {
		return nil, http.StatusUnauthorized, "sign in required"
	}
	if s.Stage != auth.StageFull {
		return nil, http.StatusUnauthorized, "finish two-factor sign-in first"
	}
	if unsafeMethod(r.Method) {
		if err := a.checkCSRF(r, s); err != nil {
			return nil, http.StatusForbidden, err.Error()
		}
	}
	return &Principal{User: u, Session: s}, 0, ""
}

// session returns the cookie's session if it is live and its user still
// valid. Sessions older than a password change or MFA reset are dropped.
func (a *API) session(r *http.Request, st *store.State) (*auth.Session, *store.User) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return nil, nil
	}
	s := a.Sessions.Get(c.Value)
	if s == nil {
		return nil, nil
	}
	u, ok := st.Users[s.UserID]
	if !ok || u.Disabled || s.Created.Before(u.PasswordChangedAt.Add(-time.Second)) ||
		(s.Stage == auth.StageFull && !u.MFAEnrolled()) {
		a.Sessions.Delete(c.Value)
		return nil, nil
	}
	return s, u
}

// stage wraps sign-in steps that need a session at a given pending stage.
func (a *API) stage(want string, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, u := a.session(r, a.Store.State())
		if s == nil || s.Stage != want {
			writeErr(w, http.StatusUnauthorized, "sign in first")
			return
		}
		if err := a.checkCSRF(r, s); err != nil {
			writeErr(w, http.StatusForbidden, err.Error())
			return
		}
		h(w, r, &Principal{User: u, Session: s})
	}
}

// checkCSRF requires the session's CSRF token in X-CSRF-Token and, when the
// browser sends one, a same-origin Origin header.
func (a *API) checkCSRF(r *http.Request, s *auth.Session) error {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.CSRF)) != 1 {
		return errors.New("missing or wrong CSRF token")
	}
	return a.checkOrigin(r)
}

func (a *API) checkOrigin(r *http.Request) error {
	o := r.Header.Get("Origin")
	if o == "" {
		return nil
	}
	u, err := url.Parse(o)
	if err != nil {
		return errors.New("cross-site request blocked")
	}
	if strings.EqualFold(u.Host, r.Host) || slices.ContainsFunc(a.AllowedOrigins, func(h string) bool { return strings.EqualFold(h, u.Host) }) {
		return nil
	}
	return errors.New("cross-site request blocked (set DNSERV_ALLOWED_ORIGINS if a proxy rewrites Host)")
}

func (a *API) checkToken(st *store.State, raw string) (*store.Token, *store.User) {
	id, secret, ok := strings.Cut(strings.TrimPrefix(strings.TrimSpace(raw), "dns_"), ".")
	if !ok {
		return nil, nil
	}
	t, ok := st.Tokens[id]
	if !ok || subtle.ConstantTimeCompare([]byte(auth.HashToken(secret)), []byte(t.Hash)) != 1 {
		return nil, nil
	}
	if !t.ExpiresAt.IsZero() && a.now().After(t.ExpiresAt) {
		return nil, nil
	}
	u, ok := st.Users[t.UserID]
	if !ok || u.Disabled {
		return nil, nil
	}
	return t, u
}

func unsafeMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

func (a *API) setCookie(w http.ResponseWriter, r *http.Request, token string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: token, Path: "/", HttpOnly: true, Secure: r.TLS != nil,
		SameSite: http.SameSiteStrictMode, MaxAge: int(maxAge / time.Second),
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func secureHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-store")
		hd.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.ServeHTTP(w, r)
	})
}

// --- JSON helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("bad request: %v", err))
		return false
	}
	return true
}

// apply runs a store command and maps errors to HTTP statuses.
func (a *API) apply(w http.ResponseWriter, c store.Command) (any, bool) {
	res, err := a.Store.Apply(c)
	switch {
	case err == nil:
		return res, true
	default:
		a.writeStoreErr(w, err)
	}
	return nil, false
}
