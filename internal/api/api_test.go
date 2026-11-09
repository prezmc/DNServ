package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prezmc/dnserve/internal/auth"
	"github.com/prezmc/dnserve/internal/config"
	"github.com/prezmc/dnserve/internal/store"
)

type env struct {
	t   *testing.T
	api *API
	srv *httptest.Server
	now time.Time
}

func newEnv(t *testing.T) *env {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := auth.OpenSessions(dir)
	if err != nil {
		t.Fatal(err)
	}
	base := config.Default()
	e := &env{t: t, now: time.Unix(1_800_000_000, 0)}
	e.api = New(st, sess, base, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.api.now = func() time.Time { return e.now }
	e.srv = httptest.NewServer(e.api.Handler())
	t.Cleanup(e.srv.Close)
	return e
}

// client is one browser: a cookie jar plus the current CSRF token.
type client struct {
	e     *env
	http  *http.Client
	csrf  string
	token string // API token instead of a cookie
}

func (e *env) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{e: e, http: &http.Client{Jar: jar}}
}

func (c *client) do(method, path string, body any, out any) int {
	c.e.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.e.srv.URL+path, r)
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	if json.Unmarshal(b, &m) == nil {
		if v, ok := m["csrf"].(string); ok {
			c.csrf = v
		}
	}
	if out != nil {
		json.Unmarshal(b, out)
	}
	return resp.StatusCode
}

func (c *client) want(status int, method, path string, body any, out any) {
	c.e.t.Helper()
	if got := c.do(method, path, body, out); got != status {
		c.e.t.Fatalf("%s %s: got HTTP %d, want %d", method, path, got, status)
	}
}

func (e *env) code(secret string) string {
	c, err := auth.TOTPCode(secret, e.now)
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

const pw = "plum orchard 42 sky"

// setupAdmin runs first-run setup and MFA enrollment, returning a fully
// signed-in admin and the TOTP secret.
func (e *env) setupAdmin() (*client, string) {
	c := e.client()
	code := e.api.SetupCode()
	if code == "" {
		e.t.Fatal("no setup code")
	}
	c.want(403, "POST", "/api/v1/setup/check", map[string]string{"code": "WRONG"}, nil)
	c.want(204, "POST", "/api/v1/setup/check", map[string]string{"code": strings.ToLower(strings.ReplaceAll(code, "-", " "))}, nil)
	c.want(403, "POST", "/api/v1/setup", map[string]string{"code": "WRONG", "username": "admin", "password": pw}, nil)
	c.want(201, "POST", "/api/v1/setup", map[string]string{"code": code, "username": "admin", "password": pw}, nil)
	// Not signed in until MFA is enrolled.
	c.want(401, "GET", "/api/v1/users", nil, nil)
	var begin struct{ Secret string }
	c.want(200, "POST", "/api/v1/auth/totp/begin", map[string]string{}, &begin)
	c.want(401, "POST", "/api/v1/auth/totp/confirm", map[string]string{"code": "000000"}, nil)
	var conf struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	c.want(200, "POST", "/api/v1/auth/totp/confirm", map[string]string{"code": e.code(begin.Secret)}, &conf)
	if len(conf.RecoveryCodes) != 10 {
		e.t.Fatalf("got %d recovery codes", len(conf.RecoveryCodes))
	}
	return c, begin.Secret
}

func TestSetupAndSignIn(t *testing.T) {
	e := newEnv(t)
	admin, secret := e.setupAdmin()
	admin.want(200, "GET", "/api/v1/users", nil, nil)

	// Setup can't run twice.
	e.client().want(409, "POST", "/api/v1/setup/check", map[string]string{"code": "X"}, nil)
	e.client().want(409, "POST", "/api/v1/setup", map[string]string{"code": "X", "username": "evil", "password": pw}, nil)

	// Writes need the CSRF token.
	saved := admin.csrf
	admin.csrf = ""
	admin.want(403, "POST", "/api/v1/users", map[string]any{"username": "bob", "password": pw, "role": "viewer"}, nil)
	admin.csrf = saved

	// Sign in again: password, then a TOTP code.
	c := e.client()
	c.want(401, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "wrong password!!"}, nil)
	c.want(200, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": pw}, nil)
	c.want(401, "GET", "/api/v1/status", nil, nil)
	// The code used for enrollment can't be replayed.
	c.want(401, "POST", "/api/v1/auth/mfa", map[string]string{"code": e.code(secret)}, nil)
	e.now = e.now.Add(30 * time.Second)
	c.want(200, "POST", "/api/v1/auth/mfa", map[string]string{"code": e.code(secret)}, nil)
	c.want(200, "GET", "/api/v1/status", nil, nil)

	var me struct {
		SignedIn bool `json:"signed_in"`
		Perms    []string
	}
	c.want(200, "GET", "/api/v1/auth/me", nil, &me)
	if !me.SignedIn || len(me.Perms) != len(store.AllPerms) {
		t.Fatalf("me: %+v", me)
	}

	// Logout ends the session.
	c.want(204, "POST", "/api/v1/auth/logout", nil, nil)
	c.want(401, "GET", "/api/v1/status", nil, nil)
}

func TestRecoveryCodeSignIn(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	code := e.api.SetupCode()
	c.want(201, "POST", "/api/v1/setup", map[string]string{"code": code, "username": "admin", "password": pw}, nil)
	var begin struct{ Secret string }
	c.want(200, "POST", "/api/v1/auth/totp/begin", map[string]string{}, &begin)
	var conf struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	c.want(200, "POST", "/api/v1/auth/totp/confirm", map[string]string{"code": e.code(begin.Secret)}, &conf)

	for i, wantStatus := range []int{200, 401} { // second use fails
		b := e.client()
		b.want(200, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": pw}, nil)
		if got := b.do("POST", "/api/v1/auth/mfa", map[string]string{"code": conf.RecoveryCodes[0]}, nil); got != wantStatus {
			t.Fatalf("recovery attempt %d: HTTP %d, want %d", i, got, wantStatus)
		}
	}
}

func TestRolesTokensAndSettings(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()

	var pat store.PublicUser
	admin.want(201, "POST", "/api/v1/users", map[string]any{"username": "pat", "password": pw, "role": "power", "perms": []string{"rules.edit", "domains.allowblock"}}, &pat)

	// New users must enroll MFA before anything else.
	p := e.client()
	var login struct{ Stage string }
	p.want(200, "POST", "/api/v1/auth/login", map[string]string{"username": "pat", "password": pw}, &login)
	if login.Stage != auth.StageEnroll {
		t.Fatalf("new user stage %q, want enroll", login.Stage)
	}
	var begin struct{ Secret string }
	p.want(200, "POST", "/api/v1/auth/totp/begin", map[string]string{}, &begin)
	p.want(200, "POST", "/api/v1/auth/totp/confirm", map[string]string{"code": e.code(begin.Secret)}, nil)

	// Power user: may edit rules and block domains, not upstream or users.
	p.want(200, "POST", "/api/v1/domains", map[string]string{"domain": "Ads.Example.com", "action": "block"}, nil)
	p.want(403, "PATCH", "/api/v1/settings", map[string]any{"upstream_mode": "recursive"}, nil)
	p.want(403, "GET", "/api/v1/users", nil, nil)
	p.want(403, "GET", "/api/v1/audit", nil, nil)
	p.want(400, "POST", "/api/v1/domains", map[string]string{"domain": "not a domain", "action": "block"}, nil)

	var settings struct {
		Effective config.Config
	}
	admin.want(200, "GET", "/api/v1/settings", nil, &settings)
	if r := settings.Effective.Filtering.Rules; len(r) != 1 || r[0] != "||ads.example.com^" {
		t.Fatalf("rules after block: %v", r)
	}

	// Admin: invalid settings are rejected, valid ones saved.
	admin.want(400, "PATCH", "/api/v1/settings", map[string]any{"upstream_mode": "carrier-pigeon"}, nil)
	admin.want(400, "PATCH", "/api/v1/settings", map[string]any{"allowed_nets": []string{"not-a-net"}}, nil)
	admin.want(200, "PATCH", "/api/v1/settings", map[string]any{"upstream_mode": "recursive"}, &settings)
	if settings.Effective.Upstream.Mode != "recursive" {
		t.Fatal("mode not saved")
	}

	// Tokens are limited to the creator's permissions.
	p.want(403, "POST", "/api/v1/tokens", map[string]any{"name": "t", "perms": []string{"users.manage"}}, nil)
	var tok struct{ Token string }
	p.want(201, "POST", "/api/v1/tokens", map[string]any{"name": "automation", "perms": []string{"domains.allowblock"}}, &tok)
	bot := e.client()
	bot.token = tok.Token
	bot.want(200, "POST", "/api/v1/domains", map[string]string{"domain": "tracker.example", "action": "block"}, nil)
	bot.want(403, "PATCH", "/api/v1/settings", map[string]any{"rules": []string{}}, nil) // rules.edit not in token
	bot.token = tok.Token + "x"
	bot.want(401, "GET", "/api/v1/status", nil, nil)

	// Disabling a user ends their sessions and tokens.
	admin.want(200, "PATCH", "/api/v1/users/"+pat.ID, map[string]any{"disabled": true}, nil)
	p.want(401, "GET", "/api/v1/status", nil, nil)
	bot.token = tok.Token
	bot.want(401, "GET", "/api/v1/status", nil, nil)

	// The audit log records who did what.
	var log []store.AuditEntry
	admin.want(200, "GET", "/api/v1/audit", nil, &log)
	if len(log) < 5 {
		t.Fatalf("audit has %d entries", len(log))
	}
}

func TestPasswordChangeEndsOtherSessions(t *testing.T) {
	e := newEnv(t)
	a, secret := e.setupAdmin()
	e.now = e.now.Add(30 * time.Second)
	other := e.client()
	other.want(200, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": pw}, nil)
	other.want(200, "POST", "/api/v1/auth/mfa", map[string]string{"code": e.code(secret)}, nil)

	a.want(401, "POST", "/api/v1/auth/password", map[string]string{"current": "nope nope nope", "new": "brand new passphrase 9"}, nil)
	a.want(200, "POST", "/api/v1/auth/password", map[string]string{"current": pw, "new": "brand new passphrase 9"}, nil)
	a.want(200, "GET", "/api/v1/status", nil, nil)
	other.want(401, "GET", "/api/v1/status", nil, nil)
}

func TestLoginThrottle(t *testing.T) {
	e := newEnv(t)
	e.setupAdmin()
	c := e.client()
	for i := 0; i < 5; i++ {
		c.want(401, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "wrong password!!"}, nil)
	}
	c.want(429, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": pw}, nil)
}

func TestCrossOriginBlocked(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/auth/login", bytes.NewReader([]byte(`{"username":"a","password":"b"}`)))
	req.Header.Set("Origin", "https://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("cross-origin login: HTTP %d", resp.StatusCode)
	}
}
