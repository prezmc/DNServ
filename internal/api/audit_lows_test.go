package api

import (
	"testing"
	"time"

	"github.com/prezmc/dnserv/internal/store"
)

// List addresses from the API must be web addresses; ones already in the
// settings (perhaps a file from the config) can stay.
func TestListURLsMustBeWeb(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()
	for _, u := range []string{"/etc/passwd", "file:///data/x.txt", "ftp://x.example/l.txt"} {
		admin.want(400, "PATCH", "/api/v1/settings", map[string]any{"lists": []map[string]any{{"name": "x", "url": u, "enabled": true}}}, nil)
		admin.want(400, "PATCH", "/api/v1/settings", map[string]any{"allowlists": []map[string]any{{"name": "x", "url": u, "enabled": true}}}, nil)
	}
	admin.want(200, "PATCH", "/api/v1/settings", map[string]any{"lists": []map[string]any{{"name": "ok", "url": "https://lists.example/a.txt", "enabled": true}}}, nil)
}

// An API token can't create users, set passwords, reset 2FA or change roles.
func TestTokenCantManagePeople(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()
	var v store.PublicUser
	admin.want(201, "POST", "/api/v1/users", map[string]any{"username": "vee", "password": pw, "role": "viewer"}, &v)
	var tok struct{ Token string }
	admin.want(201, "POST", "/api/v1/tokens", map[string]any{"name": "t", "perms": []string{"users.manage"}}, &tok)
	bot := e.client()
	bot.token = tok.Token
	bot.want(200, "GET", "/api/v1/users", nil, nil)
	bot.want(403, "POST", "/api/v1/users", map[string]any{"username": "eve", "password": pw, "role": "admin"}, nil)
	bot.want(403, "POST", "/api/v1/users/"+v.ID+"/password", map[string]string{"password": "orange lantern 77 river"}, nil)
	bot.want(403, "POST", "/api/v1/users/"+v.ID+"/reset-mfa", nil, nil)
	bot.want(403, "PATCH", "/api/v1/users/"+v.ID, map[string]any{"role": "admin"}, nil)
	bot.want(200, "PATCH", "/api/v1/users/"+v.ID, map[string]any{"disabled": true}, nil)
}

// Signing out everywhere reaches every session, not just this server's list.
func TestSignOutEverywhere(t *testing.T) {
	e := newEnv(t)
	a, secret := e.setupAdmin()
	var v store.PublicUser
	a.want(201, "POST", "/api/v1/users", map[string]any{"username": "vee", "password": pw, "role": "viewer"}, &v)
	vc, _ := e.signInNew("vee", pw)

	e.now = e.now.Add(30 * time.Second)
	other := e.client()
	other.want(200, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": pw}, nil)
	other.want(200, "POST", "/api/v1/auth/mfa", map[string]string{"code": e.code(secret)}, nil)
	e.now = e.now.Add(30 * time.Second)

	a.want(200, "POST", "/api/v1/auth/sessions/sign-out-others", nil, nil)
	other.want(401, "GET", "/api/v1/status", nil, nil)
	a.want(200, "GET", "/api/v1/status", nil, nil)
	vc.want(200, "GET", "/api/v1/status", nil, nil)

	vc.want(403, "POST", "/api/v1/users/"+v.ID+"/sign-out", nil, nil)
	a.want(204, "POST", "/api/v1/users/"+v.ID+"/sign-out", nil, nil)
	vc.want(401, "GET", "/api/v1/status", nil, nil)
	a.want(200, "GET", "/api/v1/status", nil, nil)
}

// Managing devices alone doesn't let someone loosen a group's filtering.
func TestGroupFilteringNeedsFilterPerms(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()
	admin.want(201, "POST", "/api/v1/users", map[string]any{"username": "dee", "password": pw, "role": "power", "perms": []string{"devices.manage"}}, nil)
	d, _ := e.signInNew("dee", pw)
	var g store.Group
	admin.want(201, "POST", "/api/v1/groups", map[string]any{"name": "Kids", "rules": []string{"||games.example^"}}, &g)
	path := "/api/v1/groups/" + g.ID
	d.want(403, "PUT", path, map[string]any{"name": "Kids", "rules": []string{}}, nil)
	d.want(403, "PUT", path, map[string]any{"name": "Kids", "rules": []string{"||games.example^"}, "household_rules": "off"}, nil)
	d.want(403, "PUT", path, map[string]any{"name": "Kids", "rules": []string{"||games.example^"}, "list_mode": "choose"}, nil)
	d.want(403, "POST", "/api/v1/groups", map[string]any{"name": "Open", "rules": []string{"@@||games.example^"}}, nil)
	d.want(200, "PUT", path, map[string]any{"name": "Children", "rules": []string{"||games.example^"}}, nil)
	d.want(201, "POST", "/api/v1/groups", map[string]any{"name": "Guests"}, nil)
}

// Viewers can't spend the VirusTotal quota.
func TestVirusTotalNeedsAllowBlock(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()
	admin.want(201, "POST", "/api/v1/users", map[string]any{"username": "vee", "password": pw, "role": "viewer"}, nil)
	vc, _ := e.signInNew("vee", pw)
	vc.want(403, "POST", "/api/v1/analytics/virustotal?name=example.com", nil, nil)
}

func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{"=cmd()": "'=cmd()", "+1": "'+1", "@x": "'@x", "-2": "'-2", "example.com": "example.com", "": ""} {
		if got := csvSafe(in); got != want {
			t.Fatalf("csvSafe(%q) = %q", in, got)
		}
	}
}
