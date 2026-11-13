package api

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/prezmc/dnserv/internal/analytics"
	"github.com/prezmc/dnserv/internal/cache"
	"github.com/prezmc/dnserv/internal/config"
	"github.com/prezmc/dnserv/internal/querylog"
	"github.com/prezmc/dnserv/internal/store"
)

// signInNew signs a new user in and enrolls their authenticator.
func (e *env) signInNew(username, password string) (*client, string) {
	e.t.Helper()
	c := e.client()
	c.want(200, "POST", "/api/v1/auth/login", map[string]string{"username": username, "password": password}, nil)
	var begin struct{ Secret string }
	c.want(200, "POST", "/api/v1/auth/totp/begin", map[string]string{}, &begin)
	c.want(200, "POST", "/api/v1/auth/totp/confirm", map[string]string{"code": e.code(begin.Secret)}, nil)
	return c, begin.Secret
}

func TestUserAdministration(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()
	var v store.PublicUser
	admin.want(201, "POST", "/api/v1/users", map[string]any{"username": "vee", "password": pw, "role": "viewer"}, &v)
	vc, secret := e.signInNew("vee", pw)

	// Session lists never carry token hashes or CSRF tokens.
	for _, path := range []string{"/api/v1/auth/sessions", "/api/v1/sessions"} {
		raw := admin.raw("GET", path)
		if strings.Contains(raw, `"hash"`) || strings.Contains(raw, `"csrf"`) {
			t.Fatalf("%s leaks secrets: %s", path, raw)
		}
	}
	var mine []sessionView
	vc.want(200, "GET", "/api/v1/auth/sessions", nil, &mine)
	if len(mine) != 1 || mine[0].UserID != v.ID {
		t.Fatalf("viewer's sessions = %+v", mine)
	}
	vc.want(403, "GET", "/api/v1/sessions", nil, nil)
	// A user can't sign out someone else's session.
	var all []sessionView
	admin.want(200, "GET", "/api/v1/sessions", nil, &all)
	var adminSession string
	for _, s := range all {
		if s.UserID != v.ID {
			adminSession = s.ID
		}
	}
	vc.want(404, "DELETE", "/api/v1/auth/sessions/"+adminSession, nil, nil)
	// An admin can.
	admin.want(204, "DELETE", "/api/v1/sessions/"+mine[0].ID, nil, nil)
	vc.want(401, "GET", "/api/v1/status", nil, nil)

	// Tokens: listed without their secret, and revocable.
	var tok struct{ ID, Token string }
	admin.want(201, "POST", "/api/v1/tokens", map[string]any{"name": "script", "perms": []string{"dashboard.view"}}, &tok)
	if raw := admin.raw("GET", "/api/v1/tokens"); !strings.Contains(raw, `"script"`) || strings.Contains(raw, strings.SplitN(tok.Token, ".", 2)[1]) {
		t.Fatalf("token list %s", raw)
	}
	bot := e.client()
	bot.token = tok.Token
	bot.want(200, "GET", "/api/v1/status", nil, nil)
	admin.want(204, "DELETE", "/api/v1/tokens/"+tok.ID, nil, nil)
	bot.want(401, "GET", "/api/v1/status", nil, nil)

	// A new password from an admin: the old one stops working.
	const pw2 = "orange lantern 77 river"
	admin.want(400, "POST", "/api/v1/users/"+v.ID+"/password", map[string]string{"password": "short"}, nil)
	admin.want(204, "POST", "/api/v1/users/"+v.ID+"/password", map[string]string{"password": pw2}, nil)
	e.client().want(401, "POST", "/api/v1/auth/login", map[string]string{"username": "vee", "password": pw}, nil)
	e.now = e.now.Add(time.Minute)
	c := e.client()
	c.want(200, "POST", "/api/v1/auth/login", map[string]string{"username": "vee", "password": pw2}, nil)
	c.want(200, "POST", "/api/v1/auth/mfa", map[string]string{"code": e.code(secret)}, nil)

	// Resetting two-factor makes them enroll again.
	admin.want(204, "POST", "/api/v1/users/"+v.ID+"/reset-mfa", nil, nil)
	e.now = e.now.Add(time.Minute)
	var login struct{ Stage string }
	e.client().want(200, "POST", "/api/v1/auth/login", map[string]string{"username": "vee", "password": pw2}, &login)
	if login.Stage != "enroll" {
		t.Fatalf("stage after MFA reset = %q", login.Stage)
	}

	// Deleting: gone from the list, can't sign in.
	admin.want(204, "DELETE", "/api/v1/users/"+v.ID, nil, nil)
	admin.want(404, "DELETE", "/api/v1/users/"+v.ID, nil, nil)
	e.client().want(401, "POST", "/api/v1/auth/login", map[string]string{"username": "vee", "password": pw2}, nil)
	if raw := admin.raw("GET", "/api/v1/users"); strings.Contains(raw, `"vee"`) {
		t.Fatal("deleted user still listed")
	}
}

func TestCacheAndBeaconEndpoints(t *testing.T) {
	e := newEnv(t)
	e.now = time.Now()
	hs, err := analytics.Open(filepath.Join(t.TempDir(), "h.db"), func() string { return "alpha" }, 30, 90, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })
	e.api.Analytics = hs
	admin, _ := e.setupAdmin()

	rr := func(ttl uint32) []dns.RR {
		a, _ := dns.NewRR("short.example. " + itoa(uint64(ttl)) + " IN A 192.0.2.1")
		return []dns.RR{a}
	}
	tv := netip.MustParseAddr("192.168.1.10")
	start := e.now.Add(-2 * time.Hour)
	// A name with a 10-second cache time, asked every minute: every
	// lookup after the first is a "short" miss, and it's a steady beat.
	for i := range 20 {
		hs.Record(querylog.Entry{Time: start.Add(time.Duration(i) * time.Minute), Client: tv, Name: "short.example", Type: "A", Result: querylog.Answered, Answer: rr(10)})
	}
	// A cached one, for the hit count.
	hs.Record(querylog.Entry{Time: start, Client: tv, Name: "short.example", Type: "AAAA", Result: querylog.Cached})
	hs.Flush()

	var report struct {
		Hits    int64 `json:"hits"`
		Misses  int64 `json:"misses"`
		Reasons []struct {
			Reason  string `json:"reason"`
			N       int64  `json:"n"`
			Domains []struct {
				Name string `json:"name"`
				N    int64  `json:"n"`
			} `json:"domains"`
		} `json:"reasons"`
	}
	admin.want(200, "GET", "/api/v1/analytics/cache?range=24h", nil, &report)
	got := map[string]int64{}
	for _, r := range report.Reasons {
		got[r.Reason] = r.N
	}
	if report.Hits != 1 || report.Misses != 20 || got["first"] != 1 || got["short"] != 19 {
		t.Fatalf("cache report = %+v", report)
	}
	admin.want(400, "GET", "/api/v1/analytics/cache?range=bad", nil, nil)

	var beats struct {
		Domains []struct {
			Name   string `json:"name"`
			Period int64  `json:"period"`
			Who    []struct {
				Addr string `json:"addr"`
			} `json:"who"`
		} `json:"domains"`
	}
	admin.want(200, "GET", "/api/v1/analytics/beacons?range=24h", nil, &beats)
	if len(beats.Domains) != 1 || beats.Domains[0].Name != "short.example" || beats.Domains[0].Period != 60 || len(beats.Domains[0].Who) != 1 || beats.Domains[0].Who[0].Addr != "192.168.1.10" {
		t.Fatalf("beacons = %+v", beats)
	}
	// How full each server's cache is comes with the report.
	e.api.CacheFill = func(context.Context) []CacheFill {
		return []CacheFill{{Server: "n1", Fill: &cache.Fill{Entries: 900, Fresh: 700, Usable: 850, Max: 1000, Evicted: 5}}, {Server: "n2", Error: "down"}}
	}
	var withFill struct{ Fill []CacheFill }
	admin.want(200, "GET", "/api/v1/analytics/cache?range=24h", nil, &withFill)
	if len(withFill.Fill) != 2 || withFill.Fill[0].Fill.Entries != 900 || withFill.Fill[1].Error != "down" {
		t.Fatalf("fill = %+v", withFill.Fill)
	}
	// The cache size is a setting, within limits.
	admin.want(400, "PATCH", "/api/v1/settings", map[string]any{"cache_size": 10}, nil)
	var set struct{ Effective config.Config }
	admin.want(200, "PATCH", "/api/v1/settings", map[string]any{"cache_size": 250000}, &set)
	if set.Effective.Cache.MaxEntries != 250000 {
		t.Fatalf("cache size = %d", set.Effective.Cache.MaxEntries)
	}

	// Filtered to another device: nothing.
	admin.want(200, "GET", "/api/v1/analytics/beacons?range=24h&client=192.168.1.99", nil, &beats)
	if len(beats.Domains) != 0 {
		t.Fatalf("other device's beacons = %+v", beats)
	}
}
