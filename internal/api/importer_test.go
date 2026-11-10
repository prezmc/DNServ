package api

import (
	"context"
	"testing"

	"github.com/prezmc/dnserv/internal/adguard"
	"github.com/prezmc/dnserv/internal/store"
)

func TestAdGuardImport(t *testing.T) {
	snap := &adguard.Snapshot{
		Source: "http://192.168.1.2:3000", Version: "v0.107.52",
		Filters:         []adguard.Filter{{Name: "AdGuard DNS filter", URL: "https://example.com/f1.txt", Enabled: true}},
		UserRules:       []string{"||ads.example^", "192.168.1.5 nas.lan"},
		Rewrites:        []adguard.Rewrite{{Domain: "router.lan", Answer: "192.168.1.1"}},
		DNS:             adguard.DNSInfo{Upstreams: []string{"https://dns.quad9.net/dns-query"}, BlockingMode: "refused", LocalPTR: []string{"192.168.1.1"}},
		Clients:         []adguard.Client{{Name: "Laptop", IDs: []string{"192.168.1.10"}, UseGlobalServices: true, UseGlobalSettings: false, FilteringEnabled: false}, {Name: "TV", IDs: []string{"192.168.1.11"}, UseGlobalSettings: true, UseGlobalServices: true}},
		BlockedServices: []string{"tiktok"},
		Services:        map[string]adguard.Service{"tiktok": {Name: "TikTok", Rules: []string{"||tiktok.com^"}}},
	}
	var gotConn adguard.Conn
	old := fetchAdGuard
	fetchAdGuard = func(_ context.Context, c adguard.Conn) (*adguard.Snapshot, error) { gotConn = c; return snap, nil }
	t.Cleanup(func() { fetchAdGuard = old })

	e := newEnv(t)
	admin, _ := e.setupAdmin()
	var prev struct {
		ID   string
		Plan adguard.Plan
	}
	admin.want(200, "POST", "/api/v1/import/adguard/preview", map[string]any{"url": "192.168.1.2:3000", "username": "admin", "password": "pw"}, &prev)
	if gotConn.Password != "pw" || prev.ID == "" || len(prev.Plan.Sections) < 5 {
		t.Fatalf("preview: %+v", prev)
	}

	// Another user can't use the preview, and only admins can import.
	admin.want(201, "POST", "/api/v1/users", map[string]any{"username": "pat", "password": pw, "role": "power", "perms": []string{"rules.edit", "lists.manage"}}, nil)
	admin.want(410, "POST", "/api/v1/import/adguard/apply", map[string]any{"id": "nope", "sections": []string{"lists"}}, nil)

	var res importResult
	admin.want(200, "POST", "/api/v1/import/adguard/apply", map[string]any{
		"id":       prev.ID,
		"sections": []string{"lists", "rules", "records", "blocking", "local_dns", "devices", "groups"},
		"exclude":  []string{"devices:TV@192.168.1.11"},
	}, &res)
	if res.Lists != 1 || res.Rules != 2 || res.Records != 2 || res.Devices != 1 || res.Groups != 1 || res.Summary == "" {
		t.Fatalf("result: %+v", res)
	}
	st := e.api.Store.State()
	eff := e.api.Effective()
	if eff.Filtering.BlockMode != "refused" || eff.DNS.LocalDNS != "192.168.1.1" || len(eff.DNS.Records) != 2 {
		t.Errorf("settings: block %q local %q records %v", eff.Filtering.BlockMode, eff.DNS.LocalDNS, eff.DNS.Records)
	}
	if eff.Upstream.Servers[0] == "https://dns.quad9.net/dns-query" {
		t.Error("upstream imported though not chosen")
	}
	if len(st.Devices) != 1 || len(st.Groups) != 1 {
		t.Fatalf("devices %v groups %v", st.Devices, st.Groups)
	}
	for _, d := range st.Devices {
		g := st.Groups[d.Group]
		if d.Name != "Laptop" || g == nil || !g.SkipBlocklists {
			t.Errorf("device %+v group %+v", d, g)
		}
	}

	// The preview is used up; a fresh one finds nothing new except what
	// was left out.
	admin.want(410, "POST", "/api/v1/import/adguard/apply", map[string]any{"id": prev.ID, "sections": []string{"lists"}}, nil)
	admin.want(200, "POST", "/api/v1/import/adguard/preview", map[string]any{"url": "x"}, &prev)
	for _, s := range prev.Plan.Sections {
		switch s.Key {
		case "lists", "rules", "records", "blocking", "local_dns", "groups":
			if len(s.Items) != 0 {
				t.Errorf("second preview %s still has %v", s.Key, s.Items)
			}
		case "devices":
			if len(s.Items) != 1 || s.Items[0].Text != "TV" {
				t.Errorf("second preview devices: %v", s.Items)
			}
		}
	}
	var log []store.AuditEntry
	admin.want(200, "GET", "/api/v1/audit", nil, &log)
	if len(log) < 4 {
		t.Errorf("audit has %d entries", len(log))
	}
}

func TestAdGuardImportAdminOnly(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()
	admin.want(201, "POST", "/api/v1/users", map[string]any{"username": "pat", "password": pw, "role": "power", "perms": []string{"rules.edit", "lists.manage"}}, nil)
	p := e.client()
	var login struct{ Stage string }
	p.want(200, "POST", "/api/v1/auth/login", map[string]string{"username": "pat", "password": pw}, &login)
	var begin struct{ Secret string }
	p.want(200, "POST", "/api/v1/auth/totp/begin", map[string]string{}, &begin)
	p.want(200, "POST", "/api/v1/auth/totp/confirm", map[string]string{"code": e.code(begin.Secret)}, nil)
	p.want(403, "POST", "/api/v1/import/adguard/preview", map[string]any{"url": "x"}, nil)
	p.want(403, "POST", "/api/v1/import/adguard/apply", map[string]any{"id": "x"}, nil)
}
