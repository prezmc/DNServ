package adguard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prezmc/dnserv/internal/config"
	"github.com/prezmc/dnserv/internal/store"
)

// fakeAGH answers like AdGuard Home v0.107 with Basic auth.
func fakeAGH(t *testing.T, missing ...string) *httptest.Server {
	t.Helper()
	resp := map[string]string{
		"/control/status": `{"version":"v0.107.52","protection_enabled":true,"running":true}`,
		"/control/filtering/status": `{"enabled":true,"interval":24,
			"filters":[{"id":1,"name":"AdGuard DNS filter","url":"https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt","enabled":true,"rules_count":50000},
			           {"id":2,"name":"Old list","url":"https://example.com/old.txt","enabled":false},
			           {"id":3,"name":"Local file","url":"/opt/adguardhome/mylist.txt","enabled":true},
			           {"id":4,"name":"Already here","url":"https://example.com/have.txt","enabled":true}],
			"whitelist_filters":[{"id":5,"name":"My allowlist","url":"https://example.com/allow.txt","enabled":true}],
			"user_rules":["! comment","||ads.example^","@@||good.example^","/regex.*/","||kid.example^$client=192.168.1.20",
			              "192.168.1.5 nas.lan","0.0.0.0 tracker.example","||printer.lan^$dnsrewrite=192.168.1.9","||x.example^$dnsrewrite=REFUSED","||have.example^"]}`,
		"/control/rewrite/list": `[{"domain":"router.lan","answer":"192.168.1.1"},{"domain":"*.lab.lan","answer":"192.168.1.50"},
			{"domain":"www.lan","answer":"router.lan"},{"domain":"keep.example","answer":"A"},{"domain":"off.lan","answer":"192.168.1.7","enabled":false}]`,
		"/control/dns_info": `{"upstream_dns":["https://dns.quad9.net/dns-query","tls://1.1.1.1","quic://dns.adguard-dns.com","127.0.0.1:5335","[/lan/]192.168.1.1","# note"],
			"local_ptr_upstreams":[],"blocking_mode":"nxdomain","protection_enabled":true}`,
		"/control/clients": `{"clients":[
			{"name":"Kid tablet","ids":["192.168.1.20"],"use_global_settings":true,"filtering_enabled":true,"use_global_blocked_services":false,"blocked_services":["youtube","tiktok"]},
			{"name":"Work laptop","ids":["aa:bb:cc:dd:ee:ff","work-laptop"],"use_global_settings":false,"filtering_enabled":false,"use_global_blocked_services":true},
			{"name":"Office","ids":["10.0.0.0/24"],"use_global_settings":true,"use_global_blocked_services":true},
			{"name":"Named already","ids":["192.168.1.30"],"use_global_settings":true,"use_global_blocked_services":true}],
			"auto_clients":[{"name":"phone","ip":"192.168.1.40"}]}`,
		"/control/access/list":           `{"allowed_clients":["192.168.1.0/24","my-client-id"],"disallowed_clients":["192.168.1.99"],"blocked_hosts":["version.bind","id.server","hostname.bind","bad.example"]}`,
		"/control/blocked_services/get":  `{"ids":["tiktok"],"schedule":{"time_zone":"Local"}}`,
		"/control/blocked_services/all":  `{"blocked_services":[{"id":"tiktok","name":"TikTok","rules":["||tiktok.com^","||tiktokv.com^"]},{"id":"youtube","name":"YouTube","rules":["||youtube.com^","||ytimg.com^","/yt-regex/"]}]}`,
		"/control/dhcp/status":           `{"enabled":true,"static_leases":[{"mac":"AA-BB-CC-DD-EE-FF","ip":"192.168.1.60","hostname":"work"},{"mac":"11:22:33:44:55:66","ip":"192.168.1.61","hostname":"tv"}]}`,
		"/control/safebrowsing/status":   `{"enabled":true}`,
		"/control/parental/status":       `{"enabled":false}`,
		"/control/safesearch/status":     `{"enabled":true}`,
		"/control/blocked_services/list": `["tiktok"]`,
	}
	for _, m := range missing {
		delete(resp, m)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "secret" {
			http.Redirect(w, r, "/login.html", http.StatusFound)
			return
		}
		body, ok := resp[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
}

func TestFetchAuthAndURL(t *testing.T) {
	srv := fakeAGH(t)
	defer srv.Close()
	ctx := context.Background()
	if _, err := Fetch(ctx, Conn{URL: srv.URL, Username: "admin", Password: "wrong"}); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong password: %v", err)
	}
	host := strings.TrimPrefix(srv.URL, "http://")
	s, err := Fetch(ctx, Conn{URL: host + "/", Username: "admin", Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != "v0.107.52" || len(s.Filters) != 4 || len(s.Rewrites) != 5 || len(s.Clients) != 4 || s.AutoClients != 1 {
		t.Fatalf("snapshot: %+v", s)
	}
	if len(s.Services) != 2 || len(s.BlockedServices) != 1 || s.ServicesSchedule {
		t.Fatalf("services: %+v %v %v", s.Services, s.BlockedServices, s.ServicesSchedule)
	}
	for _, bad := range []string{"", "ftp://x", "http://u:p@host"} {
		if _, err := NormalizeURL(bad); err == nil {
			t.Errorf("NormalizeURL(%q) accepted", bad)
		}
	}
	if u, _ := NormalizeURL("10.0.0.2:3000/control/"); u != "http://10.0.0.2:3000" {
		t.Errorf("NormalizeURL: %q", u)
	}
}

func TestFetchOldVersion(t *testing.T) {
	srv := fakeAGH(t, "/control/blocked_services/get", "/control/blocked_services/all", "/control/dhcp/status")
	defer srv.Close()
	s, err := Fetch(context.Background(), Conn{URL: srv.URL, Username: "admin", Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.BlockedServices) != 1 || len(s.Missing) != 2 {
		t.Fatalf("old version: services %v missing %v", s.BlockedServices, s.Missing)
	}
}

func TestFetchNotAdGuard(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if _, err := Fetch(context.Background(), Conn{URL: srv.URL}); err == nil || !strings.Contains(err.Error(), "doesn't look like AdGuard Home") {
		t.Fatalf("got %v", err)
	}
}

func texts(items []Item) []string {
	var out []string
	for _, i := range items {
		out = append(out, i.Text)
	}
	return out
}

func has(items []Item, text string) bool {
	for _, i := range items {
		if strings.Contains(i.Text, text) {
			return true
		}
	}
	return false
}

func testState() (*store.State, config.Config) {
	st := &store.State{
		Devices: map[string]*store.Device{"d1": {ID: "d1", Name: "Named already", Addrs: []string{"192.168.1.30"}}},
		Groups:  map[string]*store.Group{},
	}
	eff := config.Default()
	eff.Filtering.Lists = []config.ListConfig{{Name: "Have", URL: "https://example.com/have.txt", Enabled: true}}
	eff.Filtering.Rules = []string{"||have.example^"}
	return st, eff
}

func TestBuildPlan(t *testing.T) {
	srv := fakeAGH(t)
	defer srv.Close()
	s, err := Fetch(context.Background(), Conn{URL: srv.URL, Username: "admin", Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	st, eff := testState()
	p := Build(s, st, eff, nil)
	sec := func(k string) *Section {
		t.Helper()
		x := p.Section(k)
		if x == nil {
			t.Fatalf("no section %s", k)
		}
		return x
	}

	lists := sec(KeyLists)
	if got := texts(lists.Items); len(got) != 2 || got[0] != "AdGuard DNS filter" || got[1] != "Old list" {
		t.Errorf("lists: %v", got)
	}
	if len(lists.Have) != 1 || len(lists.Skipped) != 1 {
		t.Errorf("lists have %v skipped %v", lists.Have, lists.Skipped)
	}
	if got := *p.patches[KeyLists].Lists; len(got) != 3 || got[2].Enabled {
		t.Errorf("lists patch: %+v", got)
	}

	rules := sec(KeyRules)
	for _, want := range []string{"||ads.example^", "@@||good.example^", "0.0.0.0 tracker.example", "Blocked service: TikTok", "||bad.example^"} {
		if !has(rules.Items, want) {
			t.Errorf("rules missing %q: %v", want, texts(rules.Items))
		}
	}
	if has(rules.Items, "version.bind") || has(rules.Items, "nas.lan") {
		t.Errorf("rules include defaults or rewrites: %v", texts(rules.Items))
	}
	if len(rules.Have) != 1 || len(rules.Skipped) != 2 { // $client, REFUSED rewrite
		t.Errorf("rules have %v skipped %v", texts(rules.Have), texts(rules.Skipped))
	}
	r := *p.patches[KeyRules].Rules
	if r[0] != "||have.example^" || !contains(r, "||tiktok.com^") || !contains(r, "||tiktokv.com^") {
		t.Errorf("rules patch: %v", r)
	}

	recs := sec(KeyRecords)
	for _, want := range []string{"router.lan → 192.168.1.1", "*.lab.lan → 192.168.1.50", "www.lan → router.lan", "nas.lan → 192.168.1.5", "printer.lan → 192.168.1.9"} {
		if !has(recs.Items, want) {
			t.Errorf("records missing %q: %v", want, texts(recs.Items))
		}
	}
	if len(recs.Skipped) != 2 { // the A keep-answer and the turned off one
		t.Errorf("records skipped: %v", recs.Skipped)
	}

	up := sec(KeyUpstream)
	if got := texts(up.Items); len(got) != 2 || got[0] != "https://dns.quad9.net/dns-query" || got[1] != "tls://1.1.1.1" {
		t.Errorf("upstream: %v", got)
	}
	if !up.Default || len(up.Skipped) != 3 { // quic, loopback, [/lan/]
		t.Errorf("upstream default %v skipped %v", up.Default, texts(up.Skipped))
	}
	if ld := sec(KeyLocalDNS); len(ld.Items) != 1 || ld.Items[0].Text != "192.168.1.1" || !ld.Default {
		t.Errorf("local dns: %+v", ld)
	}
	if bl := sec(KeyBlocking); len(bl.Items) != 1 || *p.patches[KeyBlocking].BlockMode != "nxdomain" {
		t.Errorf("blocking: %+v", bl)
	}
	if ac := sec(KeyAccess); len(ac.Items) != 1 || ac.Default || len(ac.Skipped) != 2 {
		t.Errorf("access: %+v", ac)
	}

	devs := sec(KeyDevices)
	for _, want := range []string{"Kid tablet", "Work laptop", "tv"} {
		if !has(devs.Items, want) {
			t.Errorf("devices missing %q: %v", want, texts(devs.Items))
		}
	}
	if has(devs.Items, "work") && !has(devs.Items, "Work laptop") || len(devs.Items) != 3 {
		t.Errorf("devices: %v (the MAC client takes its lease's address, so the lease isn't added again)", texts(devs.Items))
	}
	if len(devs.Have) != 1 {
		t.Errorf("devices have: %v", devs.Have)
	}

	groups := sec(KeyGroups)
	if len(p.Groups) != 2 || len(groups.Items) != 2 {
		t.Fatalf("groups: %+v", p.Groups)
	}
	kid, work := p.Groups[0], p.Groups[1]
	if kid.Name != "Kid tablet" || !contains(kid.Rules, "||youtube.com^") || contains(kid.Rules, "||tiktok.com^") || !contains(kid.Rules, "/yt-regex/") {
		t.Errorf("kid group: %+v", kid)
	}
	if !work.SkipBlocklists || len(work.Rules) != 0 {
		t.Errorf("work group: %+v", work)
	}

	other := sec(KeyOther)
	for _, want := range []string{"DHCP", "Safe browsing", "Safe search", "1 device name"} {
		if !has(other.Skipped, want) {
			t.Errorf("other missing %q: %v", want, texts(other.Skipped))
		}
	}

	// Leaving items out.
	p2 := Build(s, st, eff, map[string]bool{"lists:https://example.com/old.txt": true, "groups:Kid tablet": true})
	if len(p2.Section(KeyLists).Items) != 1 || len(p2.Groups) != 1 {
		t.Errorf("exclude: lists %v groups %v", texts(p2.Section(KeyLists).Items), p2.Groups)
	}
	patch := p2.Patch(map[string]bool{KeyLists: true, KeyBlocking: true})
	if patch.Lists == nil || patch.BlockMode == nil || patch.Rules != nil || patch.UpstreamServers != nil {
		t.Errorf("patch: %+v", patch)
	}
}

func TestUpstreamNotDefaultWhenPlain(t *testing.T) {
	s := &Snapshot{DNS: DNSInfo{Upstreams: []string{"8.8.8.8", "1.1.1.1:53 9.9.9.9", "[2606:4700::1111]:53", "dns.example"}}}
	st, eff := testState()
	p := Build(s, st, eff, nil)
	up := p.Section(KeyUpstream)
	want := []string{"udp://8.8.8.8:53", "udp://1.1.1.1:53", "udp://9.9.9.9:53", "udp://[2606:4700::1111]:53", "udp://dns.example"}
	if got := texts(up.Items); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("upstreams: %v", got)
	}
	if up.Default {
		t.Error("unencrypted upstreams ticked by default")
	}
	cfg := eff
	cfg.Upstream.Servers = p.patches[KeyUpstream].UpstreamServers
	if err := cfg.Validate(); err != nil {
		t.Errorf("mapped upstreams don't validate: %v", err)
	}
}

func TestRecordConflicts(t *testing.T) {
	s := &Snapshot{Rewrites: []Rewrite{{Domain: "a.lan", Answer: "b.lan"}, {Domain: "a.lan", Answer: "192.168.1.2"}, {Domain: "bad name", Answer: "1.2.3.4"}}}
	st, eff := testState()
	eff.DNS.Records = []config.Record{{Name: "a.lan", Value: "b.lan"}}
	p := Build(s, st, eff, nil)
	r := p.Section(KeyRecords)
	if len(r.Items) != 0 || len(r.Have) != 1 || len(r.Skipped) != 2 {
		t.Errorf("records: items %v have %v skipped %v", r.Items, r.Have, r.Skipped)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
