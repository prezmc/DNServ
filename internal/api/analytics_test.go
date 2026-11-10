package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/prezmc/dnserve/internal/analytics"
	"github.com/prezmc/dnserve/internal/filter"
	"github.com/prezmc/dnserve/internal/querylog"
	"github.com/prezmc/dnserve/internal/threat"
	"github.com/prezmc/dnserve/internal/virustotal"
)

func TestAnalytics(t *testing.T) {
	e := newEnv(t)
	e.now = time.Now() // the history store dates queries by wall clock
	hs, err := analytics.Open(filepath.Join(t.TempDir(), "h.db"), func() string { return "alpha" }, 30, 90, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })
	e.api.Analytics = hs
	e.api.LookupName = func(_ context.Context, a netip.Addr) string {
		if a.String() == "192.168.1.20" {
			return "phone"
		}
		return ""
	}
	e.api.CheckDomain = func(name string) filter.Match {
		if name == "ads.example.com" {
			return filter.Match{Blocked: true, Rule: filter.Rule{Domain: name, Kind: filter.Suffix}, Source: "Test list"}
		}
		return filter.Match{}
	}
	admin, _ := e.setupAdmin()

	tv, phone := netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("192.168.1.20")
	at := e.now.Add(-10 * time.Minute)
	for i := range 6 {
		hs.Record(querylog.Entry{Time: at.Add(time.Duration(i) * time.Second), Client: tv, Name: "ads.example.com", Type: "A", Result: querylog.Blocked, Rule: "||ads.example.com^", List: "Test list"})
	}
	for i := range 4 {
		hs.Record(querylog.Entry{Time: at.Add(time.Duration(i) * time.Second), Client: phone, Name: "news.example.org", Type: "AAAA", Result: querylog.Cached})
	}
	hs.Flush()
	admin.want(201, "POST", "/api/v1/devices", map[string]any{"name": "Living room TV", "addrs": []string{"192.168.1.10"}}, nil)

	var sum struct {
		Counts  analytics.Counts
		Devices int
		Series  []analytics.Point
		Nodes   []nodeAnswer
	}
	for _, rg := range []string{"1h", "24h", "7d", "30d", "90d"} {
		admin.want(200, "GET", "/api/v1/analytics/summary?range="+rg, nil, &sum)
		if sum.Counts.Total != 10 || sum.Counts.Blocked != 6 || sum.Counts.Cached != 4 || sum.Devices != 2 || len(sum.Series) == 0 {
			t.Fatalf("%s summary = %+v", rg, sum)
		}
	}
	if len(sum.Nodes) != 1 || !sum.Nodes[0].OK || sum.Nodes[0].Counts == nil || sum.Nodes[0].Counts.Total != 10 || sum.Nodes[0].Counts.Blocked != 6 {
		t.Fatalf("nodes = %+v", sum.Nodes)
	}
	admin.want(400, "GET", "/api/v1/analytics/summary?range=1y", nil, nil)

	var top struct{ Rows []topRow }
	admin.want(200, "GET", "/api/v1/analytics/top?by=blocked", nil, &top)
	if len(top.Rows) != 1 || top.Rows[0].Key != "ads.example.com" || top.Rows[0].List != "Test list" || top.Rows[0].Now == nil || !top.Rows[0].Now.Blocked {
		t.Fatalf("top blocked = %+v", top.Rows)
	}
	admin.want(200, "GET", "/api/v1/analytics/top?by=clients", nil, &top)
	if len(top.Rows) != 2 || top.Rows[0].Label != "Living room TV" || top.Rows[0].DeviceID == "" || top.Rows[0].Total != 6 {
		t.Fatalf("top clients = %+v", top.Rows)
	}
	admin.want(400, "GET", "/api/v1/analytics/top?by=nonsense", nil, nil)

	var q struct {
		Queries     []analytics.Entry
		DeviceNames map[string]string `json:"device_names"`
	}
	admin.want(200, "GET", "/api/v1/analytics/queries?search=news&client=192.168.1.20", nil, &q)
	if len(q.Queries) != 4 || q.Queries[0].Node != "alpha" {
		t.Fatalf("search = %+v", q.Queries)
	}
	admin.want(200, "GET", "/api/v1/analytics/queries?client="+top.Rows[0].DeviceID, nil, &q)
	if len(q.Queries) != 6 || q.DeviceNames["192.168.1.10"] != "Living room TV" {
		t.Fatalf("by device = %+v %v", len(q.Queries), q.DeviceNames)
	}

	var dom struct {
		Counts   analytics.Counts
		CaughtBy map[string]string `json:"caught_by"`
		Devices  []topRow
	}
	admin.want(200, "GET", "/api/v1/analytics/domain?name=Ads.Example.com", nil, &dom)
	if dom.Counts.Blocked != 6 || dom.CaughtBy["list"] != "Test list" || len(dom.Devices) != 1 {
		t.Fatalf("domain = %+v", dom)
	}

	// CSV export, with formula-looking cells defused.
	req, _ := http.NewRequest("GET", e.srv.URL+"/api/v1/analytics/export?range=24h", nil)
	resp, err := admin.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(resp.Body).ReadAll()
	resp.Body.Close()
	if err != nil || len(recs) != 11 || recs[0][0] != "time" {
		t.Fatalf("export: %v rows, %v", len(recs), err)
	}

	// Totals only: a token with just dashboard.view sees totals and top
	// domains, but no devices or individual queries.
	var tok struct{ Token string }
	admin.want(201, "POST", "/api/v1/tokens", map[string]any{"name": "wall display", "perms": []string{"dashboard.view"}}, &tok)
	v := e.client()
	v.token = tok.Token
	v.want(200, "GET", "/api/v1/analytics/summary", nil, &sum)
	v.want(200, "GET", "/api/v1/analytics/top?by=domains", nil, nil)
	v.want(403, "GET", "/api/v1/analytics/top?by=clients", nil, nil)
	v.want(403, "GET", "/api/v1/analytics/summary?client=192.168.1.10", nil, nil)
	v.want(403, "GET", "/api/v1/analytics/queries", nil, nil)
	v.want(403, "GET", "/api/v1/analytics/export", nil, nil)
	var vdom map[string]any
	v.want(200, "GET", "/api/v1/analytics/domain?name=ads.example.com", nil, &vdom)
	if _, ok := vdom["devices"]; ok {
		t.Fatal("devices shown without querylog.view")
	}

	// Export needs both permissions.
	admin.want(201, "POST", "/api/v1/tokens", map[string]any{"name": "export only", "perms": []string{"data.export"}}, &tok)
	v.token = tok.Token
	v.want(403, "GET", "/api/v1/analytics/export", nil, nil)

	// How long history is kept is an admin setting.
	admin.want(201, "POST", "/api/v1/tokens", map[string]any{"name": "net", "perms": []string{"network.manage"}}, &tok)
	v.token = tok.Token
	v.want(403, "PATCH", "/api/v1/settings", map[string]any{"history_days": 7}, nil)
	admin.want(400, "PATCH", "/api/v1/settings", map[string]any{"history_days": 9999}, nil)
	admin.want(200, "PATCH", "/api/v1/settings", map[string]any{"history_days": 7, "stats_days": 30}, nil)
	if d := e.api.Effective().History; d.Days != 7 || d.StatsDays != 30 {
		t.Fatalf("history settings = %+v", d)
	}
	if !strings.Contains(e.api.Store.State().Audit[len(e.api.Store.State().Audit)-1].Summary, "history_days") {
		t.Fatal("history change not audited")
	}
}

func TestRiskyDomainsAndTypes(t *testing.T) {
	e := newEnv(t)
	e.now = time.Now()
	hs, err := analytics.Open(filepath.Join(t.TempDir(), "h.db"), func() string { return "alpha" }, 30, 90, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })
	e.api.Analytics = hs
	dir := t.TempDir()
	for n, c := range map[string]string{
		"urlhaus.txt": "127.0.0.1 malware.example\n", "threatfox.txt": "", "phishingarmy.txt": "login-bank.example\n", "hagezi-tif.txt": "",
		"feodo.txt": "203.0.113.66\n", "drop4.txt": "", "drop6.txt": "",
		"trackers.json":  `{"categories":{"4":"advertising"},"trackers":{"dc":{"name":"DoubleClick","categoryId":4,"companyId":"google"}},"trackerDomains":{"doubleclick.net":"dc"}}`,
		"companies.json": `{"companies":{"google":{"name":"Google"}}}`,
	} {
		os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600)
	}
	in := threat.New(dir, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	in.SetEnabled(true)
	in.Refresh(context.Background(), false)
	e.api.Intel = in
	hs.SetChecker(in.CheckAnswer)
	admin, _ := e.setupAdmin()
	c2, _ := dns.NewRR("innocent-looking.example. 60 IN A 203.0.113.66")
	hs.Record(querylog.Entry{Time: e.now.Add(-time.Minute), Client: netip.MustParseAddr("192.168.1.11"), Name: "innocent-looking.example", Type: "A", Result: querylog.Answered, Answer: []dns.RR{c2}})

	ip := netip.MustParseAddr("192.168.1.10")
	for i, n := range []string{"malware.example", "malware.example", "login-bank.example", "doubleclick.net", "example.com"} {
		hs.Record(querylog.Entry{Time: e.now.Add(-time.Duration(i+1) * time.Minute), Client: ip, Name: n, Type: "A", Result: querylog.Answered})
	}
	hs.Flush()

	var risky struct {
		Rows    []topRow
		Domains int
		Queries int64
		Feeds   bool
	}
	admin.want(200, "GET", "/api/v1/analytics/risky?range=24h", nil, &risky)
	if risky.Domains != 3 || risky.Queries != 4 || !risky.Feeds || risky.Rows[0].Key != "malware.example" || risky.Rows[0].Risk.Level != "high" {
		t.Fatalf("risky = %+v", risky)
	}
	var flagged *topRow
	for i := range risky.Rows {
		if risky.Rows[i].Key == "innocent-looking.example" {
			flagged = &risky.Rows[i]
		}
	}
	if flagged == nil || flagged.Risk.Score != 90 || !strings.Contains(strings.Join(flagged.Risk.Reasons, " "), "botnet") {
		t.Fatalf("answer-flagged domain = %+v", flagged)
	}
	var dom struct {
		Risk    threat.Risk
		Answers []analytics.Answer
	}
	admin.want(200, "GET", "/api/v1/analytics/domain?name=innocent-looking.example", nil, &dom)
	if dom.Risk.Score != 90 || len(dom.Answers) != 1 || dom.Answers[0].IPs[0] != "203.0.113.66" {
		t.Fatalf("domain = %+v", dom)
	}
	var top struct{ Rows []topRow }
	admin.want(200, "GET", "/api/v1/analytics/top?by=domains", nil, &top)
	for _, r := range top.Rows {
		if r.Key == "doubleclick.net" && (r.Type == nil || r.Type.Company != "Google" || r.Type.Category != "Advertising") {
			t.Fatalf("type = %+v", r.Type)
		}
		if r.Key == "example.com" && (r.Risk != nil || r.Type != nil) {
			t.Fatalf("example.com = %+v", r)
		}
	}
	var q struct{ Risk map[string]threat.Risk }
	admin.want(200, "GET", "/api/v1/analytics/queries", nil, &q)
	if len(q.Risk) != 3 || q.Risk["login-bank.example"].Level != "high" || q.Risk["innocent-looking.example"].Score != 90 {
		t.Fatalf("query log risk = %+v", q.Risk)
	}

	// Trusting a domain clears its score; it's a lists setting.
	admin.want(400, "PATCH", "/api/v1/settings", map[string]any{"trusted_domains": []string{"not a domain"}}, nil)
	admin.want(200, "PATCH", "/api/v1/settings", map[string]any{"trusted_domains": []string{"Malware.Example"}}, nil)
	if got := e.api.Effective().Analytics.TrustedDomains; len(got) != 1 || got[0] != "malware.example" {
		t.Fatalf("trusted = %v", got)
	}
	var st struct {
		Enabled bool
		Sources []threat.SourceStatus
	}
	admin.want(200, "GET", "/api/v1/analytics/intel", nil, &st)
	if !st.Enabled || len(st.Sources) != 8 {
		t.Fatalf("intel = %+v", st)
	}
}

func TestAlsoOn(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin()
	var out struct {
		Name  string
		Lists []filter.ListHit
	}
	admin.want(200, "GET", "/api/v1/analytics/alsoon?name=Ads.Example.com", nil, &out)
	if out.Name != "ads.example.com" || out.Lists == nil || len(out.Lists) != 0 {
		t.Fatalf("no lists: %+v", out)
	}
	e.api.AlsoOn = func(_ context.Context, name string) []filter.ListHit {
		return []filter.ListHit{{List: "One", Rule: "||" + name + "^"}, {List: "Two", Rule: "0.0.0.0 " + name}}
	}
	admin.want(200, "GET", "/api/v1/analytics/alsoon?name=ads.example.com", nil, &out)
	if len(out.Lists) != 2 || out.Lists[1].List != "Two" {
		t.Fatalf("lists = %+v", out)
	}
	admin.want(400, "GET", "/api/v1/analytics/alsoon?name=", nil, nil)
}

func TestVirusTotal(t *testing.T) {
	e := newEnv(t)
	vt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "secret-key-123" {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":3,"harmless":70}}}}`))
	}))
	defer vt.Close()
	c := virustotal.New(func() string { return e.api.Store.State().VirusTotalKey })
	c.Base = vt.URL
	e.api.VirusTotal = c
	admin, _ := e.setupAdmin()

	var st struct{ Configured bool }
	admin.want(200, "GET", "/api/v1/virustotal", nil, &st)
	if st.Configured {
		t.Fatal("configured before a key was set")
	}
	admin.want(409, "POST", "/api/v1/analytics/virustotal?name=bad.example", nil, nil)
	admin.want(400, "PUT", "/api/v1/virustotal", map[string]string{"key": "has space"}, nil)
	admin.want(200, "PUT", "/api/v1/virustotal", map[string]string{"key": "secret-key-123"}, nil)
	admin.want(200, "GET", "/api/v1/virustotal", nil, &st)
	if !st.Configured {
		t.Fatal("not configured")
	}
	var out struct {
		Report virustotal.Report
		Cached bool
	}
	admin.want(200, "POST", "/api/v1/analytics/virustotal?name=Bad.Example", nil, &out)
	if !out.Report.Found || out.Report.Malicious != 3 || out.Report.Name != "bad.example" || out.Cached {
		t.Fatalf("report = %+v", out)
	}
	// The key never comes back: not in settings, their history, or the audit log.
	for _, path := range []string{"/api/v1/settings", "/api/v1/config/versions", "/api/v1/audit"} {
		var raw json.RawMessage
		admin.want(200, "GET", path, nil, &raw)
		if strings.Contains(string(raw), "secret-key-123") || len(raw) == 0 {
			t.Fatalf("%s shows the key", path)
		}
	}
}
