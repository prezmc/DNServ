// Package usage sends the weekly anonymous usage summary, when an admin
// has said yes to it.
//
// One summary a week per cluster, sent by the leader. It holds counts
// rounded into ranges, percentages and which features are on: never a
// domain, an address, a name, a list or server address, or any setting's
// value. It carries no install ID: a random report ID, new each week,
// only lets the receiver drop a retry it already has. docs/usage-stats.md
// lists every field; change it, and bump Schema, when the report grows.
package usage

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"runtime"
	"sync"
	"time"
)

// Schema is the report's version. Admins who agreed to an older one are
// asked again before a summary with more in it is sent.
const Schema = 1

// DefaultURL is where summaries go: a small receiver whose code is in
// deploy/stats-worker. It keeps no IP addresses.
const DefaultURL = "https://stats.dnserv.dev/v1/report"

// Report is the whole summary. Nothing else is sent.
type Report struct {
	Schema   int    `json:"schema"`
	ReportID string `json:"report_id"`
	Week     string `json:"week"`
	Version  string `json:"version"`
	Channel  string `json:"channel"`
	Arch     string `json:"arch"`
	// Servers and Witnesses: how many of each the cluster has.
	Servers   int `json:"servers"`
	Witnesses int `json:"witnesses"`
	// UpstreamMode: forward, recursive or tunnel.
	UpstreamMode string `json:"upstream_mode"`
	// Devices and LookupsPerDay are ranges such as "11-50", over the
	// last 7 days.
	Devices       string `json:"devices"`
	LookupsPerDay string `json:"lookups_per_day"`
	// Answer times over the last 7 days, in milliseconds.
	AnswerMsP50 float64 `json:"answer_ms_p50"`
	AnswerMsP95 float64 `json:"answer_ms_p95"`
	// Percentages of all lookups over the last 7 days.
	CacheHitPct float64 `json:"cache_hit_pct"`
	BlockedPct  float64 `json:"blocked_pct"`
	FailedPct   float64 `json:"failed_pct"`
	// Lists is how many blocklists are on.
	Lists int `json:"lists"`
	// Features are the names of features in use, from a fixed set.
	Features []string `json:"features"`
}

// Stats are the parts of a report that come from the cluster.
type Stats struct {
	Servers, Witnesses int
	UpstreamMode       string
	Devices            int
	Lookups7d          int64
	Blocked7d          int64
	Failed7d           int64
	CacheHit           float64 // 0-1, of lookups that needed resolving
	P50, P95           float64
	Lists              int
	Features           []string
}

// Features is every feature name a report may hold.
var Features = []string{
	"https", "backups", "backups_s3", "backups_smb", "passkeys", "groups",
	"schedules", "blocked_services", "safe_search", "block_bypass",
	"local_names", "query_history", "threat_feeds", "auto_updates",
}

// Week is the ISO week of t, like "2026-W46".
func Week(t time.Time) string {
	y, w := t.ISOWeek()
	return fmt.Sprintf("%d-W%02d", y, w)
}

// Range puts n in a range, so a report never holds an exact count.
func Range(n int64) string {
	bounds := []struct {
		hi    int64
		label string
	}{
		{0, "0"}, {10, "1-10"}, {50, "11-50"}, {100, "51-100"}, {250, "101-250"},
		{1000, "251-1000"},
	}
	for _, b := range bounds {
		if n <= b.hi {
			return b.label
		}
	}
	return "1000+"
}

// DayRange puts lookups per day in a range.
func DayRange(n int64) string {
	switch {
	case n <= 0:
		return "0"
	case n < 1_000:
		return "<1k"
	case n < 10_000:
		return "1k-10k"
	case n < 100_000:
		return "10k-100k"
	case n < 1_000_000:
		return "100k-1M"
	}
	return "1M+"
}

// Build makes a report from the cluster's stats.
func Build(s Stats, version, channel, week, id string) Report {
	if channel == "" {
		channel = "stable"
	}
	pct := func(part, all int64) float64 {
		if all <= 0 {
			return 0
		}
		return round(100*float64(part)/float64(all), 1)
	}
	allowed := map[string]bool{}
	for _, f := range Features {
		allowed[f] = true
	}
	feats := []string{}
	for _, f := range s.Features {
		if allowed[f] {
			feats = append(feats, f)
		}
	}
	return Report{
		Schema: Schema, ReportID: id, Week: week,
		Version: version, Channel: channel, Arch: runtime.GOARCH,
		Servers: s.Servers, Witnesses: s.Witnesses, UpstreamMode: s.UpstreamMode,
		Devices: Range(int64(s.Devices)), LookupsPerDay: DayRange(s.Lookups7d / 7),
		AnswerMsP50: round(s.P50, 2), AnswerMsP95: round(s.P95, 1),
		CacheHitPct: round(100*s.CacheHit, 1),
		BlockedPct:  pct(s.Blocked7d, s.Lookups7d), FailedPct: pct(s.Failed7d, s.Lookups7d),
		Lists: s.Lists, Features: feats,
	}
}

func round(v float64, places int) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

// Sender sends a summary once a week from the leader.
type Sender struct {
	URL      string
	Off      bool // DNSERV_USAGE_REPORT=off: never send, whatever the choice
	Version  string
	Channel  func() string
	IsLeader func() bool
	// Allowed says the admin agreed to this Schema; SentWeek is the
	// last week a summary went out.
	Allowed  func() bool
	SentWeek func() string
	Stats    func(ctx context.Context) (Stats, error)
	// Sent records the summary in the cluster state (and audit log).
	Sent   func(week string, report []byte) error
	Client *http.Client
	Log    *slog.Logger
	Now    func() time.Time

	mu     sync.Mutex
	idWeek string
	id     string
}

// Preview is the summary as it would be sent now.
func (s *Sender) Preview(ctx context.Context) (Report, error) {
	st, err := s.Stats(ctx)
	if err != nil {
		return Report{}, err
	}
	week := Week(s.now())
	return Build(st, s.Version, s.channel(), week, s.reportID(week)), nil
}

func (s *Sender) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Sender) channel() string {
	if s.Channel == nil {
		return ""
	}
	return s.Channel()
}

// reportID is random and new each week, the same for retries in a week.
func (s *Sender) reportID(week string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.idWeek != week {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		s.idWeek, s.id = week, hex.EncodeToString(b)
	}
	return s.id
}

// Run checks every hour whether this week's summary is due.
func (s *Sender) Run(ctx context.Context) {
	if s.Off {
		return
	}
	// Not straight after a start, so a restart loop never sends twice
	// before the first one is recorded.
	t := time.NewTimer(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := s.Tick(ctx); err != nil && s.Log != nil {
			s.Log.Info("weekly usage summary not sent; will try again in an hour", "err", err)
		}
		t.Reset(time.Hour)
	}
}

// Tick sends this week's summary if it is due. It returns nil when there
// was nothing to do.
func (s *Sender) Tick(ctx context.Context) error {
	if s.Off || !s.IsLeader() || !s.Allowed() {
		return nil
	}
	week := Week(s.now())
	if s.SentWeek() == week {
		return nil
	}
	rep, err := s.Preview(ctx)
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}
	body, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	if err := s.post(ctx, body); err != nil {
		return err
	}
	if err := s.Sent(week, body); err != nil {
		return fmt.Errorf("sent, but couldn't record it: %w", err)
	}
	if s.Log != nil {
		s.Log.Info("sent the weekly anonymous usage summary", "week", week)
	}
	return nil
}

func (s *Sender) post(ctx context.Context, body []byte) error {
	url := s.URL
	if url == "" {
		url = DefaultURL
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "DNServ")
	c := s.Client
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("receiver answered %s", resp.Status)
	}
	return nil
}
