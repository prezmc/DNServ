package usage

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRanges(t *testing.T) {
	for n, want := range map[int64]string{0: "0", 1: "1-10", 10: "1-10", 11: "11-50", 100: "51-100", 999: "251-1000", 5000: "1000+"} {
		if got := Range(n); got != want {
			t.Errorf("Range(%d) = %q, want %q", n, got, want)
		}
	}
	for n, want := range map[int64]string{0: "0", 500: "<1k", 25_000: "10k-100k", 2_000_000: "1M+"} {
		if got := DayRange(n); got != want {
			t.Errorf("DayRange(%d) = %q, want %q", n, got, want)
		}
	}
	if w := Week(time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)); w != "2026-W46" {
		t.Errorf("Week = %q", w)
	}
}

func TestBuildKeepsOnlyKnownFeatures(t *testing.T) {
	r := Build(Stats{Servers: 2, Devices: 37, Lookups7d: 140_000, Blocked7d: 14_000, CacheHit: 0.7123, P50: 0.4321,
		Features: []string{"https", "my-secret-domain.example"}}, "1.2.0", "", "2026-W46", "abc")
	if r.Devices != "11-50" || r.LookupsPerDay != "10k-100k" || r.BlockedPct != 10 || r.CacheHitPct != 71.2 || r.AnswerMsP50 != 0.43 || r.Channel != "stable" {
		t.Fatalf("report = %+v", r)
	}
	if len(r.Features) != 1 || r.Features[0] != "https" {
		t.Fatalf("features = %v", r.Features)
	}
}

func TestTickSendsOncePerWeek(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		got = append(got, m)
	}))
	defer srv.Close()
	sent := ""
	allowed, leader := false, true
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	s := &Sender{
		URL: srv.URL, Version: "1.0.0",
		IsLeader: func() bool { return leader },
		Allowed:  func() bool { return allowed },
		SentWeek: func() string { return sent },
		Stats:    func(context.Context) (Stats, error) { return Stats{Servers: 1}, nil },
		Sent:     func(week string, _ []byte) error { sent = week; return nil },
		Now:      func() time.Time { return now },
	}
	ctx := context.Background()
	if err := s.Tick(ctx); err != nil || len(got) != 0 {
		t.Fatalf("sent without consent: %v %d", err, len(got))
	}
	allowed = true
	leader = false
	if _ = s.Tick(ctx); len(got) != 0 {
		t.Fatal("a follower sent")
	}
	leader = true
	for range 3 {
		if err := s.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(got) != 1 || sent != "2026-W46" {
		t.Fatalf("sent %d times, week %q", len(got), sent)
	}
	for k := range got[0] {
		if strings.Contains(k, "ip") || strings.Contains(k, "host") || strings.Contains(k, "name") {
			t.Errorf("report has field %q", k)
		}
	}
	now = now.Add(7 * 24 * time.Hour)
	_ = s.Tick(ctx)
	if len(got) != 2 || got[0]["report_id"] == got[1]["report_id"] {
		t.Fatalf("next week: %d sends, ids %v %v", len(got), got[0]["report_id"], got[1]["report_id"])
	}
	s.Off = true
	now = now.Add(7 * 24 * time.Hour)
	_ = s.Tick(ctx)
	if len(got) != 2 {
		t.Fatal("sent with DNSERV_USAGE_REPORT=off")
	}
}
