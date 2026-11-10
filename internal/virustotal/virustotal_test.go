package virustotal

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestLookup(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("x-apikey") != "k1" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/domains/bad.example":
			w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":7,"suspicious":1,"harmless":60,"undetected":20},"reputation":-12,"categories":{"X":"phishing"},"last_analysis_date":1700000000}}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	key := "k1"
	now := time.Unix(1800000000, 0)
	c := New(func() string { return key })
	c.Base, c.Now = srv.URL, func() time.Time { return now }

	r, cached, err := c.Lookup(context.Background(), "bad.example")
	if err != nil || cached || !r.Found || r.Malicious != 7 || r.Reputation != -12 || r.Categories["X"] != "phishing" || r.Analyzed.Unix() != 1700000000 {
		t.Fatalf("report = %+v %v %v", r, cached, err)
	}
	if r, cached, _ = c.Lookup(context.Background(), "bad.example"); !cached || r.Malicious != 7 || hits.Load() != 1 {
		t.Fatalf("not cached: %+v hits=%d", r, hits.Load())
	}
	if r, _, err = c.Lookup(context.Background(), "unknown.example"); err != nil || r.Found {
		t.Fatalf("unknown = %+v %v", r, err)
	}
	// Four lookups a minute: two used, two left.
	c.Lookup(context.Background(), "a.example")
	c.Lookup(context.Background(), "b.example")
	if _, _, err = c.Lookup(context.Background(), "c.example"); !errors.Is(err, ErrBusy) {
		t.Fatalf("limit: %v", err)
	}
	now = now.Add(61 * time.Second)
	key = "wrong"
	if _, _, err = c.Lookup(context.Background(), "c.example"); !errors.Is(err, ErrBadKey) {
		t.Fatalf("bad key: %v", err)
	}
	key = ""
	if _, _, err = c.Lookup(context.Background(), "c.example"); !errors.Is(err, ErrNoKey) {
		t.Fatalf("no key: %v", err)
	}
	// After a day the cached report is fetched again.
	key, now = "k1", now.Add(25*time.Hour)
	before := hits.Load()
	if _, cached, _ = c.Lookup(context.Background(), "bad.example"); cached || hits.Load() != before+1 {
		t.Fatal("stale report served")
	}
}
