package geo

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const sample = `1.0.0.0,1.0.0.255,AU
1.0.1.0,1.0.3.255,CN
1.0.4.0,1.0.7.255,AU
1.0.8.0,1.0.8.255,AU
5.0.0.0,5.0.0.255,"RU"
9.9.9.0,9.9.9.255,ZZ
"2001:200::","2001:200:ffff:ffff:ffff:ffff:ffff:ffff",JP
2a00:1450::,2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff,US
`

func TestParseLookup(t *testing.T) {
	tb, err := parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"1.0.0.1": "AU", "1.0.2.9": "CN", "1.0.5.1": "AU", "1.0.8.255": "AU", "1.0.9.0": "",
		"0.255.255.255": "", "5.0.0.200": "RU", "4.255.255.255": "", "9.9.9.9": "", "200.1.1.1": "",
		"2001:200::1": "JP", "2a00:1450:4001::1": "US", "2a00:1451::": "", "::ffff:1.0.2.1": "CN", "2000::1": "",
	}
	for in, want := range cases {
		if got := tb.lookup(netip.MustParseAddr(in)); got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	io.WriteString(w, s)
	w.Close()
	return b.Bytes()
}

func TestRefresh(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.Contains(r.URL.Path, "2026-11") {
			http.NotFound(w, r) // not out yet: falls back to last month
			return
		}
		w.Write(gz(sample))
	}))
	defer srv.Close()
	dir := t.TempDir()
	d := New(dir, srv.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.now = func() time.Time { return time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC) }
	d.url = func(m time.Time) string { return srv.URL + "/" + m.Format("2006-01") + ".csv.gz" }
	loaded := 0
	d.SetOnLoad(func() { loaded++ })

	d.Refresh(context.Background()) // off: nothing
	if d.Ready() || hits.Load() != 0 {
		t.Fatal("loaded while off")
	}
	d.SetEnabled(true)
	d.Refresh(context.Background())
	if !d.Ready() || d.Country(netip.MustParseAddr("5.0.0.1")) != "RU" || loaded != 1 {
		t.Fatalf("not loaded: %+v", d.Status())
	}
	if d.Country(netip.MustParseAddr("192.168.1.1")) != "" {
		t.Fatal("private address got a country")
	}
	if hits.Load() != 2 {
		t.Fatalf("hits %d, want 2 (this month, then last)", hits.Load())
	}
	// Fresh copy: no download, no reload.
	d.Refresh(context.Background())
	if hits.Load() != 2 || loaded != 1 {
		t.Fatalf("refetched a fresh copy: hits %d loads %d", hits.Load(), loaded)
	}
	// A broken download keeps the old copy.
	path := filepath.Join(dir, fileName)
	old := time.Now().Add(-40 * 24 * time.Hour)
	os.Chtimes(path, old, old)
	d.now = time.Now
	d.url = func(time.Time) string { return srv.URL + "/2026-11" }
	d.Refresh(context.Background())
	if !d.Ready() || d.Status().Error == "" {
		t.Fatalf("status %+v", d.Status())
	}
	// Off: freed and removed.
	d.SetEnabled(false)
	d.Refresh(context.Background())
	if d.Ready() {
		t.Fatal("still loaded")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("download not removed")
	}
}

func BenchmarkCountry(b *testing.B) {
	var sb strings.Builder
	// About as many ranges as the real file.
	for i := range 400000 {
		a := netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 0})
		e := netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 255})
		cc := []string{"AU", "US", "DE"}[i%3]
		sb.WriteString(a.String() + "," + e.String() + "," + cc + "\n")
	}
	tb, err := parse(strings.NewReader(sb.String()))
	if err != nil {
		b.Fatal(err)
	}
	a := netip.MustParseAddr("3.4.5.6")
	b.ResetTimer()
	for b.Loop() {
		tb.lookup(a)
	}
}
