// Command dnsbench load-tests a DNS server: it sends a realistic mix of
// queries from many concurrent clients and reports throughput, latency
// percentiles and answer codes.
//
//	dnsbench -server 192.168.1.10:53 -c 50 -d 30s
//
// Cache hits dominate real home traffic, so by default most queries repeat
// a small set of popular names. -miss sets the share of queries for names
// never seen before (random labels under real domains), which exercises
// the upstream path; -blocked sets the share aimed at blocked names.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

var popular = []string{
	"google.com", "www.google.com", "youtube.com", "www.youtube.com", "facebook.com", "instagram.com",
	"apple.com", "icloud.com", "netflix.com", "amazon.com", "microsoft.com", "wikipedia.org",
	"en.wikipedia.org", "github.com", "cloudflare.com", "whatsapp.net", "spotify.com", "bbc.co.uk",
	"reddit.com", "twitch.tv", "zoom.us", "office.com", "outlook.com", "linkedin.com",
}

var blockedNames = []string{
	"doubleclick.net", "ad.doubleclick.net", "googleadservices.com", "pagead2.googlesyndication.com",
	"app-measurement.com", "ads.tiktok.com", "graph.facebook.com", "ads.yahoo.com",
}

type result struct {
	lat   time.Duration
	rcode int // -1 = error/timeout
}

// firstErr keeps one example error for the report.
var firstErr struct {
	sync.Once
	msg string
}

func main() {
	server := flag.String("server", "127.0.0.1:53", "DNS server host:port")
	conc := flag.Int("c", 20, "concurrent clients")
	dur := flag.Duration("d", 10*time.Second, "test duration")
	rate := flag.Int("qps", 0, "target queries per second across all clients (0 = as fast as possible)")
	miss := flag.Float64("miss", 0.05, "share of queries for never-seen names (cache misses)")
	blocked := flag.Float64("blocked", 0.1, "share of queries for blocked names")
	names := flag.String("names", "", "file of names to use instead of the built-in popular set (one per line)")
	tcp := flag.Bool("tcp", false, "use TCP instead of UDP")
	timeout := flag.Duration("timeout", 2*time.Second, "per-query timeout")
	asJSON := flag.Bool("json", false, "print the report as JSON")
	flag.Parse()

	pool := popular
	if *names != "" {
		var err error
		if pool, err = readNames(*names); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	network := "udp"
	if *tcp {
		network = "tcp"
	}

	var (
		mu      sync.Mutex
		results = make([]result, 0, 1<<16)
		stop    = make(chan struct{})
		wg      sync.WaitGroup
	)
	var tick <-chan time.Time
	if *rate > 0 {
		t := time.NewTicker(time.Second / time.Duration(*rate))
		defer t.Stop()
		tick = t.C
	}
	start := time.Now()
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func(seed uint64) {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(seed, uint64(time.Now().UnixNano())))
			local := make([]result, 0, 4096)
			c := &dns.Client{Net: network, Timeout: *timeout}
			var conn *dns.Conn
			for {
				select {
				case <-stop:
					mu.Lock()
					results = append(results, local...)
					mu.Unlock()
					if conn != nil {
						conn.Close()
					}
					return
				default:
				}
				if tick != nil {
					select {
					case <-tick:
					case <-stop:
						continue
					}
				}
				name := pick(rng, pool, *miss, *blocked)
				m := new(dns.Msg)
				qt := dns.TypeA
				if rng.IntN(3) == 0 {
					qt = dns.TypeAAAA
				}
				m.SetQuestion(dns.Fqdn(name), qt)
				m.RecursionDesired = true
				if conn == nil {
					var err error
					if conn, err = c.Dial(*server); err != nil {
						local = append(local, result{rcode: -1})
						time.Sleep(10 * time.Millisecond)
						continue
					}
				}
				r, rtt, err := c.ExchangeWithConn(m, conn)
				if err != nil && *tcp && (errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET)) {
					// Servers close TCP connections after a number of
					// queries (128 by default); real clients reconnect.
					conn.Close()
					if conn, err = c.Dial(*server); err == nil {
						r, rtt, err = c.ExchangeWithConn(m, conn)
					}
				}
				if err != nil {
					firstErr.Do(func() { firstErr.msg = err.Error() })
					local = append(local, result{lat: rtt, rcode: -1})
					if conn != nil {
						conn.Close() // a lost UDP reply can leave a late answer queued
					}
					conn = nil
					time.Sleep(10 * time.Millisecond) // don't spin on a refused port
					continue
				}
				local = append(local, result{lat: rtt, rcode: r.Rcode})
			}
		}(uint64(i))
	}
	time.Sleep(*dur)
	close(stop)
	wg.Wait()
	elapsed := time.Since(start)

	rep := summarize(results, elapsed)
	rep.Server, rep.Clients, rep.Network, rep.FirstError = *server, *conc, network, firstErr.msg
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(rep)
	} else {
		rep.print()
	}
	if rep.Errors > rep.Queries/100 {
		os.Exit(1) // more than 1% failed
	}
}

func pick(rng *rand.Rand, pool []string, miss, blocked float64) string {
	x := rng.Float64()
	switch {
	case x < miss:
		return fmt.Sprintf("x%08x.%s", rng.Uint32(), pool[rng.IntN(len(pool))])
	case x < miss+blocked:
		return blockedNames[rng.IntN(len(blockedNames))]
	}
	// Zipf-like: popular names are asked far more often.
	i := int(float64(len(pool)) * rng.Float64() * rng.Float64())
	return pool[i]
}

func readNames(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s has no names", path)
	}
	return out, sc.Err()
}

type report struct {
	Server     string         `json:"server"`
	Network    string         `json:"network"`
	Clients    int            `json:"clients"`
	Seconds    float64        `json:"seconds"`
	Queries    int            `json:"queries"`
	Errors     int            `json:"errors"`
	QPS        float64        `json:"qps"`
	P50ms      float64        `json:"p50_ms"`
	P90ms      float64        `json:"p90_ms"`
	P99ms      float64        `json:"p99_ms"`
	MaxMs      float64        `json:"max_ms"`
	Rcodes     map[string]int `json:"rcodes"`
	FirstError string         `json:"first_error,omitempty"`
}

func summarize(rs []result, elapsed time.Duration) report {
	r := report{Seconds: elapsed.Seconds(), Queries: len(rs), Rcodes: map[string]int{}}
	lats := make([]time.Duration, 0, len(rs))
	for _, x := range rs {
		if x.rcode < 0 {
			r.Errors++
			r.Rcodes["timeout/error"]++
			continue
		}
		r.Rcodes[dns.RcodeToString[x.rcode]]++
		lats = append(lats, x.lat)
	}
	r.QPS = float64(len(rs)-r.Errors) / elapsed.Seconds()
	if len(lats) > 0 {
		slices.Sort(lats)
		p := func(q float64) float64 {
			return float64(lats[min(len(lats)-1, int(q*float64(len(lats))))].Microseconds()) / 1000
		}
		r.P50ms, r.P90ms, r.P99ms, r.MaxMs = p(.5), p(.9), p(.99), float64(lats[len(lats)-1].Microseconds())/1000
	}
	return r
}

func (r report) print() {
	fmt.Printf("%s over %s, %d clients, %.1fs\n", r.Server, r.Network, r.Clients, r.Seconds)
	fmt.Printf("  queries   %d (%d failed)\n", r.Queries, r.Errors)
	fmt.Printf("  rate      %.0f answered/s\n", r.QPS)
	fmt.Printf("  latency   p50 %.2f ms  p90 %.2f ms  p99 %.2f ms  max %.1f ms\n", r.P50ms, r.P90ms, r.P99ms, r.MaxMs)
	keys := make([]string, 0, len(r.Rcodes))
	for k := range r.Rcodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Print("  answers  ")
	for _, k := range keys {
		fmt.Printf(" %s %d", k, r.Rcodes[k])
	}
	fmt.Println()
	if r.FirstError != "" {
		fmt.Println("  first error:", r.FirstError)
	}
}
