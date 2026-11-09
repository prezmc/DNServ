package main

import (
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

func TestSummarize(t *testing.T) {
	rs := []result{{lat: time.Millisecond, rcode: 0}, {lat: 3 * time.Millisecond, rcode: 0}, {lat: 2 * time.Millisecond, rcode: 3}, {rcode: -1}}
	r := summarize(rs, time.Second)
	if r.Queries != 4 || r.Errors != 1 || r.QPS != 3 || r.Rcodes["NOERROR"] != 2 || r.Rcodes["NXDOMAIN"] != 1 || r.MaxMs != 3 || r.P50ms != 2 {
		t.Fatalf("%+v", r)
	}
}

func TestPickMix(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	var miss, blocked int
	for i := 0; i < 10000; i++ {
		n := pick(rng, popular, 0.2, 0.1)
		switch {
		case strings.HasPrefix(n, "x") && strings.Count(n, ".") >= 2 && len(n) > 9:
			miss++
		case contains(blockedNames, n):
			blocked++
		}
	}
	if miss < 1800 || miss > 2200 || blocked < 800 || blocked > 1200 {
		t.Fatalf("miss=%d blocked=%d", miss, blocked)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
