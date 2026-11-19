package main

import "testing"

func TestMetricsServer(t *testing.T) {
	for in, want := range map[string]string{
		"https://dns.nextdns.io/abc123":         "https://dns.nextdns.io",
		"https://user:pw@doh.example/dns-query": "https://doh.example",
		"tls://dns.quad9.net":                   "tls://dns.quad9.net",
		"udp://192.168.1.245:53":                "udp://192.168.1.245:53",
		"192.168.1.245:53":                      "192.168.1.245:53",
		"1.1.1.1":                               "1.1.1.1",
	} {
		if got := metricsServer(in); got != want {
			t.Errorf("metricsServer(%q) = %q, want %q", in, got, want)
		}
	}
}
