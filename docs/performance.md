# Performance

Micro-benchmarks from `go test -bench` on a 4-core VM:

| Operation | Time |
|---|---|
| Blocklist check against 1,000,000 rules | about 0.1 µs |
| The same with 1,000 wildcard and regex rules added | about 0.25 µs |
| Cache hit (parallel) | about 0.5 µs |
| Whole query path in process, cached answer, query log on | about 1.1 µs |
| Whole query path, blocked name | about 0.7 µs |

End to end with the included load tester, `dnsbench`, on the same 4-core
VM. The tester and the node share the CPUs, and a fake upstream answers
in 15 ms, like a typical DNS over HTTPS resolver. 20 clients each send
their next query when the last is answered:

| Mix | Answered per second | p50 | p90 | p99 |
|---|---|---|---|---|
| All popular names (cache hits) | about 115,000 | 0.12 ms | 0.28 ms | 1.1 ms |
| 5% never-seen names, 10% blocked (typical home) | about 23,000 | 0.07 ms | 0.17 ms | 16 ms |
| Same over TCP | about 23,000 | 0.07 ms | 0.16 ms | 16 ms |
| 30% never-seen names | about 4,100 | 0.20 ms | 16 ms | 17 ms |

With never-seen names in the mix, the rate is set by the clients waiting
15 ms for each lookup, not by the node: 100 clients get about 75,000 a
second from the same mix.

When an upstream server is slow to answer, DNServ asks the next one too
(after four times the first's usual answer time, between 60 and 750 ms)
and uses whichever answers first. With two upstreams that each lose 3%
of queries and 10% never-seen names:

| | Answered per second | Average wait |
|---|---|---|
| Before (wait for the 3 s timeout, then try the other) | about 1,600 | about 12 ms |
| Now (ask the other after 60 ms) | about 8,000 | about 2.5 ms |

A busy home or small office sends 5 to 50 queries a second, so one node
has room to spare. The slow tail is the upstream's round trip for names
not yet cached.

Run it against your own node (it's in the image):

```bash
docker run --rm --network host --entrypoint dnsbench ghcr.io/prezmc/dnserv \
  -server 192.168.1.10:53 -c 20 -d 30s
```

Options: `-c` concurrent clients, `-d` duration, `-qps` a fixed rate
instead of flat out, `-miss` share of never-seen names (default 0.05),
`-blocked` share of blocked names (default 0.1), `-names FILE` your own
list of names, `-tcp`, and `-json` for a machine-readable report. It
exits non-zero if more than 1% of queries fail. Point it at a test node
or run it briefly: never-seen names are real lookups that reach your
upstream.

[Back to the README](../README.md)
