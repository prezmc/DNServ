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
in 15 ms, like a typical DNS over HTTPS resolver:

| Mix | Answered per second | p50 | p90 | p99 |
|---|---|---|---|---|
| All popular names (cache hits) | about 107,000 | 0.36 ms | 0.79 ms | 2.4 ms |
| 5% never-seen names, 10% blocked (typical home) | about 51,000 | 0.14 ms | 0.44 ms | 16 ms |
| Same over TCP | about 52,000 | 0.13 ms | 0.42 ms | 16 ms |
| 30% never-seen names | about 10,000 | 0.25 ms | 16 ms | 17 ms |

A busy home or small office sends 5 to 50 queries a second, so one node
has room to spare. The slow tail is the upstream's round trip for names
not yet cached.

Run it against your own node (it's in the image):

```bash
docker run --rm --network host --entrypoint dnsbench ghcr.io/prezmc/dnserve \
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
