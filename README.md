# DNServe

A self-hosted DNS server with filtering, built for homes and small businesses
(5 to 100 devices). It is designed to run as a cluster of identical containers
on separate servers that keep rules and settings in sync, so DNS keeps working
when a server goes down.

**Status: early development (step 1a of the roadmap).** A single node works:
encrypted forwarding, caching and blocklists. Clustering, the dashboard,
users with MFA, recursive resolution and analytics are on the way. See
[Roadmap](#roadmap).

## What works today

- **Encrypted upstreams by default.** DNS over HTTPS to Cloudflare
  (`1.1.1.1`), with DNS over TLS as a fallback. Plain UDP/TCP upstreams are
  also supported. Upstreams are tried fastest-first with automatic failover.
- **Fast cache.** Sharded in-memory cache with prefetch of popular entries
  before they expire, serve-stale when upstream is down (RFC 8767), and
  persistence: the cache is saved on shutdown and reloaded on start.
- **Blocklists and custom rules.** Hosts files, plain domain lists and AdBlock
  syntax (`||domain^`, `@@||domain^`, `*.domain`). Lists download on a
  schedule and are cached on disk, so a restart works offline. A refresh
  builds a new index off to the side and swaps it in without pausing DNS.
- **Private by default.** Local names (`.lan`, `.local`, `.home.arpa`,
  single-label names) and reverse lookups of private addresses never leave
  your network. Client subnet information is never sent upstream.
- **Safe by default.** Only private networks may query unless you configure
  `allowed_nets`, so a node can't become an open resolver by accident.
  Optional per-client rate limit.
- **Observable.** `/healthz`, `/readyz` and Prometheus `/metrics` (queries by
  outcome, latency histograms, cache and upstream stats).

## Run it

```bash
docker run -d --name dnserve --restart unless-stopped \
  -p 53:53/udp -p 53:53/tcp -p 8080:8080 \
  -v dnserve-data:/data prezmcmahon/dnserve:latest
```

or `docker compose up -d` with the included `docker-compose.yml`.

With no config file the node uses the defaults in
[`dnserve.example.yaml`](dnserve.example.yaml). To customize, copy that file
to `/data/dnserve.yaml` in the volume (or mount your own) and restart. Check a
config without starting it with `dnserve -check-config -config FILE`.

Notes:

- **Port 53 already in use?** On many Linux hosts `systemd-resolved` listens
  on port 53. Either publish DNServe on the host's LAN address
  (`-p 192.168.1.10:53:53/udp …`) or set `DNSStubListener=no` in
  `/etc/systemd/resolved.conf`.
- **Non-root.** The container runs as an unprivileged user. Docker 20.10+ lets
  containers on bridge networks bind port 53 without extra privileges. With
  `network_mode: host` that doesn't apply, so run that container with
  `user: root`.
- Point your router's DHCP DNS setting (or individual devices) at the host.
- The image's health check probes `127.0.0.1:8080`; keep `http.listen` on
  port 8080 or override the health check.

## Rule syntax

| Rule | Matches |
|---|---|
| `\|\|ads.example^` | `ads.example` and every subdomain |
| `*.ads.example` | subdomains only, not `ads.example` itself |
| `ads.example` or `0.0.0.0 ads.example` | exactly that name |
| `@@\|\|cdn.example^` | never blocks it or its subdomains |

Custom rules beat lists. At the same level, an allow rule beats a block.
Regex rules, cosmetic rules and modifiers other than `$important` are skipped
and counted, so the index never claims to block something it doesn't.

## Performance

Micro-benchmarks from `go test -bench` on a 4-core VM:

| Operation | Time |
|---|---|
| Blocklist check against 1,000,000 rules | about 0.1 µs |
| Cache hit (parallel) | about 0.5 µs |

End-to-end load-test numbers (queries per second, cached and cold latency)
come with step 1d.

## Development

```bash
go test -race ./...
go test -run '^$' -bench . ./internal/...
go run ./cmd/dnserve -config dnserve.example.yaml
```

Layout: `cmd/dnserve` (entry point), `internal/config`, `internal/filter`
(rule parsing, compiled index, list downloads), `internal/cache`,
`internal/upstream` (DoH, DoT, plain), `internal/server` (DNS handler,
metrics).

## Roadmap

1. **DNS node.** 1a core node (this). 1b Unbound recursive mode, WireGuard
   tunnel mode, DoH/DoT for clients. 1c admin API and UI with users, roles and
   mandatory MFA. 1d per-device and per-group policies with schedules, and a
   load-test harness.
2. **Clustering and backups.** Embedded Raft so any node can lead, owner
   overrides, witness mode, audit log, versioned config, scheduled encrypted
   backups.
3. **Analytics.** The AdGuard Insight features (threat scoring, domain types,
   devices, search) built in, across every node.
4. **Multi-server deploy and failover testing.**

## License

[Apache License 2.0](LICENSE).
