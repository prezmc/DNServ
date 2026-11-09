# DNServe

A self-hosted DNS server with filtering, built for homes and small businesses
(5 to 100 devices). It is designed to run as a cluster of identical containers
on separate servers that keep rules and settings in sync, so DNS keeps working
when a server goes down.

**Status: early development (step 1b of the roadmap).** A single node works:
encrypted forwarding or recursive resolution, an optional VPN tunnel,
encrypted DNS for your devices, caching and blocklists. Clustering, the
dashboard, users with MFA and analytics are on the way. See
[Roadmap](#roadmap).

**No config files needed.** Pull the image and start it. Defaults work out
of the box, common options can be set with environment variables, and the
dashboard (step 1c) will handle the rest from your browser.

## What works today

- **Three ways to resolve** (`upstream.mode` or `DNSERVE_UPSTREAM_MODE`):

  | Mode | How | ISP sees your lookups | You trust |
  |---|---|---|---|
  | `forward` (default) | DNS over HTTPS/TLS to Cloudflare or your choice | No | That resolver |
  | `recursive` | Bundled Unbound walks from the root servers, validating DNSSEC | Yes (queries to domain servers are unencrypted), but can't fake answers | Nobody but the DNS hierarchy |
  | `tunnel` | Recursive, with every query leaving through a WireGuard VPN | No | The VPN only sees encrypted traffic |

  Recursive mode uses Unbound's hardening: DNSSEC validation, QNAME
  minimisation, randomized query case (0x20), aggressive NSEC, DNS rebinding
  protection, no EDNS Client Subnet. Unbound runs as a supervised child
  process on loopback and is restarted if it exits.
- **Encrypted DNS for your devices.** DNS over TLS on port 853 and DNS over
  HTTPS on 443 (`/dns-query`), alongside plain DNS on 53. Uses your
  certificate, or a self-signed one generated on first start (fine for
  testing; Android Private DNS and most browsers need a trusted
  certificate).
- **Bypass protection.** Answers Firefox's `use-application-dns.net` canary
  so it doesn't switch to its own DoH. With `block_bypass` on, also blocks
  well-known public DoH resolvers and iCloud Private Relay.
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
  -p 53:53/udp -p 53:53/tcp -p 853:853 -p 8080:8080 \
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
- **Non-root.** The container runs as an unprivileged user, and so does the
  bundled Unbound. Docker 20.10+ lets containers on bridge networks bind ports
  53, 443 and 853 without extra privileges. With
  `network_mode: host` that doesn't apply, so run that container with
  `user: root`.
- Point your router's DHCP DNS setting (or individual devices) at the host.
- The image's health check probes `127.0.0.1:8080`; keep `http.listen` on
  port 8080 or override the health check.

## Configuring without files

| Variable | Example | Sets |
|---|---|---|
| `DNSERVE_UPSTREAM_MODE` | `recursive` | `forward`, `recursive` or `tunnel` |
| `DNSERVE_UPSTREAM_SERVERS` | `https://dns.quad9.net/dns-query,tls://dns.quad9.net` | forwarding servers |
| `DNSERVE_TUNNEL_INTERFACE` | `wg0` | interface that must be up in tunnel mode |
| `DNSERVE_TUNNEL_EXPECTED_EGRESS` | `185.65.0.0/16` | optional VPN exit IPs to verify |
| `DNSERVE_TUNNEL_ON_DOWN` | `block` | `forward` (encrypted fallback) or `block` |
| `DNSERVE_ALLOWED_NETS` | `192.168.1.0/24,10.0.0.0/8` | client networks allowed to query |
| `DNSERVE_BLOCK_BYPASS` | `true` | block public DoH resolvers and Private Relay |
| `DNSERVE_BLOCK_MODE` | `nxdomain` | `null_ip`, `nxdomain` or `refused` |

Environment variables override the optional config file.

## Tunnel mode

[`deploy/docker-compose.tunnel.yml`](deploy/docker-compose.tunnel.yml) pairs
DNServe with [gluetun](https://github.com/qdm12/gluetun), which brings up
WireGuard for most VPN providers. DNServe shares gluetun's network, so all its
traffic goes through the tunnel and gluetun's firewall drops anything that
tries to leave outside it. Fill in your provider's WireGuard values and run
`docker compose -f deploy/docker-compose.tunnel.yml up -d`.

DNServe also checks the tunnel every 30 seconds: the interface must be up,
and if you set `expected_egress`, the address that authoritative servers see
must be one of your VPN's. If a check fails, DNServe either falls back to
encrypted forwarding (`on_down: forward`, the default; your ISP still sees
nothing) or stops resolving (`on_down: block`). The `dnserve_tunnel_up`
metric shows the state.

## Stopping devices from bypassing DNServe

Blocking resolver names only goes so far, because a device can still use a
resolver by IP. On your router or firewall:

1. Block outbound TCP and UDP port 853 (DNS over TLS) from every device
   except the DNServe hosts.
2. Redirect (DNAT) outbound port 53 from devices to DNServe, so hard-coded
   `8.8.8.8` still reaches it.

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
(rule parsing, compiled index, list downloads, bypass list),
`internal/cache`, `internal/upstream` (DoH, DoT, plain),
`internal/recursive` (Unbound config and supervisor, tunnel checks),
`internal/server` (DNS handler, DoT/DoH listeners, metrics).

The Unbound integration test runs when `unbound` and a DNSSEC root key are
installed (`apt install unbound` or `apk add unbound dnssec-root`).

Images: `.github/workflows/publish.yml` builds amd64 and arm64 images and
pushes `prezmcmahon/dnserve` to Docker Hub on every push to `main` and on
version tags, once the `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` repository
secrets are set.

## Roadmap

1. **DNS node.** 1a core node. 1b Unbound recursive mode, WireGuard
   tunnel mode, DoH/DoT for clients (this). 1c admin API and UI with users, roles and
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
