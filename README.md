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
setup wizard and dashboard handle the rest from your browser.

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
- **Accounts with mandatory two-factor sign-in.** Admins, power users (an
  admin picks what each one may change) and viewers. Every account must set
  up an authenticator app before it can do anything, and gets ten one-time
  recovery codes. Passwords are hashed with Argon2id; failed sign-ins are
  throttled; sessions end on password change, MFA reset or disable.
- **Settings change live.** Upstream mode, servers, tunnel, allowed
  networks, lists and rules saved through the API apply without a restart,
  and every change is in the audit log with who made it and what it was
  before.
- **API tokens** for scripts and home automation, limited to the
  permissions you pick.
- **Devices and recent queries.** See every device using DNServe, name
  them, and browse its most recent queries (kept in memory) with one-click
  Block or Allow. "Check a domain" says whether a name is blocked and by
  which rule and list. Give DNServe your router's address (`local_dns`) and
  it shows the names your router knows and answers local names such as
  `printer.lan` through it.
- **Analytics and query history.** Each node keeps its own query history
  in SQLite (`/data/history.db`): every query for 30 days and hourly
  totals for 90 by default (Settings → Query history, admins only; 0
  keeps none). **Analytics** shows queries over time, blocked share,
  cache hits, response time, top domains, top blocked domains with what
  caught them, and the busiest devices, for the last hour up to 90 days,
  for everyone or one device. Click a domain for its chart, which devices
  asked and one-click Block, Allow or Undo. The **Query log** searches
  every node's history (several words match in any order), pages back in
  time and exports CSV. With several nodes, the dashboard asks each one
  and merges the answers; there is no central database, and a node that
  is down is named as missing. Writing history never slows DNS answers:
  queries are queued and written in batches, and if the disk can't keep
  up they are counted and dropped rather than waited on. People with only
  `dashboard.view` see totals and top domains; devices, the query log and
  exports need `querylog.view` (and `data.export`).
- **Risk scores and domain types.** Analytics marks risky domains (0-100)
  from public threat feeds (URLhaus and ThreatFox from abuse.ch, Phishing
  Army, HaGeZi's Threat Intelligence Feeds) plus a few signs in the name
  itself (machine-generated look, often-abused top-level domains,
  look-alike characters), and says what each domain is and who runs it
  (Advertising · Google) from AdGuard's companies database (CC BY-SA
  4.0). A **Risky domains** list sits at the top of Analytics, and the
  domain detail and Query log show scores and reasons. Scores never block
  anything. Turn the feeds off, or list trusted domains, under Settings →
  Risk scoring. Each node downloads the sources itself, keeps them in
  `/data/threat` and refreshes them twice a day (about 30 MB of memory).
- **Local names.** Give names to things on your network under **Local
  names**: `nas.home → 192.168.1.20`, an alias like `files.home → nas.home`
  (or to an outside name), or a wildcard like `*.lab.home`. Every node
  answers them, ahead of blocklists, the router and the internet, and
  reverse lookups of their addresses return the name. They're kept with the
  settings, so they're in settings history and backups. In a config file
  they're `dns.records: [{name, value, note}]`.
- **Groups with schedules.** Put devices in a group (say, Kids) to give
  them extra rules, let them skip the household blocklists, or add
  schedules: pause the internet at bedtime, or block a few sites during
  homework time. Windows that end before they start run overnight. Allow
  rules in a group beat everything, so a school site keeps working at
  bedtime. Schedules follow the time zone set in Settings.

## Run it

```bash
docker run -d --name dnserve --restart unless-stopped \
  -p 53:53/udp -p 53:53/tcp -p 853:853 -p 8080:8080 -p 8081:8081 \
  -v dnserve-data:/data ghcr.io/prezmc/dnserve:latest
```

or `docker compose up -d` with the included `docker-compose.yml`.

No config file is needed. On first start the node prints a one-time setup
code in its log:

```bash
docker logs dnserve 2>&1 | grep setup_code
```

Open `http://<server>:8080` and the setup wizard walks you through it:

1. Enter the setup code and create the admin account.
2. Scan the QR code with an authenticator app (1Password, Bitwarden,
   Google or Microsoft Authenticator, Authy…) and enter a code.
3. Save your ten recovery codes.
4. Pick how lookups leave your network and which blocklists to use.

Then set your router's DHCP DNS server to the machine's address. Only
someone who can read the container's logs can claim a new node.

The dashboard has pages for status, checking and blocking domains,
devices, recent queries, settings,
users (admins), the audit log (admins), and your own password, sessions
and API tokens. It is a small built-in page with no external scripts or
fonts, so it works without internet access. Port 8080 is plain HTTP: keep
it on your LAN, or put it behind a reverse proxy with HTTPS (set
`DNSERVE_ALLOWED_ORIGINS` to the proxy's host name).

Settings you save are stored in the data volume and win over the config
file and environment variables, which only provide the starting values. A
config file is optional: copy [`dnserve.example.yaml`](dnserve.example.yaml)
to `/data/dnserve.yaml` if you'd rather manage settings that way. Check one
with `dnserve -check-config -config FILE`.

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

## Two or more nodes

Run the same image on a second server (same command or compose file, port
8081 published and open between the servers). Then:

1. On your first node, open **Cluster** and choose **Make a join code**.
2. Open the new node's dashboard, enter its setup code, choose **No, add
   this server to my DNServe**, and paste the join code.

The new node copies the accounts, settings, devices, groups and rules, and
from then on every change made on either node reaches both. Add the second
node's address to your router as a second DNS server.

How it works: every node runs embedded Raft (HashiCorp), alone or not.
Changes go through the leader's log and are applied on every node in the
same order; a change made on a follower is forwarded to the leader. Nodes
talk over one port (8081) with mutual TLS, using certificates from a private
CA the cluster creates for itself; the join code carries the CA's
fingerprint and a one-time secret (valid for an hour), so there is nothing to
copy between servers. A node that joins starts as a non-voter and votes once
it has caught up. Existing single nodes upgrade in place: their state becomes
the cluster's first log entry.

**DNS never waits for the cluster.** Each node answers from its own copy of
the settings, so a node cut off from the others keeps filtering with what it
last had. Without a leader only changes pause; sign-in still works (with an
authenticator code).

Leadership controls, under **Cluster**:

- **Make leader** hands leadership to another node now.
- **Prefer as leader**: the node leads whenever it is up and caught up.
- **Never lead**: the node keeps a full copy and answers DNS, but never
  leads or votes. With two nodes, this lets the other one take changes on
  its own even while this one is down.
- **Recover with this node only**, for when the other node is gone for good:
  the survivor becomes a cluster of one and keeps its settings. It refuses
  while any other node still answers, and asks again if the nodes left out
  could still have a majority between them, so two clusters never run at
  once. Nodes left out are locked out (their certificates are no longer
  accepted) until they join again with a new code.
- **Join another DNServe instead** moves a node that is set up already into
  another cluster, replacing its accounts and settings.

### How many nodes?

DNServe works with one node, two, or more. The Cluster page says how many
voting nodes can be down while changes still work.

| Setup | DNS if a node is down | Changes if a node is down |
|---|---|---|
| 1 node | Down | Down |
| 2 nodes | The other answers | Pause until it's back (or set one to Never lead) |
| 2 nodes + witness | The other answers | Keep working |
| 3 nodes | Others answer | Keep working |

A **witness** is the same image started with `DNSERVE_ROLE=witness` on a
third machine. It votes and keeps the change log, but answers no DNS and has
no dashboard, so a Raspberry Pi or a NAS is plenty. It joins with a join code
in `DNSERVE_JOIN` (the join-code screen shows the full command; see also
`deploy/docker-compose.witness.yml`). If it wins an election it hands
leadership straight to a full node. Put it on a different machine from your
DNS nodes: a witness on the same box doesn't help when that box fails. With
an even number of full nodes (4, 6, …) a witness also lets the cluster lose
one more node.

Clients only take two DNS servers? See
[docs/floating-dns-addresses.md](docs/floating-dns-addresses.md) for putting
any number of nodes behind two floating addresses with keepalived.

By default a node learns its cluster address from the address its dashboard
is opened at, or, for a witness, from the address the other node sees it
connect from. Set `DNSERVE_CLUSTER_ADVERTISE` (for example
`192.168.1.10:8081`) if other nodes reach it differently, such as through a
different published port.

## Backups and settings history

**Settings history.** Every change to settings, devices or groups is kept
as a version (the last 50, on every node). Under **Backups & history** you
can compare any version with now and go back to it. Going back is itself a
new version, so it can be undone. Accounts aren't part of the history, so
going back never brings back an old password or a deleted user.

**Encrypted backups.** A backup is one `.dnsbak` file with the accounts,
API tokens, settings, devices, groups and settings history. It is encrypted
with a passphrase you choose when you set backups up (at least 12
characters). DNServe keeps only a public key made from it: nodes can make
backups on their own but can't read them, and without the passphrase
nobody can open one. Keep it in a password manager.

- **Download a backup now** from the dashboard at any time.
- **Automatic backups** run daily or weekly (Sundays) at a set time, in the
  same time zone as group schedules. Every node keeps its own in
  `/data/backups` (the last 14 by default).
- **A copy off the server:** mount a folder from a NAS or another disk into
  the container (for example `-v /mnt/nas/dnserve:/backups`) and enter
  `/backups` as the copy folder. The leading node writes one copy of each
  backup there.
- **Restore** from a file under Backups & history (replaces the accounts and
  configuration on every node; the cluster's nodes stay as they are), or on
  a brand-new node choose **Restore from a backup** in the setup wizard.

Backup files use XChaCha20-Poly1305. The key comes from an ephemeral X25519
key agreed with the passphrase's key (scrypt, then HKDF-SHA256), and the
readable header (when, which node) is authenticated too.

## Configuring without files

| Variable | Example | Sets |
|---|---|---|
| `DNSERVE_UPSTREAM_MODE` | `recursive` | `forward`, `recursive` or `tunnel` |
| `DNSERVE_UPSTREAM_SERVERS` | `https://dns.quad9.net/dns-query,tls://dns.quad9.net` | forwarding servers |
| `DNSERVE_TUNNEL_INTERFACE` | `wg0` | interface that must be up in tunnel mode |
| `DNSERVE_TUNNEL_EXPECTED_EGRESS` | `185.65.0.0/16` | optional VPN exit IPs to verify |
| `DNSERVE_TUNNEL_ON_DOWN` | `block` | `forward` (encrypted fallback) or `block` |
| `DNSERVE_ALLOWED_NETS` | `192.168.1.0/24,10.0.0.0/8` | client networks allowed to query |
| `DNSERVE_LOCAL_DNS` | `192.168.1.1` | your router, for device names and local names |
| `DNSERVE_TIME_ZONE` | `Europe/London` | time zone for group schedules (default: the container's `TZ`, else UTC) |
| `DNSERVE_BLOCK_BYPASS` | `true` | block public DoH resolvers and Private Relay |
| `DNSERVE_BLOCK_MODE` | `nxdomain` | `null_ip`, `nxdomain` or `refused` |
| `DNSERVE_THREAT_FEEDS` | `false` | download threat feeds for risk scores (default on) |
| `DNSERVE_HISTORY_DAYS` | `14` | days of individual queries each node keeps (0 = none) |
| `DNSERVE_STATS_DAYS` | `90` | days of hourly totals each node keeps (0 = none) |
| `DNSERVE_CLUSTER_ADVERTISE` | `192.168.1.10:8081` | how other nodes reach this one (default: learned from the dashboard's address) |
| `DNSERVE_CLUSTER_LISTEN` | `:8081` | node-to-node listener |
| `DNSERVE_ROLE` | `witness` | `node` (default) or `witness` (votes only; see above) |
| `DNSERVE_JOIN` | `DNSJ1-…` | witness only: the join code it uses the first time it starts |
| `DNSERVE_NODE_NAME` | `pi-kitchen` | this node's name when it is first created (rename it under Cluster) |
| `DNSERVE_ALLOWED_ORIGINS` | `dns.example.com` | extra host names for the admin API behind a reverse proxy |

Environment variables override the optional config file; settings saved in
the dashboard or API override both.

## Admin API

Everything is under `/api/v1` on port 8080. Browsers use a session cookie
plus the `X-CSRF-Token` header from the sign-in response; scripts use
`Authorization: Bearer dns_…` tokens.

| | Endpoint |
|---|---|
| First run | `GET /setup`, `POST /setup` `{code, username, password}`, `POST /setup/join` `{code, join_code, host}`, or `POST /setup/restore` (multipart: `file`, `passphrase`, `code`) |
| Sign in | `POST /auth/login`, then `POST /auth/mfa` `{code}` (authenticator or recovery code) |
| Enroll MFA | `POST /auth/totp/begin` (returns the secret and `otpauth://` URL), `POST /auth/totp/confirm` `{code}` |
| You | `GET /auth/me`, `POST /auth/password`, `GET`/`DELETE /auth/sessions`, `POST /auth/logout`, `POST /auth/recovery-codes` `{password}`, `POST /auth/authenticator/begin` `{password}` then `/confirm` `{code}` |
| Users | `GET`/`POST /users`, `PATCH`/`DELETE /users/{id}`, `POST /users/{id}/password`, `POST /users/{id}/reset-mfa` |
| Tokens | `GET`/`POST /tokens`, `DELETE /tokens/{id}` |
| Settings | `GET`/`PATCH /settings`, `POST /settings/reset` `{fields}` |
| Local names | `PATCH /settings` `{records: [{name, value, note}]}` (the whole list; `value` is an IP address or another name) |
| Lists | `POST /lists/update` (download every list again now) |
| Block or allow | `POST /domains` `{domain, action: block\|allow\|clear}`, `GET /domains/check?name=` |
| Devices | `GET`/`POST /devices` `{name, addrs, group}`, `PUT`/`DELETE /devices/{id}` |
| Groups | `GET`/`POST /groups` `{name, rules, skip_blocklists, schedules: [{name, days, start, end, block_all, rules}], devices}`, `PUT`/`DELETE /groups/{id}` |
| Recent queries | `GET /queries?client=&search=&result=&before=&limit=` (`client` is an IP or device id; `result` is `blocked`, `allowed`, `failed`, …) |
| Analytics | `GET /analytics/summary`, `/analytics/top?by=domains\|blocked\|clients`, `/analytics/domain?name=`, `/analytics/queries?search=&result=&before=`, `/analytics/export` (CSV), `/analytics/risky`, `/analytics/intel` (sources). All take `range=1h\|24h\|7d\|30d\|90d` and `client=` (IP or device id), and merge every node's history |
| Settings history | `GET /config/versions`, `GET /config/versions/{id}` (with the changes going back would make), `POST /config/versions/{id}/restore` |
| Backups | `GET /backups`, `POST /backups/passphrase` `{passphrase, password}`, `PUT /backups/schedule` `{every: daily\|weekly\|"", at: "HH:MM", keep, offsite}`, `POST /backups/download`, `GET /backups/files/{local\|offsite}/{name}`, `POST /backups/restore` (multipart: `file`, `passphrase`, `password`) |
| Cluster | `GET /cluster`, `POST /cluster/join-codes` `{host}`, `PUT /cluster/nodes/{id}` `{name, never_leader}`, `DELETE /cluster/nodes/{id}`, `POST /cluster/preferred` `{id}`, `POST /cluster/transfer` `{to}`, `POST /cluster/recover` `{password, accept_risk}`, `POST /cluster/join` `{join_code, host, password}` |
| Status and audit | `GET /status`, `GET /audit` |

Permissions: `dashboard.view`, `querylog.view`, `data.export`,
`domains.allowblock`, `rules.edit`, `lists.manage`, `devices.manage`,
`upstream.manage`, `network.manage` (any of these can be given to a power
user), and the admin-only `users.manage`, `cluster.manage`,
`backups.manage`, `audit.view`.

Lost your phone? Sign in with a recovery code, or have another admin reset
your MFA. If the only admin is locked out, stop the node and run:

```bash
docker stop dnserve
docker run --rm -v dnserve-data:/data ghcr.io/prezmc/dnserve -reset-mfa USERNAME
docker start dnserve
```

That clears the account's second factor when the node starts (you set it up
again at the next sign-in) and is recorded in the audit log. In a cluster
the node must reach the leader for it to apply. Add `-reset-password` to also
print a new temporary password.

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
pushes `ghcr.io/prezmc/dnserve` on every push to `main` and on version tags.
Adding `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` repository secrets also
pushes `prezmcmahon/dnserve` to Docker Hub.

## Roadmap

1. **DNS node.** 1a core node. 1b Unbound recursive mode, WireGuard
   tunnel mode, DoH/DoT for clients. 1c admin API with users, roles and
   mandatory MFA, and the web UI with a setup wizard. 1d devices, recent
   queries, router names, groups with schedules, and a load tester.
2. **Clustering and backups.** Embedded Raft so any node can lead, join
   codes, owner overrides (preferred leader, never lead, transfer, forced
   recovery), witness mode, settings history with restore, and scheduled
   encrypted backups (this). Later: backups to S3-compatible storage.
3. **Analytics.** Per-node query history merged across nodes, charts,
   top lists, "caught by", search and export, and the AdGuard Insight
   features: threat-feed risk scores and domain types and owners (this).
4. **Multi-server deploy and failover testing.**

## License

[Apache License 2.0](LICENSE).
