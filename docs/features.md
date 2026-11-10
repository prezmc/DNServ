# Features

Everything DNServ does today, in more detail than the README.

- **Three ways to resolve** (`upstream.mode` or `DNSERV_UPSTREAM_MODE`):

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
  syntax (`||domain^`, `@@||domain^`, `*.domain`, wildcards, regex,
  `$denyallow`, `$badfilter`). Lists download on a
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
- **Pause filtering** from the Dashboard for 1, 5, 15 or 30 minutes, an
  hour, or until you turn it back on, on every server at once or just one.
  A banner counts down and turns it back on in one click. The pause goes
  through the cluster like any change, so every node obeys it; it's in the
  audit log but not in settings history or backups. Admins, power users
  with "Manage blocklists" or "Pause filtering", and viewers given "Pause
  filtering" can use it.
- **Devices and recent queries.** See every device using DNServ, name
  them, and browse its most recent queries (kept in memory) with one-click
  Block or Allow. "Check a domain" says whether a name is blocked and by
  which rule and list. Give DNServ your router's address (`local_dns`) and
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
- **Performance.** The **Performance** page shows how quickly DNServ
  answers: median, 95th and 99th percentile response times, how long
  lookups the cache couldn't answer took, cache hit rate and SERVFAILs,
  over time and by record type, plus each upstream server's speed,
  timeouts and errors (per node, since each has its own path out), the
  slowest domains to look up and each device's cache hits. It flags
  anything unusual against the 7 days before (or the typical bucket for
  longer periods): slow lookups, failure surges, upstream servers timing
  out or slowing down, query surges and cache hit drops. The Dashboard
  shows the last hour and any warnings, and the **Top blocking lists**
  (Dashboard and Analytics) say which lists block the most. Response
  times come from what each node already measures; they are rolled up
  into 5-minute slots with latency histograms by the history writer, so
  percentiles merge exactly across nodes and nothing is added to the
  query path. Kept as long as the hourly totals. On first start after
  updating, response times are rebuilt from the existing query history.
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
  History also keeps each answer's addresses and aliases (about 33 MB a
  day per 100,000 queries), so a harmless-looking name that answers with a
  known botnet server (Feodo Tracker, Spamhaus DROP) or points to a risky
  name is marked too. These checks run in the history writer, never on
  the DNS path.
- **Also on, and VirusTotal.** A domain's details list every enabled list
  with a rule for it ("on your lists"), read from the saved list files
  only when you open it, so it costs no memory. Add your own free
  VirusTotal API key under Settings → VirusTotal to get a **Check on
  VirusTotal** button: only the domain you click is sent, at most 4 a
  minute, and results are kept for a day. The key is shared with your
  other nodes, never shown again, and not part of backups.
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

[Back to the README](../README.md)
