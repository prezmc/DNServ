# Installing and configuring

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
config file is optional: copy [`dnserve.example.yaml`](../dnserve.example.yaml)
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

[Back to the README](../README.md)
