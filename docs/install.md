# Installing and configuring

```bash
docker run -d --name dnserv --restart unless-stopped \
  -p 53:53/udp -p 53:53/tcp -p 853:853 -p 8080:8080 -p 8081:8081 \
  -v dnserv-data:/data ghcr.io/prezmc/dnserv:latest
```

or `docker compose up -d` with the included `docker-compose.yml`.

No config file is needed. On first start the node prints a one-time setup
code in its log:

```bash
docker logs dnserv 2>&1 | grep setup_code
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
fonts, so it works without internet access. Port 8080 is plain HTTP until
you turn on HTTPS under Settings → Dashboard HTTPS (see
[Dashboard HTTPS](https.md)), or put it behind a reverse proxy with HTTPS
(set `DNSERV_ALLOWED_ORIGINS` to the proxy's host name).

Settings you save are stored in the data volume and win over the config
file and environment variables, which only provide the starting values. A
config file is optional: copy [`dnserv.example.yaml`](../dnserv.example.yaml)
to `/data/dnserv.yaml` if you'd rather manage settings that way. Check one
with `dnserv -check-config -config FILE`.

Notes:

- **Port 53 already in use?** On many Linux hosts `systemd-resolved` listens
  on port 53. Either publish DNServ on the host's LAN address
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
| `DNSERV_UPSTREAM_MODE` | `recursive` | `forward`, `recursive` or `tunnel` |
| `DNSERV_UPSTREAM_SERVERS` | `https://dns.quad9.net/dns-query,tls://dns.quad9.net` | forwarding servers |
| `DNSERV_UPSTREAM_STRATEGY` | `round_robin` | with several servers: `fastest` (default), `in_order`, `round_robin` or `parallel` |
| `DNSERV_TUNNEL_INTERFACE` | `wg0` | interface that must be up in tunnel mode |
| `DNSERV_TUNNEL_EXPECTED_EGRESS` | `185.65.0.0/16` | optional VPN exit IPs to verify |
| `DNSERV_TUNNEL_ON_DOWN` | `block` | `forward` (encrypted fallback) or `block` |
| `DNSERV_ALLOWED_NETS` | `192.168.1.0/24,10.0.0.0/8` | client networks allowed to query |
| `DNSERV_LOCAL_DNS` | `192.168.1.1` | your router, for device names and local names |
| `DNSERV_TIME_ZONE` | `Europe/London` | time zone for group schedules (default: the container's `TZ`, else UTC) |
| `DNSERV_BLOCK_BYPASS` | `true` | block public DoH resolvers and Private Relay |
| `DNSERV_BLOCK_MODE` | `nxdomain` | `null_ip`, `nxdomain` or `refused` |
| `DNSERV_THREAT_FEEDS` | `false` | download threat feeds for risk scores (default on) |
| `DNSERV_HISTORY_DAYS` | `14` | days of individual queries each node keeps (0 = none) |
| `DNSERV_STATS_DAYS` | `90` | days of hourly totals each node keeps (0 = none) |
| `DNSERV_CLUSTER_ADVERTISE` | `192.168.1.10:8081` | how other nodes reach this one (default: learned from the dashboard's address) |
| `DNSERV_CLUSTER_LISTEN` | `:8081` | node-to-node listener |
| `DNSERV_ROLE` | `witness` | `node` (default) or `witness` (votes only; see above) |
| `DNSERV_JOIN` | `DNSJ1-…` | witness only: the join code it uses the first time it starts |
| `DNSERV_NODE_NAME` | `pi-kitchen` | this node's name when it is first created (rename it under Cluster) |
| `DNSERV_ALLOWED_ORIGINS` | `dns.example.com` | extra host names for the admin API behind a reverse proxy |
| `DNSERV_HTTPS` | `off` | turns dashboard HTTPS off on this server whatever Settings say, to get back in after a bad certificate |
| `DNSERV_HTTPS_NAMES` | `dns1.example.com` | extra names for this server's self-signed dashboard certificate |

Environment variables override the optional config file; settings saved in
the dashboard or API override both.

## Upgrading from DNServe

The project was called DNServe until November 2026. Servers set up under
the old name keep their data, but a few names changed. In each server's
`docker-compose.yml`:

1. Change the image to `ghcr.io/prezmc/dnserv:latest`. The old image
   name gets no more updates.
2. Rename every `DNSERVE_` environment variable to `DNSERV_` (for
   example `DNSERVE_CLUSTER_ADVERTISE` becomes `DNSERV_CLUSTER_ADVERTISE`).
   The old names are ignored.
3. Leave the `volumes:` lines as they are. The volume holds your settings
   and history, and a new volume name would start an empty server.

Then run `docker compose pull && docker compose up -d`. Update every
server: nodes on either side of the rename still talk to each other, so
the order doesn't matter. You'll need to sign in again, and Prometheus
metrics now start with `dnserv_`. Backups made before the rename restore
as normal.

[Back to the README](../README.md)
