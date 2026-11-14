# Installing and configuring

There's one standard way to run DNServ: the `docker-compose.yml` from this
repository, plus an optional `.env` file for anything that's different on
your server. You never edit `docker-compose.yml`, so updating is always the
same two commands.

## Install

On a Linux server with Docker and Docker Compose:

```bash
mkdir -p ~/dnserv && cd ~/dnserv
curl -fsSLO https://raw.githubusercontent.com/prezmc/DNServ/main/docker-compose.yml
echo "TZ=America/Chicago" > .env      # your time zone, used by schedules
docker compose up -d
docker compose logs | grep setup_code
```

Open `http://<server address>:8080`, enter the setup code, and the wizard
walks you through it:

1. Create the admin account.
2. Scan the QR code with an authenticator app and enter a code.
3. Save your ten recovery codes.
4. Pick how lookups leave your network and which blocklists to use.

Then set your router's DHCP DNS server to the server's address. Only someone
who can read the container's logs can claim a new server.

Next steps:

- **A second server:** follow the [two-server guide](deploy-two-servers.md).
- **HTTPS and a name for the dashboard:** see [Dashboard HTTPS](https.md).
- **Passkeys:** see [Signing in](sign-in.md#passkeys).

## Update

In the server's folder:

```bash
docker compose pull && docker compose up -d
```

Settings, history and statistics are kept. With two or more servers, update
one at a time (see [Upgrading](deploy-two-servers.md#upgrading)). Updates
are published a few minutes after each change to `main`.

Once in a while `docker-compose.yml` itself changes (a new port, say). To
get the new one, download it again with the `curl` line above. Your `.env`
is left alone.

## The `.env` file

Put anything specific to this server in `.env`, next to
`docker-compose.yml`. Every setting is optional; see
[`.env.example`](../.env.example) for the full list with explanations.

| Setting | When you need it |
|---|---|
| `TZ=America/Chicago` | Always a good idea: group schedules use it |
| `DNSERV_HTTPS_PORT=8443` | Something else on the server already uses port 443 |
| `DNSERV_WEB_PORT=8090` | Something else already uses port 8080 |
| `DNSERV_CLUSTER_PORT=8091` and `DNSERV_CLUSTER_ADVERTISE=192.168.1.10:8091` | Something else already uses port 8081. The second line tells the other servers the new port |
| `DNSERV_HTTPS=off` | A bad dashboard certificate keeps you out (see [Locked out](https.md#locked-out)). Remove it again afterwards |
| `DNSERV_VOLUME=dnserve_dnserve-data` | You're moving a server set up another way and want to keep its data (see [below](#moving-an-existing-server-to-the-standard-compose-file)) |

After changing `.env`, run `docker compose up -d`.

### Ports

| Port | What for |
|---|---|
| 53 (UDP and TCP) | DNS for your devices |
| 853 | DNS over TLS (Android Private DNS and similar) |
| 443 | The dashboard over HTTPS at `https://<name>/`, and DNS over HTTPS |
| 8080 | The dashboard and setup wizard (HTTP, and HTTPS once it's on) |
| 8081 | Other DNServ servers in the same cluster |

If something already uses one of these, Docker refuses to start with
"port is already allocated". Pick another host port in `.env` as above.

### Without compose

If you'd rather use `docker run`, this is the same as the compose file:

```bash
docker run -d --name dnserv --restart unless-stopped \
  -p 53:53/udp -p 53:53/tcp -p 853:853 -p 443:443 -p 8080:8080 -p 8081:8081 \
  -e TZ=America/Chicago -v dnserv-data:/data ghcr.io/prezmc/dnserv:latest
```

To update, `docker pull ghcr.io/prezmc/dnserv:latest`, then remove the
container and run the same command again. The data volume keeps everything.

## The dashboard

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

- **Port 53 already in use?** On Ubuntu and many other Linux hosts
  `systemd-resolved` listens on port 53 (`address already in use`). Turn off
  its listener and point the server itself at a public resolver:

  ```sh
  sudo mkdir -p /etc/systemd/resolved.conf.d
  printf '[Resolve]\nDNSStubListener=no\nDNS=1.1.1.1\n' | sudo tee /etc/systemd/resolved.conf.d/dnserv.conf
  sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  sudo systemctl restart systemd-resolved
  ```
- **Non-root.** The container runs as an unprivileged user, and so does the
  bundled Unbound. Docker 20.10+ lets containers on bridge networks bind ports
  53, 443 and 853 without extra privileges. With
  `network_mode: host` that doesn't apply, so run that container with
  `user: root`.
- The image's health check probes `127.0.0.1:8080`; keep `http.listen` on
  port 8080 or override the health check.

## Configuring without files

Everything below can also be set in the dashboard, which is the usual way.
These variables give a server its starting values, for people who use
`docker run -e …` or keep their own compose file.

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

## Moving an existing server to the standard compose file

Servers set up with an older compose file (including ones from before the
DNServe to DNServ rename) or with `docker run` can switch to the standard
`docker-compose.yml` and keep everything. In the server's folder:

1. Find the data volume the current container uses:
   `docker inspect <container name> --format '{{range .Mounts}}{{.Name}} {{end}}'`
   (the container name is in `docker ps`, for example `dnserve`).
2. Stop the old container: `docker compose down` (or `docker rm -f <name>`
   for `docker run`). This keeps the volume and your data.
3. Download the standard file:
   `curl -fsSLO https://raw.githubusercontent.com/prezmc/DNServ/main/docker-compose.yml`
4. Create `.env` next to it with `DNSERV_VOLUME=<the volume name from step 1>`
   and anything else this server needs from [`.env.example`](../.env.example),
   such as `TZ` or a different cluster port with its
   `DNSERV_CLUSTER_ADVERTISE`. Settings that used to be `DNSERVE_...`
   variables are now `DNSERV_...`.
5. `docker compose pull && docker compose up -d`, then open the dashboard
   and check your settings and history are there.

You'll need to sign in again after the rename, and Prometheus metrics start
with `dnserv_`. Backups made before the rename restore as normal.

[Back to the README](../README.md)
