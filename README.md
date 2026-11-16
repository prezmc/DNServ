<p align="center">
  <img src="internal/web/static/logo.svg" alt="DNServ logo" width="96">
</p>

<h1 align="center">DNServ</h1>

<p align="center">
  Fast, filtered DNS for homes and small offices.<br>
  Blocklists, per-device rules, analytics and two-server failover, in one container you set up from the browser.<br>
  <a href="https://dnserv.dev"><b>dnserv.dev</b></a>
</p>

<p align="center">
  <img src="docs/images/dashboard.png" alt="DNServ dashboard" width="900">
</p>

## Why DNServ

- **Fast.** About 115,000 cached answers a second on a 4-core machine, with a median answer of 0.07 ms. Popular names are prefetched before they expire, a slow upstream gets backup from the next one, and old answers are served if the internet is down.
- **Blocks ads, trackers and malware.** Use any hosts file, domain list or AdGuard-style list (wildcards and regex included), plus your own allow and block rules.
- **Rules per device.** Put devices in groups like Kids, with their own blocklists, blocked services, safe search, and schedules such as bedtime or homework time. Custom rules can target a group or device (`$client=Kids`).
- **Shows what's going on.** Query log, analytics, response times and a traffic map from each device, through your servers, out to the services it reaches. History is kept for 30 days.
- **Spots threats.** Every lookup is scored against public malware and phishing feeds. The Dashboard tells you when something risky got through, who reached it, and lets you block it in one click. You can see and tune how scores add up.
- **Keeps working when a server fails.** Run two or more nodes. Settings stay in sync and any node can take over.
- **Private.** Uses encrypted DNS to Cloudflare by default, or resolves on its own with the bundled Unbound, optionally through a VPN.
- **Safe to run.** Two-factor sign-in (or a passkey) for every account. Roles are admin, power user and viewer. Every change is in the audit log. Encrypted backups go to a NAS, a network share or S3 storage, and the dashboard can have a free Let's Encrypt certificate.
- **Updates itself.** The Updates page shows what's new and installs it on every server, one at a time, with a backup first and one-click rollback. Follow numbered releases or every change.
- **No config files.** Pull the image, start it, and finish setup in the browser. You can import an existing AdGuard Home setup.

## Quick start

```bash
mkdir -p ~/dnserv && cd ~/dnserv
curl -fsSLO https://raw.githubusercontent.com/prezmc/DNServ/main/docker-compose.yml
echo "TZ=America/Chicago" > .env      # your time zone
docker compose up -d
docker compose logs | grep setup_code
```

Anything different on your server, such as a port that's already taken, goes in `.env` (see [Installing](docs/install.md#the-env-file)). Prefer `docker run`? See [Without compose](docs/install.md#without-compose). Installing from Portainer, Unraid, Synology or TrueNAS? The image is also on Docker Hub as [`prezmcmahon/dnserv`](https://hub.docker.com/r/prezmcmahon/dnserv), and the [GUI install guide](docs/docker-hub.md) lists every port, folder and setting to fill in.

Open `http://<server>:8080`, enter the setup code, and follow the wizard:

| | |
|---|---|
| <img src="docs/images/setup-code.png" alt="Enter the setup code" width="420"><br>**1.** Enter the code from the log | <img src="docs/images/setup-mfa.png" alt="Set up two-factor sign-in" width="420"><br>**2.** Create your account and scan the QR code |
| <img src="docs/images/setup-basics.png" alt="Pick upstream and blocklists" width="420"><br>**3.** Pick your blocklists, how lookups leave your network, and whether to send a weekly usage summary | <img src="docs/images/setup-done.png" alt="Setup finished" width="420"><br>**4.** Point your router's DHCP DNS at the server |

Is port 53 already in use? See [Installing](docs/install.md) for systemd-resolved and other notes.

**Updating:** open **Updates** in the dashboard and press **Install update** ([how it works](docs/updates.md)). Server set up before the updater existed? Paste the [one-line setup](docs/updates.md#adding-the-updater-to-an-existing-server) once. By hand: `docker compose pull && docker compose up -d`. Settings and history are kept. Set up with an older compose file or the old DNServe name? See [Moving an existing server to the standard compose file](docs/install.md#moving-an-existing-server-to-the-standard-compose-file).

## A second server

1. Install the same way on another machine, with port 8081 open between the two.
2. On the first server, open **Servers** and choose **Make a join code**.
3. On the new server, enter its setup code, choose **No, add this server to my DNServ**, and paste the join code.

Then add the second server as your router's second DNS server. For a trusted certificate on both, give each server a name under **Local names** and turn on Let's Encrypt under **System → General → Dashboard HTTPS**; then add a passkey on each server. To keep taking changes while either server is down, add a witness on a third machine. The [two-server guide](docs/deploy-two-servers.md) covers firewalls, upgrades, and what happens when something fails.

## Screenshots

| | |
|---|---|
| <img src="docs/images/security-page.png" alt="Security page" width="420"><br>**Security** says whether anything risky got through, who reached it, and every risky domain | <img src="docs/images/traffic-map.png" alt="Traffic map" width="420"><br>**Traffic map** follows lookups from devices to servers to services |
| <img src="docs/images/query-log-paused.png" alt="Query log, paused" width="420"><br>**Query log** searches every server's history, and holds still while you read | <img src="docs/images/analytics.png" alt="Analytics" width="420"><br>**Analytics** shows top domains, what blocked them, and busy devices |
| <img src="docs/images/performance.png" alt="Performance" width="420"><br>**Performance** shows response times, upstream health and anything unusual | <img src="docs/images/cluster.png" alt="Cluster" width="420"><br>**Servers** shows your nodes, with leader controls and join codes |
| <img src="docs/images/group.png" alt="Group with schedules" width="420"><br>**Groups** have their own blocklists, blocked services, safe search and schedules | <img src="docs/images/scoring.png" alt="Tune risk scoring" width="420"><br>**Risk scoring** explains every score, with presets and a preview when you tune it |
| <img src="docs/images/updates.png" alt="Updates" width="420"><br>**Updates** shows what's new and updates every server one at a time | <img src="docs/images/backups.png" alt="Backups" width="420"><br>**Backups** go to each server, a network share or S3 storage, encrypted |
| <img src="docs/images/blocklists.png" alt="Blocklists" width="420"><br>**Blocklists** pick a protection level, add categories or any list | <img src="docs/images/menu-search.png" alt="Menu search" width="420"><br>**Find** any domain or device from the menu |
| <img src="docs/images/devices-search.png" alt="Device search" width="420"><br>**Devices** search forgives typos | <img src="docs/images/dashboard-light.png" alt="Light theme" width="420"><br>**Light theme**, which follows your system setting |

## Documentation

| | |
|---|---|
| [Features](docs/features.md) | Everything DNServ does, in detail |
| [Installing and configuring](docs/install.md) | Install, update, the `.env` file, ports and environment variables |
| [Installing from a GUI](docs/docker-hub.md) | Portainer, Unraid, Synology, TrueNAS: what to fill in (also the Docker Hub page) |
| [Signing in](docs/sign-in.md) | Two-factor, passkeys on one or more servers, getting back in |
| [Updates](docs/updates.md) | Update from the dashboard, one server at a time; releases and the updater container |
| [Making a release](docs/releasing.md) | For the maintainer: cut a numbered release with one button |
| [Clustering](docs/clustering.md) | Nodes, witnesses, leader controls and recovery |
| [Two-server guide](docs/deploy-two-servers.md) | Step-by-step deploy with names, HTTPS and passkeys, and failure scenarios |
| [Two floating DNS addresses](docs/floating-dns-addresses.md) | More than two nodes behind keepalived |
| [Filtering](docs/filtering.md) | Rule syntax, blocked services, safe search, stopping bypass |
| [Security and risk scoring](docs/risk-scoring.md) | Threat feeds, the Security card, how scores add up, tuning |
| [Dashboard HTTPS](docs/https.md) | Let's Encrypt (built in), Nginx Proxy Manager, your own certificate or self-signed |
| [Backups and history](docs/backups.md) | Encrypted backups to a NAS, SMB share or S3, schedules, restore |
| [Moving from AdGuard Home](docs/adguard-import.md) | What the importer brings across |
| [Tunnel mode](docs/tunnel-mode.md) | Recursive DNS through a WireGuard VPN |
| [Admin API](docs/api.md) | Endpoints, tokens, permissions, account recovery |
| [Performance](docs/performance.md) | Benchmarks and the `dnsbench` load tester |
| [Development](docs/development.md) | Building, tests and roadmap |
| [Usage stats](docs/usage-stats.md) | The opt-in weekly anonymous summary: every field, where it goes, how to turn it off |
| [Testing](docs/testing.md) | Test layers, browser tests, the feature checklist and security scans |

## License

[Apache License 2.0](LICENSE).
