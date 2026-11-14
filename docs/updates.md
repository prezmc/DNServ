# Updates

DNServ tells you when a new version is out, and installs it from the
dashboard, one server at a time, so your network never loses DNS.

Open **Updates** in the menu (admins). The menu entry shows **new** when an
update is available.

## How it works

**Finding new versions.** Every few hours each server asks the image
registry (`ghcr.io`) which image its tag (`latest`) points to now, and
compares that image's version with its own. Nothing about your network is
sent. When the image comes from GitHub, the page also lists what changed
(the pull requests merged since your version). You can turn checking off on
the Updates page.

**Installing.** Updates come from a small second container, the
**updater**, which the standard `docker-compose.yml` runs next to DNServ.
When you press **Install update**:

1. The server you're on asks each server's updater in turn. Witnesses go
   first (they answer no DNS), then the other servers, the leader after the
   followers, and the server you're on last.
2. On each server the updater downloads the new image, stops the DNServ
   container (DNServ saves its cache first), and starts a new one with
   exactly the same settings: ports, volumes, networks, environment.
3. It waits for the new container to report itself healthy. If it doesn't
   start, keeps restarting, or isn't healthy within 3 minutes, the updater
   removes it and starts the old container again.
4. The next server only starts once this one answers DNS again on the new
   version. If a server fails to update, the rollout stops there and the
   remaining servers are left alone.

Each server's DNS is down for a few seconds while it restarts. With two
servers, devices use the other one meanwhile. In the lab test (two servers
and a witness, a device asking both for a name every 50 ms) there was never a
moment when neither server answered.

**Automatic updates** (off by default): tick **Install new versions
automatically** and pick an hour. The leader starts the same one-at-a-time
rollout at that hour, in the time zone set under Settings, when a new
version is out.

Updates keep your settings, history and statistics: everything lives in the
`dnserv-data` volume, and history changes are always migrated in place.

## The updater and the Docker socket

To replace a container, the updater needs the Docker socket
(`/var/run/docker.sock`). Whoever controls that socket controls Docker on
that server, which is as good as root. So the updater is kept as small as it
can be:

- It has **no network at all** (`network_mode: none`). Docker itself
  downloads images; the updater only asks it to.
- DNServ reaches it only through a Unix socket in a volume the two share
  (`dnserv-updater`). The socket belongs to DNServ's user; nothing on your
  network can reach it.
- It looks after **one container**: the other container that mounts that
  volume (or the one named in `DNSERV_UPDATER_TARGET`).
- It only ever pulls the image that container was created from. Nothing
  DNServ sends can make it run a different image, change settings, or touch
  other containers. All it can be asked is "update now" and "how are you".
- An image pinned to one digest (`image: ghcr.io/prezmc/dnserv@sha256:…`)
  is never updated.

So the worst a compromised DNServ could do through the updater is restart
itself on the newest official image. If you'd still rather not run it,
delete the `dnserv-updater` service from `docker-compose.yml`. The Updates
page then shows when a new version is out, and you update by hand:

```bash
docker compose pull && docker compose up -d
```

Similar tools such as Watchtower take the same socket and update every
container on a schedule. The DNServ updater only updates DNServ, checks that
the new version is healthy before letting the old one go, and updates a
cluster one server at a time.

## Adding the updater to an existing server

Servers set up before the updater existed don't have it. In the server's
folder, download the current `docker-compose.yml` (your `.env` is left
alone), then run once:

```bash
curl -fsSLO https://raw.githubusercontent.com/prezmc/DNServ/main/docker-compose.yml
docker compose pull && docker compose up -d
```

From then on, updates can be installed from the dashboard. A witness set up
with `deploy/docker-compose.witness.yml` gets the same: download the new
file and run `docker compose -f docker-compose.witness.yml up -d`.

The updater itself runs the same image. It changes rarely; the
`docker compose pull && docker compose up -d` above (run now and then, or
when the release notes say so) refreshes it too.

## Settings

| Variable | Default | What it does |
|---|---|---|
| `DNSERV_UPDATER_TARGET` | the other container on the volume | Container the updater looks after |
| `DNSERV_UPDATE_IMAGE` | `ghcr.io/prezmc/dnserv:latest` | Image to check when no updater is set up (with one, the container's own image is checked) |
| `DNSERV_UPDATE_REGISTRY` | the image's registry | Ask another registry (a mirror) instead, as `host:port` or `http://host:port` |

Tunnel mode (`deploy/docker-compose.tunnel.yml`) doesn't include the updater
yet; update those servers by hand.
