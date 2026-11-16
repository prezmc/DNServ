# DNServ

A DNS server for homes and small businesses that blocks ads, trackers and
malware for every device on your network. Runs on one server or several
kept in sync, with a web dashboard, query history, two-factor sign-in and
backups. Works on Intel/AMD (amd64) and ARM (arm64, e.g. Raspberry Pi 4/5).

- Website: https://dnserv.dev
- Source and full docs: https://github.com/prezmc/DNServ
- The same image is also at `ghcr.io/prezmc/dnserv`

## Which tag?

| Tag | What you get |
|---|---|
| `stable` | The latest release. **Use this one.** |
| `latest` | Every change as soon as it's merged. For testing. |
| `1.2.1`, `1.2` | A fixed release, if you want to choose when to update |

## Quick start (command line)

```bash
docker run -d --name dnserv --restart unless-stopped \
  -p 53:53/udp -p 53:53/tcp -p 853:853 -p 443:443 -p 8080:8080 -p 8081:8081 \
  -e TZ=America/Chicago -v dnserv-data:/data prezmcmahon/dnserv:stable
docker logs dnserv | grep setup_code
```

Or with Docker Compose (recommended, it includes one-click updates):
https://github.com/prezmc/DNServ/blob/main/docker-compose.yml

## Installing from a GUI (Portainer, Unraid, Synology, TrueNAS, ...)

There are no config files. You set a few things when you create the
container, and everything else is done in the setup wizard.

### 1. Image

`prezmcmahon/dnserv:stable`

### 2. Ports

Map each container port to the same host port unless something else on
the box already uses it. Only port 53 really has to stay 53, because
devices always ask for DNS on port 53.

| Container port | Protocol | Needed? | What for |
|---|---|---|---|
| 53 | **UDP** | Yes | DNS. Add it twice: once UDP, once TCP |
| 53 | **TCP** | Yes | DNS (large answers) |
| 8080 | TCP | Yes | Dashboard and setup wizard |
| 443 | TCP | Optional | Dashboard over HTTPS and DNS over HTTPS. Pick another host port (e.g. 8443) if the box's own web page uses 443 |
| 853 | TCP | Optional | DNS over TLS for phones and laptops (Android "Private DNS") |
| 8081 | TCP | Only with 2+ servers | How DNServ servers talk to each other |

### 3. Volume (keeps your settings)

| Container path | Host path or volume | Needed? |
|---|---|---|
| `/data` | a folder such as `/mnt/user/appdata/dnserv` or a named volume `dnserv-data` | **Yes.** Settings, users, lists and history live here. Without it, you start from scratch on every update |

Any folder works, whoever owns it: at start DNServ gives the folder to its
own user (ID 65532) and then stops running as root. If your system starts
containers as a fixed user instead (a "PUID" or "User" field), leave that
empty, or set it to `65532` and make sure that ID can write to the folder.

### 4. Environment variables

Only `TZ` is worth setting for most people. All of these are optional.

| Variable | Example | When you need it |
|---|---|---|
| `TZ` | `America/Chicago` | Always a good idea: blocking schedules use your local time |
| `DNSERV_CLUSTER_ADVERTISE` | `192.168.1.10:8091` | You run 2+ servers and changed host port 8081, or this server is reached at a different address |
| `DNSERV_HTTPS` | `off` | Only to get back in after a bad dashboard certificate. Remove it afterwards |

### 5. Network and restart

- **Network:** use the normal **bridge** network (or a macvlan / `br0`
  network with its own IP). No privileged mode or extra capabilities.
  Avoid **host** networking: the container runs as a normal user and
  can't open port 53 directly on the host.
- **Restart policy:** `unless-stopped` (or "Always").
- Give the server a **fixed IP address** (a DHCP reservation in your
  router), because your devices will point at it.

### 6. Finish setup in the browser

1. Open the container's **logs** in your GUI and find the line with
   `setup_code`.
2. Open `http://<server address>:8080`, enter the code, create the admin
   account and scan the two-factor QR code.
3. In your router, set the **DHCP DNS server** to this server's address.
   Devices switch over as they renew (or reconnect them).

### Notes for specific systems

- **Unraid:** Unraid's own web page uses ports 80/443, so map container
  443 to e.g. 8443, or give the container its own IP on the `br0` network
  (then all ports stay as they are). Use `/mnt/user/appdata/dnserv` for `/data`.
- **Synology:** follow the step-by-step
  [Synology guide](https://github.com/prezmc/DNServ/blob/main/docs/install-synology.md)
  (Container Manager project, ports, folders, HTTPS with DSM's reverse proxy).
- **Portainer:** use **Stacks > Add stack** and paste the compose file
  linked above. That also gives you one-click updates.
- **TrueNAS SCALE:** use **Apps > Discover > Custom App** (or Install via
  YAML with the compose file). TrueNAS's web page uses 80/443, so map 443
  to another port.
- **Ubuntu / Debian:** if port 53 is "already in use", turn off
  systemd-resolved's stub listener: set `DNSStubListener=no` in
  `/etc/systemd/resolved.conf`, then `sudo systemctl restart systemd-resolved`.

## Updating

- **Compose install:** open **Updates** in the dashboard and press
  **Install update**.
- **GUI install:** use your GUI's "pull latest image / recreate" button
  (Portainer: *Recreate* with *Pull latest image*; Unraid: *Check for
  updates*). Your settings and history are kept in `/data`.

## More

- Two servers that stay in sync: https://github.com/prezmc/DNServ/blob/main/docs/deploy-two-servers.md
- All settings and ports: https://github.com/prezmc/DNServ/blob/main/docs/install.md
- Moving from AdGuard Home: https://github.com/prezmc/DNServ/blob/main/docs/adguard-import.md

License: Apache-2.0
