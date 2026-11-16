# Installing on a Synology NAS

This guide uses **Container Manager**, Synology's Docker app, on DSM 7.2 or
newer. It takes about ten minutes. You don't need SSH.

Your NAS needs an Intel/AMD or ARMv8 processor. Most "+" models have one.
If Container Manager isn't in Package Center, your model can't run
containers.

## Before you start

1. **Give the NAS a fixed IP address.** Your devices will use it for DNS.
   Set a DHCP reservation in your router, or set a manual address under
   **Control Panel > Network > Network Interface**.
2. **Make sure port 53 is free.** If Synology's own **DNS Server** package
   is installed, stop it or uninstall it in **Package Center**. Two DNS
   servers can't share port 53.
3. **Install Container Manager** from **Package Center**. It creates a
   shared folder called `docker`.

## 1. Make the folders

Container Manager won't create folders for you, so make them first. Open
**File Station** and, inside the `docker` shared folder, create
`dnserv`. Inside `dnserv`, create `data`.

You end up with `docker/dnserv/data`. Settings, history and backups live
there, and Hyper Backup can back it up like any other folder.

If your `docker` share isn't on Volume 1, check which volume it is on under
**Control Panel > Shared Folder**. Then change `/volume1` in the next step
to match.

## 2. Create the project

1. Open **Container Manager > Project > Create**.
2. Fill in:
   - **Project name:** `dnserv`
   - **Path:** pick `docker/dnserv`
   - **Source:** **Create docker-compose.yml**
3. Paste this in, and change the time zone on the `TZ` line to yours:

```yaml
services:
  dnserv:
    image: prezmcmahon/dnserv:stable
    container_name: dnserv
    restart: unless-stopped
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "853:853/tcp"      # DNS over TLS for phones and laptops
      - "8443:443/tcp"     # DSM already uses 443, so HTTPS goes on 8443
      - "8080:8080/tcp"    # the dashboard
      - "8081:8081/tcp"    # only used if you add a second DNServ server
    volumes:
      - /volume1/docker/dnserv/data:/data
      - dnserv-updater:/run/dnserv-updater
    environment:
      - TZ=America/Chicago

  # Installs updates when you press the button on the Updates page.
  # Delete this whole block if you'd rather update by hand.
  dnserv-updater:
    image: prezmcmahon/dnserv:stable
    container_name: dnserv-updater
    restart: unless-stopped
    command: ["-updater"]
    user: "0:0"
    network_mode: none
    healthcheck:
      disable: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - dnserv-updater:/run/dnserv-updater

volumes:
  dnserv-updater:
```

4. Press **Next**. If you're offered **Web portal settings** (Web
   Station), leave them off. They're for websites, not DNS. Press
   **Next**, then **Done**. Container Manager downloads the image and
   starts it.

The folder you made in step 1 doesn't need any permission changes.
DNServ takes it over when it starts.

## 3. Finish setup in the browser

1. In **Container Manager > Container**, open **dnserv**, go to the
   **Log** tab and find the line with `setup_code`.
2. On your computer, open `http://<NAS address>:8080`, enter the code,
   create your admin account and scan the two-factor QR code.
3. Pick your blocklists and how lookups leave your network.

## 4. Point your network at it

In your router's DHCP settings, set the **DNS server** to the NAS's
address. Devices switch over as they renew their address, or straight
away if you reconnect them.

Leave the NAS's own DNS alone (**Control Panel > Network > General**).
DSM doesn't need to use DNServ, and leaving it alone keeps the NAS online
if the container stops.

### Check that you see each device

Open **Devices** in the dashboard after a few minutes. If you see your
phones, laptops and TVs by name or address, you're done.

On some NAS models, Docker makes every lookup look like it came from the
same address, something like `172.17.0.1`. Blocking still works for
everyone, but you lose per-device statistics and per-device rules. If that
happens, give DNServ its own address on your network, as described below.

## Optional: give DNServ its own IP address

This uses a **macvlan** network. DNServ gets its own address on your
network, such as `192.168.1.53`, and sees every device's real address.
Ports can't clash with DSM, so HTTPS can stay on 443.

There's one catch: the NAS itself can't reach that address. Open the
dashboard from another computer, and don't point DSM's own DNS at it.

1. Pick a free address outside your router's DHCP range.
2. In **Container Manager > Project**, select **dnserv**, then **Action >
   Stop**. Open the **YAML** tab and change the `dnserv` service, and the end
   of the file, like this. Use your own subnet, router address and the
   address you picked.

```yaml
services:
  dnserv:
    image: prezmcmahon/dnserv:stable
    container_name: dnserv
    restart: unless-stopped
    networks:
      lan:
        ipv4_address: 192.168.1.53
    volumes:
      - /volume1/docker/dnserv/data:/data
      - dnserv-updater:/run/dnserv-updater
    environment:
      - TZ=America/Chicago

  # dnserv-updater: keep exactly as it was

networks:
  lan:
    driver: macvlan
    driver_opts:
      parent: eth0         # ovs_eth0 if Virtual Machine Manager is installed; bond0 for bonded ports
    ipam:
      config:
        - subnet: 192.168.1.0/24
          gateway: 192.168.1.1

volumes:
  dnserv-updater:
```

3. Save it and start the project again. The `ports:` lines are gone on
   purpose: everything is on the new address. The dashboard is at
   `http://192.168.1.53:8080`. Point your router's DHCP DNS at
   `192.168.1.53`.

## Optional: HTTPS with a name

Pick whichever of these fits your setup:

- **Let DNServ do it** (works with either network setup). In the dashboard,
  go to **Settings > Dashboard HTTPS** and choose **Let's Encrypt**. See
  [Dashboard HTTPS](https.md).
- **Use DSM's reverse proxy** (bridge setup only, because the NAS can't
  reach a macvlan address):
  1. **Control Panel > Login Portal > Advanced > Reverse Proxy > Create**.
  2. **Source:** protocol `HTTPS`, hostname `dns.yourdomain.com`, port
     `443`. **Destination:** protocol `HTTP`, hostname `localhost`, port
     `8080`.
  3. Under **Control Panel > Security > Certificate > Settings**, pick a
     certificate for the new entry.
  4. Add `DNSERV_ALLOWED_ORIGINS=dns.yourdomain.com` under `environment:`
     in the project's YAML. Then stop and start the project.

  Keep this name inside your network. The dashboard controls your DNS, so
  don't open port 443 to the internet for it.

## Updating

Open **Updates** in the DNServ dashboard and press **Install update**.
DNServ backs itself up first, and rolls back if the new version doesn't
start.

If you removed the updater block, go to **Container Manager > Project >
dnserv > Action > Stop**, then **Image**, select
`prezmcmahon/dnserv` and **Update**, then start the project again.

## If something goes wrong

| What you see | What to do |
|---|---|
| Project won't start: "port is already allocated" on 53 | The DNS Server package (or another DNS container) is using port 53. Stop it in Package Center. |
| "port is already allocated" on 8080 or 8443 | Something else uses it. Change the number on the **left** of the colon (e.g. `"8090:8080/tcp"`), and use that port in the browser. |
| "bind source path does not exist" | The `docker/dnserv/data` folder is missing, or the share is on another volume. Check step 1. |
| `permission denied` in the log on an older image | Update to the current image. It sorts out folder permissions itself. |
| Can't open the dashboard with the macvlan setup | Use another computer. The NAS can't reach a macvlan container. |
