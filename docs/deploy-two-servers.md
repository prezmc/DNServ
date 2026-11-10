# Running DNServ on two servers

This guide sets up DNServ on two Linux servers, with an optional witness on a
third machine, and explains what happens when something breaks. Everything in
the "What happens when" table is checked by the failover tests in
[`test/failover`](../test/failover), which run on every pull request.

## What you need

- **Two Linux servers** (x86-64 or ARM64) with Docker and Docker Compose.
  They don't need to be big; DNServ answers tens of thousands of queries a
  second on a 4-core machine.
- **A fixed address for each**, set as a DHCP reservation on your router or
  configured on the server. Devices are given these addresses as their DNS
  servers, so they must not change.
- **Optional: a third machine for a witness** (a Raspberry Pi, a NAS that
  runs containers, any always-on box). It lets either server go down without
  pausing changes. Don't run it on one of the two DNS servers: if that
  server dies, the witness goes with it.

## Ports

| Port | Who needs to reach it | What for |
|---|---|---|
| 53 UDP and TCP | Your devices | DNS |
| 853 TCP | Your devices (optional) | DNS over TLS (Android Private DNS and others) |
| 443 TCP | Your devices (optional) | DNS over HTTPS, if you uncomment it in the compose file |
| 8080 TCP | You, from your own network | Dashboard and setup |
| 8081 TCP | The other DNServ server and the witness only | Keeping settings in sync. Encrypted and authenticated with the cluster's own certificates |

Don't expose any of these to the internet. If you use a firewall on the
servers (ufw shown, with your network as `192.168.1.0/24`):

```sh
sudo ufw allow from 192.168.1.0/24 to any port 53
sudo ufw allow from 192.168.1.0/24 to any port 853 proto tcp
sudo ufw allow from 192.168.1.0/24 to any port 8080 proto tcp
sudo ufw allow from 192.168.1.20 to any port 8081 proto tcp   # the other server
sudo ufw allow from 192.168.1.30 to any port 8081 proto tcp   # the witness
```

### Port 53 is already in use

On Ubuntu and some other distributions, systemd-resolved listens on port 53,
and DNServ can't start (`address already in use`). Turn off its listener and
point the server itself at a public resolver (or at the other DNServ):

```sh
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\nDNS=1.1.1.1\n' | sudo tee /etc/systemd/resolved.conf.d/dnserv.conf
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved
```

## Set up

1. **First server.** Copy [`docker-compose.yml`](../docker-compose.yml) to
   it (set `TZ` to your time zone) and run `docker compose up -d`. Run
   `docker compose logs` to see the setup code, open
   `http://<first server>:8080`, enter the code and follow the wizard.
2. **Second server.** Same file, `docker compose up -d`. On the first
   server's dashboard open **Cluster** and choose **Make a join code**. Check
   that "Other nodes reach this one at" is the first server's address. Open
   `http://<second server>:8080`, enter its setup code from its log, choose
   **No, add this server to my DNServ** and paste the join code. A few
   seconds later the second server has the same accounts, settings and
   blocklists, and both show as healthy on the Cluster page.
3. **Witness (optional).** Make another join code; the dialog shows the
   command to run on the third machine, or use
   [`deploy/docker-compose.witness.yml`](../deploy/docker-compose.witness.yml)
   with the code in `DNSERV_JOIN`.
4. **Router.** In your router's DHCP settings, set the DNS servers to the two
   DNServ addresses, first server first. Devices pick up the change when
   they renew their lease (reconnect to Wi-Fi to hurry one along). Remove
   any other DNS servers there, or devices will use them to get around
   blocking.

The servers find each other by the addresses on the Cluster page. If they are
on different networks (two sites over a VPN, for example), set
`DNSERV_CLUSTER_ADVERTISE=<address the other server uses>:8081` in each
compose file.

## What happens when

Settings, rules and blocklists are the same on both servers. A change on
either one reaches the other within about a second, and the leader downloads
the blocklists for both, so both use the exact same version of each list.

DNS never waits for the other server: each one answers from its own copy of
the settings. In the failover tests, a client sending 50 queries a second to
each server got an answer to every query sent to a running server, in every
case below, with a typical answer in about 0.3 ms.

| What breaks | DNS | Changes (settings, rules, users) | What you do |
|---|---|---|---|
| One server goes down, with a witness | The other server answers. Devices move to it on their own | Keep working. If the leader was lost, the other server takes over in about 2 seconds | Start it again. It catches up within a second |
| One server goes down, no witness | The other server answers | Pause until it is back, unless the down server was set to **Never lead** | Start it again, or if it's gone for good, see below |
| The witness goes down | Unaffected | Keep working | Start it again |
| The link between the servers breaks | Both keep answering with the settings they had | Keep working on the side with the witness; pause on the other. Without a witness, pause on both | Fix the link. The cut-off server catches up straight away. Don't recover a server just because it can't see the other one |
| Both servers restart (power cut) | Each answers with its saved settings within a second of starting | Resume once both, or one and the witness, are up (about 2 seconds) | Nothing |
| A server is lost for good | The other server answers | Pause (no witness), or keep working (witness) | See below |

**How quickly devices switch.** When a DNS server stops answering, devices
retry the other one. How long that takes depends on the device, from about a
second to several seconds, and many devices then stay on the server that
answers for a while. To
make the switch instant, see
[floating DNS addresses](floating-dns-addresses.md).

### A server is lost for good

With a witness, nothing is urgent: changes keep working. Remove the lost
server under **Cluster** and add a replacement with a new join code.

Without a witness, changes are paused until you tell the surviving server
it's on its own: open **Cluster** on it and choose **Recover with this node
only**. It asks you to confirm, because it can't tell a server that is
switched off from a broken link. If the other server is in fact still
running, recovering both would leave two separate DNServs with different
settings. So only recover when you know the other one is off, broken or
wiped.

If the old server comes back anyway, it shows that it was left out, keeps
answering DNS with its old settings, and refuses to recover on its own. To
use it again, make a join code on the working server and use **Join another
DNServ** on the old one.

## Upgrading

Upgrade one machine at a time, so one server is always answering DNS:

1. The witness, if you have one.
2. The server that isn't leading (the Cluster page shows which one leads).
3. The leading server. The other one takes over while it restarts.

On each one run `docker compose pull && docker compose up -d`, then wait until
the Cluster page shows it as healthy before moving on. In the failover tests,
each node was back in under 2 seconds and no DNS query went unanswered.

Mixed versions are fine for the time an upgrade takes. Don't leave a cluster
on mixed versions for long.

## Try it on your own servers

After setting up, check failover yourself. From any computer on your
network (use `nslookup example.com <address>` on Windows):

1. `dig @<first server> example.com` and `dig @<second server> example.com`
   both answer.
2. On the second server run `docker compose stop`. `dig @<first server>
   example.com` still answers, and with a witness, a change on the first
   server's dashboard (add a rule, say) still saves.
3. `docker compose start` on the second server. Within a few seconds the
   Cluster page shows both healthy, and the change you made is on the second
   server too.
4. Repeat with the first server stopped.
5. On a phone, browse for a minute while one server is stopped, to see how
   your devices cope.

## Running the failover tests

The tests start real containers on a machine with Docker:

```sh
go test -tags failover -v -timeout 30m ./test/failover/
```

They build the image from this repository, or test another one with
`DNSERV_IMAGE=ghcr.io/prezmc/dnserv:latest`. `FAILOVER_REPORT=report.md`
writes the results table; `FAILOVER_KEEP=1` leaves the containers running for
a look afterwards.
