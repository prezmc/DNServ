# More than two DNS nodes behind two DNS addresses

Most devices, and most routers' DHCP settings, accept only two DNS servers.
With three or more DNServe nodes, you can point clients at two of them, and
those two then carry all the traffic. A floating address (a "virtual IP" or
VIP) lets clients use two fixed addresses while any number of nodes stand
behind them.

DNServe doesn't manage floating addresses itself. This page explains how they
work, what they need from your network, and how to set them up next to
DNServe with keepalived if you want them.

## Do you need this?

Usually not:

- **1 or 2 DNS nodes:** give clients the nodes' own addresses. Devices
  already fail over to the second DNS server when the first doesn't answer.
- **3 or more DNS nodes:** clients still only use the two they are given.
  The others back up the cluster's settings and can be swapped in by
  changing the router's DNS setting. Floating addresses make that swap
  automatic.

A witness doesn't answer DNS, so it doesn't count here.

## How a floating address works

On a LAN, a device finds the machine behind an IP address by broadcasting
"who has 192.168.1.53?" (ARP; Neighbor Discovery for IPv6). Whoever owns the
address answers with its network card's hardware (MAC) address.

To take over a floating address, a node adds it to its network card and
announces "192.168.1.53 is me now" to the whole LAN (a gratuitous ARP).
Every device updates its table, and the next DNS query goes to the new
holder. This takes a second or two. Routers and clients need no changes.

The usual setup has **two floating addresses**, for example `.53` and `.54`,
each preferring a different node so the load is shared. When a node goes
down, a healthy node picks up its address. The router hands out the two
floating addresses as DNS servers.

## What it needs from your network and containers

**Host networking.** By default a Docker container sits on Docker's
private network (172.17.x.x), and Docker forwards published ports from the
host to it. Such a container can't add an address to the host's network
card or send announcements on your LAN. Whatever manages the floating
address must run on the host itself, or in a container with
`network_mode: host`.

**Two network permissions.** Adding an address and sending ARP
announcements need `NET_ADMIN` and `NET_RAW` (in a container:
`cap_add: [NET_ADMIN, NET_RAW]`). This is narrower than running privileged.

**One LAN segment.** All nodes that can hold a floating address must be on
the same LAN (the same subnet, with no router between them). A node
elsewhere, such as another building or a cloud VM, can still be a cluster
member and answer DNS on its own address. It just can't hold a floating
address.

**Two spare addresses outside the DHCP range.** Reserve them, or keep them
out of your router's DHCP pool, so no device is ever handed one.

**Linux hosts.** Host networking only behaves properly with Docker on
Linux, not Docker Desktop on macOS or Windows.

**Virtual machines.** If a node is a VM, its virtual switch must let it
answer for an extra IP address. Proxmox allows this by default. VMware ESXi
may need "forged transmits" and "MAC address changes" accepted on the port
group. Hyper-V may need "MAC address spoofing" enabled on the VM's network
adapter.

## DNS must listen on the floating addresses

DNServe's default `dns.listen` is `:53`, so it answers on every address the
host has, including a floating address added later. This works only when
DNServe can see the host's addresses, which means it also runs with
`network_mode: host`. Behind Docker's port publishing (`-p 53:53`), traffic
reaches DNServe only for the host addresses that existed when Docker set up
the port. Run DNServe with host networking on any node that will hold a
floating address.

```yaml
services:
  dnserve:
    image: ghcr.io/prezmc/dnserve:latest
    container_name: dnserve
    restart: unless-stopped
    network_mode: host   # no ports: list; DNServe listens on the host
    volumes:
      - dnserve-data:/data
volumes:
  dnserve-data:
```

With host networking, port 53 must be free on the host. On many Linux hosts
systemd-resolved holds it (see "Port 53 already in use?" in the README).

## Setting it up with keepalived

[keepalived](https://www.keepalived.org/) implements VRRP, the standard
protocol for floating addresses. Install it on each DNS node's host (for
example `apt install keepalived`). Then give each host a config like the one
below, swapping the priorities on the second node so each address prefers a
different node.

`/etc/keepalived/keepalived.conf` on node 1:

```
vrrp_script dnserve_ready {
    # DNServe's readiness check: lists loaded and resolvers answering.
    script "/usr/bin/curl -fsS --max-time 2 http://127.0.0.1:8080/readyz"
    interval 2
    fall 2
    rise 2
}

vrrp_instance DNS_A {
    interface eth0               # your LAN interface
    virtual_router_id 53         # any number 1-255, the same on every node
    priority 150                 # node 1 prefers address A
    advert_int 1
    virtual_ipaddress {
        192.168.1.53/24
    }
    track_script {
        dnserve_ready
    }
}

vrrp_instance DNS_B {
    interface eth0
    virtual_router_id 54
    priority 100                 # node 2 uses 150 here and 100 above
    advert_int 1
    virtual_ipaddress {
        192.168.1.54/24
    }
    track_script {
        dnserve_ready
    }
}
```

A third or later node uses lower priorities (for example 50) for both
addresses. It takes an address only when both preferred nodes are down.

Then set your router's DHCP DNS servers to `192.168.1.53` and
`192.168.1.54`.

To check it: stop DNServe on node 1 (`docker stop dnserve`). Within a few
seconds `ip addr` on node 2 shows `192.168.1.53`, and lookups against `.53`
keep working.

## Things to know

- **The address follows DNS health, not the cluster.** keepalived moves
  an address when `/readyz` fails or the host stops answering VRRP. It
  doesn't know about Raft, and it doesn't need to: every node answers DNS
  from its own copy of the settings, so any node can hold either address.
- **Network splits.** If two nodes can't hear each other's VRRP messages
  but are both up, both may claim an address for a while. Devices then
  reach whichever answered last. Both give the same answers, so DNS keeps
  working. Avoid this by keeping the nodes on the same switch or VLAN.
- **Per-device rules follow the client's address,** not the server's, so
  groups and schedules work the same through a floating address.
- **Recent queries are per node.** While an address moves, a device's
  queries appear on whichever node held it. Analytics that merge all nodes
  are planned.

## Why not other approaches

- **A load balancer in front of DNServe** becomes a new single point of
  failure, unless it is itself made redundant with floating addresses.
- **Anycast** (the same address announced from several places with BGP) is
  how big public resolvers do this. It needs a router that speaks BGP, which
  is overkill for a home or small office.
- **Handing out more than two DNS servers** works on some devices, but many
  use only the first two, and the order and behavior vary by platform.
