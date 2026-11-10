# Clustering

**[Running DNServ on two servers](deploy-two-servers.md)** is the full
guide: ports and firewall, the router, upgrades, what happens when a server
or the link between them fails, and what to do when a server is lost for
good.

Run the same image on a second server (same command or compose file, port
8081 published and open between the servers). Then:

1. On your first node, open **Cluster** and choose **Make a join code**.
2. Open the new node's dashboard, enter its setup code, choose **No, add
   this server to my DNServ**, and paste the join code.

The new node copies the accounts, settings, devices, groups and rules, and
from then on every change made on either node reaches both, usually within
a second. Blocklist contents are the same on every node too: the leader
downloads each list and the others copy its exact version over the cluster
link, so rule counts match. A node that can't reach the leader downloads
lists itself. **Update lists now** on any node asks the leader. Add the
second node's address to your router as a second DNS server.

How it works: every node runs embedded Raft (HashiCorp), alone or not.
Changes go through the leader's log and are applied on every node in the
same order; a change made on a follower is forwarded to the leader. Nodes
talk over one port (8081) with mutual TLS, using certificates from a private
CA the cluster creates for itself; the join code carries the CA's
fingerprint and a one-time secret (valid for an hour), so there is nothing to
copy between servers. A node that joins starts as a non-voter and votes once
it has caught up. Existing single nodes upgrade in place: their state becomes
the cluster's first log entry.

**DNS never waits for the cluster.** Each node answers from its own copy of
the settings, so a node cut off from the others keeps filtering with what it
last had. Without a leader only changes pause; sign-in still works (with an
authenticator code).

Leadership controls, under **Cluster**:

- **Make leader** hands leadership to another node now.
- **Prefer as leader**: the node leads whenever it is up and caught up.
- **Never lead**: the node keeps a full copy and answers DNS, but never
  leads or votes. With two nodes, this lets the other one take changes on
  its own even while this one is down.
- **Recover with this node only**, for when the other node is gone for good:
  the survivor becomes a cluster of one and keeps its settings. It refuses
  while any other node still answers, and refuses on a node the others
  have already recovered without. It asks again if the nodes left out could
  still have a majority between them, or if a full node left out might only
  be cut off (a node can't tell a switched-off server from a broken link,
  and recovering both sides would leave two separate clusters). Nodes left
  out are locked out (their certificates are no longer accepted) until
  they join again with a new code; their Cluster page says so.
- **Join another DNServ instead** moves a node that is set up already into
  another cluster, replacing its accounts and settings.

## How many nodes?

DNServ works with one node, two, or more. The Cluster page says how many
voting nodes can be down while changes still work.

| Setup | DNS if a node is down | Changes if a node is down |
|---|---|---|
| 1 node | Down | Down |
| 2 nodes | The other answers | Pause until it's back (or set one to Never lead) |
| 2 nodes + witness | The other answers | Keep working |
| 3 nodes | Others answer | Keep working |

A **witness** is the same image started with `DNSERV_ROLE=witness` on a
third machine. It votes and keeps the change log, but answers no DNS and has
no dashboard, so a Raspberry Pi or a NAS is plenty. It joins with a join code
in `DNSERV_JOIN` (the join-code screen shows the full command; see also
[`deploy/docker-compose.witness.yml`](../deploy/docker-compose.witness.yml)). If it wins an election it hands
leadership straight to a full node. Put it on a different machine from your
DNS nodes: a witness on the same box doesn't help when that box fails. With
an even number of full nodes (4, 6, …) a witness also lets the cluster lose
one more node.

Clients only take two DNS servers? See
[docs/floating-dns-addresses.md](floating-dns-addresses.md) for putting
any number of nodes behind two floating addresses with keepalived.

By default a node learns its cluster address from the address its dashboard
is opened at, or, for a witness, from the address the other node sees it
connect from. Set `DNSERV_CLUSTER_ADVERTISE` (for example
`192.168.1.10:8081`) if other nodes reach it differently, such as through a
different published port.

[Back to the README](../README.md)
