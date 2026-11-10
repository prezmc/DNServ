# Tunnel mode

[`deploy/docker-compose.tunnel.yml`](../deploy/docker-compose.tunnel.yml) pairs
DNServe with [gluetun](https://github.com/qdm12/gluetun), which brings up
WireGuard for most VPN providers. DNServe shares gluetun's network, so all its
traffic goes through the tunnel and gluetun's firewall drops anything that
tries to leave outside it. Fill in your provider's WireGuard values and run
`docker compose -f deploy/docker-compose.tunnel.yml up -d`.

DNServe also checks the tunnel every 30 seconds: the interface must be up,
and if you set `expected_egress`, the address that authoritative servers see
must be one of your VPN's. If a check fails, DNServe either falls back to
encrypted forwarding (`on_down: forward`, the default; your ISP still sees
nothing) or stops resolving (`on_down: block`). The `dnserve_tunnel_up`
metric shows the state.

[Back to the README](../README.md)
