# Moving from AdGuard Home

Admins can bring an existing AdGuard Home's setup across from **Settings →
Import from AdGuard Home** (also offered at the end of the setup wizard).
Enter AdGuard Home's dashboard address, username and password: DNServe reads
its settings through AdGuard Home's own API, changes nothing there, and uses
the password once without saving it. You then see, section by section, what
would be added, what DNServe already has, and what can't move and why, and
tick what to import. Running it again adds only what's missing.

| AdGuard Home | Becomes in DNServe |
|---|---|
| Blocklists and allowlists (by URL) | Lists, added next to yours, with the same on/off state |
| Custom rules | Custom rules. Hosts lines with a real address and simple `$dnsrewrite` rules become local names |
| Blocked services for everyone | Custom rules with each service's domains |
| DNS rewrites | Local names (address, alias or `*.` wildcard) |
| Upstream DNS servers | Upstream (https, tls, plain addresses). Off to start with if any are unencrypted or you've already picked one |
| Private reverse DNS / `[/lan/]` upstream | Router for device names |
| Blocking mode | How blocked names are answered |
| Allowed clients | Allowed networks (off to start with) |
| Persistent clients with IP addresses, or MACs that have a DHCP reservation; DHCP reservations | Device names |
| Clients with filtering off, or their own blocked services | A group each, holding that device |

Not moved, and listed as such in the preview: `$client`/`$ctag`
rules, DNS-over-QUIC and DNS stamp upstreams, client IDs and CIDR clients,
schedules, safe browsing, parental control, safe search, DHCP serving and
query history. If AdGuard Home hands out addresses, turn DHCP back on in
your router before switching it off.

[Back to the README](../README.md)
