# Filtering

## Rule syntax

| Rule | Matches |
|---|---|
| `\|\|ads.example^` | `ads.example` and every subdomain |
| `*.ads.example` | subdomains only, not `ads.example` itself |
| `ads.example` or `0.0.0.0 ads.example` | exactly that name |
| `@@\|\|cdn.example^` | never blocks it or its subdomains |
| `\|\|ad-*.cdn.example^` | `*` matches any text: `ad-1.cdn.example`, `x.ad-eu.cdn.example` |
| `\|piwik.` | names that start with `piwik.` (`\|` is the start of the name, `^` the end) |
| `/^[a-z]{5}-[a-z]{5}\.xyz$/` | a regular expression (Go's RE2 syntax, case-insensitive) over the name |
| `\|\|top^$denyallow=good.top` | `top` and its subdomains, except `good.top` and its subdomains |
| `\|\|ads.example^$badfilter` | switches off `\|\|ads.example^` in every list |

Custom rules beat lists. At the same level, an allow rule beats a block.

Answers are checked too, as in AdGuard Home. A name that is an alias
(CNAME) for a blocked name is blocked, and so is an answer whose IPv4
address has a rule of its own (`||203.0.113.9^` or `203.0.113.9`). A name
you allow keeps its answer whatever it points to. The query log shows the
rule that matched, so a block "by CNAME" shows the alias's rule.
Rules that can't apply to a DNS name are skipped and counted, so the index
never claims to block something it doesn't: cosmetic rules, URL rules with a
path or port, regexes RE2 can't run (lookaheads, backreferences), and
modifiers other than `$important`, `$denyallow` and `$badfilter` (`$client`,
`$dnstype` and `$dnsrewrite` among them).

Wildcard and regex rules are indexed by three letters of the text each one
needs, so a lookup only tries the few whose letters the name contains: the
AdGuard DNS filter and Dandelion Sprout's anti-malware list (about 700 such
rules together) add well under a microsecond per lookup.

## Blocked services and safe search

**Settings > Blocked services and safe search** blocks well-known apps and
sites with one tick each (YouTube, TikTok, Roblox, Discord and about 35
more), for everyone. A group on the Devices page can block more services for
its devices, all the time or only during a schedule (homework time, say).
Each service is a short, hand-checked list of the domains it needs, so
blocking one doesn't take shared Google, Meta or Microsoft domains with it.
An allow rule of your own still wins.

**Safe search** makes Google, Bing and DuckDuckGo show only safe results and
puts YouTube in Restricted Mode (moderate), the way those companies ask
networks to do it: the search site's name is answered as an alias for its
safe-search address. A group can turn it on or off for its devices whatever
the household setting is.

## Stopping devices from bypassing DNServ

Blocking resolver names only goes so far, because a device can still use a
resolver by IP. On your router or firewall:

1. Block outbound TCP and UDP port 853 (DNS over TLS) from every device
   except the DNServ hosts.
2. Redirect (DNAT) outbound port 53 from devices to DNServ, so hard-coded
   `8.8.8.8` still reaches it.

[Back to the README](../README.md)
