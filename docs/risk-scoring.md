# Security overview and risk scoring

DNServ checks every domain your devices look up against public threat
feeds and a few checks on the name itself, and gives it a risk score from
0 to 100. **Scores never block anything.** They decide what the
Dashboard, the Security page and the Query log point out, so you can decide what
to block.

<p align="center"><img src="images/security-page.png" alt="Security page" width="800"></p>

## What you see

- **Activity → Security** puts it all on one page: the same verdict and
  Needs attention list as the Dashboard card below, every risky domain in
  the period (up to 50, each with its reasons, lookups and a Block
  button), and for admins the scoring guide, Tune scoring and a link to
  the feeds and keys (System → Risk scoring).
- **Dashboard → Security.** A verdict for the period: "All clear: nothing
  risky got through", or how many high-risk domains your devices got
  answers for, who reached them, and how many threats were blocked anyway.

  <img src="images/security.png" alt="Security card on the Dashboard" width="500">
  **Needs attention** lists each one with why it's risky, the devices
  (each opens its Query log) and when, and three buttons:
  - **Block** blocks it and its subdomains for every device.
  - **Trust** marks it as a false alarm: it scores 0 from then on.
  - **Dismiss** hides it until a device reaches it again. Dismissals are
    shared by every server.

  The card also names any feed that isn't being checked (no abuse.ch key,
  or a failed download).
- **The queries chart** marks the hours when something risky got through.
- **Analytics → Risky domains** lists the riskiest domains seen, for
  everyone or one device.
- **Query log** shows a badge on risky lookups (hover for why) and filters
  by risk: low and above, medium and above, or high only. The CSV export
  follows the filter.
- **Domain details** show the score, the reasons and **how the score adds
  up**, or that the domain was checked and nothing was found.

## Finding the app behind a risky lookup

**Analyze** (on risky rows in the Query log, on Needs attention items, and next to each device in a risky domain's details) guesses which app or site made a device look the domain up. It reads that device's other lookups in the minute either side, at up to five of the times it asked, and weighs them:

- lookups just before count most (an app looks up its own name before what it loads), and names that show up near every one of those times count more;
- a lookup whose answer was a CNAME to the risky domain, or one on the same site, is a strong hint;
- ads, trackers and CDNs, and anything your blocklists blocked every time, are listed under **Also nearby** rather than as the source;
- something the device looks up all the time (a mail or iCloud check) is marked as maybe unrelated, and a risky domain that is itself looked up on a steady beat is called out as background activity.

It is a guess from timing, never proof, and it only works when individual queries are kept (History in Settings). It runs only when you press the button, from saved history on every server, so it never slows DNS answers.

## Where the data comes from

| Source | Lists | Default points |
|---|---|---|
| [URLhaus](https://urlhaus.abuse.ch/) (abuse.ch) | Malware hosts | 90 |
| [ThreatFox](https://threatfox.abuse.ch/) (abuse.ch) | Malware and command servers | 90 |
| [Phishing Army](https://phishing.army/) | Phishing sites | 80 |
| [HaGeZi Threat Intelligence Feeds](https://github.com/hagezi/dns-blocklists) (medium) | Malware, scams, command servers (covers subdomains) | 70 |
| [Feodo Tracker](https://feodotracker.abuse.ch/) (abuse.ch) | Botnet command server addresses | 90 |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Hijacked or criminal networks | 85 |

URLhaus and ThreatFox need a free abuse.ch Auth-Key: sign in at
[auth.abuse.ch](https://auth.abuse.ch/), copy the key from your profile,
and paste it under **System → Risk scoring → abuse.ch key**. The key is shared with
your other servers, never shown again and not part of backups.

Each server downloads the sources itself, keeps them in `/data/threat`,
and refreshes them twice a day (about 30 MB of memory). The lists are
matched on your own servers, so your lookups are never sent anywhere.
Turn the feeds off, or list trusted domains, under **System → Risk scoring
scoring**.

## How a score adds up

1. The strongest list that has the domain sets the score (its points).
2. Each further list that has it adds 5.
3. Name checks add points: an often-abused top-level domain (15), a
   machine-generated look (25), look-alike international characters (15),
   mostly digits (10), an unusually long name (10). On their own they add
   at most 45, so a name alone reaches Medium at most; on top of a list,
   at most 10. Domains of companies in AdGuard's companies database skip
   the name checks.
4. The total is capped at 100.

Separately, when history is saved, each answer is checked: a domain that
answers with an address on Feodo Tracker or Spamhaus DROP, or is an alias
(CNAME) for a Medium-or-higher domain, gets that score if it is higher.

**Levels:** Low is 1 to 39, Medium 40 to 69, High 70 and up. High-risk
domains that get an answer go under Needs attention.

**System → Risk scoring → How risk scores work** shows all of this from
the numbers in force, so it stays right after you change them.

## Tuning

<p align="center"><img src="images/scoring.png" alt="Tune scoring" width="600"></p>

**System → Risk scoring → Tune scoring** (needs "Manage blocklists")
starts from a preset and lets you change every number:

| Preset | What it does |
|---|---|
| Balanced | The defaults above |
| Sensitive | Name checks count for more, further lists add 10, Medium starts at 30 and High at 60. More alerts, some false alarms |
| Quieter | Name checks count half, HaGeZi gives 65, Medium starts at 50 and High at 80. Only strong evidence makes a domain High |

Before you save, the dialog shows how many of the domains seen in the
last 7 days would be at each level, and which would rise or drop. The
scoring is a setting like any other: shared by every server, in settings
history and backups, and **Back to defaults** resets it. Scores are worked
out when they're shown, so a change applies to your whole history at
once, except the answer checks, which are scored as lookups happen.

In a config file:

```yaml
analytics:
  threat_feeds: true
  trusted_domains: [example.com]
  risk_scoring:
    feeds: {urlhaus: 90, threatfox: 90, phishingarmy: 80, hagezi-tif: 70, feodo: 90, drop4: 85, drop6: 85}
    corroboration: 5
    names: {tld: 15, generated: 25, lookalike: 15, digits: 10, long: 10}
    name_cap: 45
    name_cap_listed: 10
    medium: 40
    high: 70
```

Values left out keep their defaults; a feed at 0 is ignored.

## Location data

**Risk scoring → Location data** (off by default) downloads DB-IP's free
IP to Country Lite database ([db-ip.com](https://db-ip.com), CC BY 4.0) on
each server, a few MB, refreshed monthly. With it on:

- Analytics shows **Where answers point**: answered lookups by the country
  of the domain's address. Click a country for its busiest domains.
- The Query log shows each answer's country and can be filtered by one;
  the CSV export gets a country column.
- Domain details say which countries a domain's addresses are in.
- The traffic map gets a **By country** view.
- **Countries to mark as risky**: an answer pointing to one of them adds
  risk points (40 by default, Medium; change it in Tune scoring). Like the
  address lists, it applies to new lookups.

It never blocks anything, and lookups happen when history is written, never
while answering. Big sites usually answer from servers near you (CDNs), so
countries show where servers are, not who runs a site. Existing history is
kept: countries are noted in a separate table, filled in for the history
you already have when the data first loads, and cleared if you turn it off.

## Also

- **On your lists.** A domain's details list every enabled blocklist with
  a rule for it.
- **VirusTotal.** Add your own free API key under System → Risk scoring → VirusTotal to
  get a **Check on VirusTotal** button in domain details. Only the domain
  you click is sent, at most 4 a minute, and results are kept for a day.
- **Domain types.** Each domain's type and owner (Advertising · Google)
  come from AdGuard's companies database (CC BY-SA 4.0).

[Back to the README](../README.md)
