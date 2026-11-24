# Automating DNServ with the API

Anything you can change on the dashboard you can also change from a script,
Home Assistant, cron or a CI job. This guide shows how, with examples you can
copy. For the full list of endpoints, see the [Admin API](api.md) reference.

- [1. Make a token](#1-make-a-token)
- [2. Your first call](#2-your-first-call)
- [3. How requests work](#3-how-requests-work)
- [4. Recipes](#4-recipes)
- [5. Home Assistant](#5-home-assistant)
- [6. Python](#6-python)
- [7. Keeping tokens safe](#7-keeping-tokens-safe)

## 1. Make a token

1. Sign in to the dashboard and open **Account** (your name in the menu).
2. Under **API tokens**, give the token a name that says where it's used,
   such as `Home Assistant` or `nightly-script`.
3. Tick only what it needs (see the table below) and choose when it expires.
4. Click **Create token** and copy it. It is shown once. DNServ keeps only a
   hash, so a lost token can't be shown again. Revoke it and make a new one.

To rename a token or change what it can do later, click **Edit** next to
it. Scripts using it keep working with the same secret.

A token can never do more than your own account. If an admin later lowers
your role or disables your account, your tokens lose the same rights at
once. Revoking a token works on every server in the cluster.

| Tick this | To let the token |
|---|---|
| View dashboard (`dashboard.view`) | Read status, settings, devices, groups and analytics totals. Most scripts need this |
| View query logs (`querylog.view`) | Read single lookups and per-device history |
| Export data (`data.export`) | Download the query log as CSV |
| Block or allow domains (`domains.allowblock`) | Use `POST /domains` and dismiss security findings |
| Edit custom rules (`rules.edit`) | Replace the custom rule list |
| Manage blocklists (`lists.manage`) | Add, remove or turn off lists and allowlists, update lists now, clear the cache, blocked services, safe search, risk scoring |
| Pause filtering (`filtering.pause`) | Pause and resume blocking |
| Manage devices and groups (`devices.manage`) | Create and edit devices, groups and schedules |
| Change how DNS is resolved (`upstream.manage`) | Upstream servers, tunnel mode, cache size |
| Change allowed networks (`network.manage`) | Allowed networks, local names, time zone |

Admins can also tick the admin-only rights: users, the cluster, backups
and the audit log. Think twice before you do: a token with
those can add users or remove servers.

Some things always need a person signed in to the dashboard, whatever the
token can do: making or editing tokens, changing a password, and changing two-factor
or passkeys. A leaked token can't be used to take over an account.

## 2. Your first call

Set two variables so the rest of the examples work as written:

```sh
export DNSERV=http://192.168.1.10:8080      # any of your servers
export TOKEN=dns_xxxxxxxxxxxx.yyyyyyyyyyyy  # the token you copied
```

Then ask DNServ who you are:

```sh
curl -s -H "Authorization: Bearer $TOKEN" "$DNSERV/api/v1/auth/me"
```

```json
{"token":"nightly-script","perms":["dashboard.view","lists.manage"],"user":{"username":"admin","role":"admin", ...}}
```

`perms` is what this token may do. If you see
`{"error":"invalid or expired API token"}`, check that you copied the whole
token, including `dns_` at the start.

## 3. How requests work

- **Any server.** Send requests to any server in the cluster. Changes go
  to the leader and reach every server within about a second. Reads are
  answered by the server you ask.
- **JSON in, JSON out.** Send `Content-Type: application/json` with a body.
  Errors come back as `{"error": "…"}` with a status code: `400` the
  request is wrong, `401` the token is missing, wrong or expired, `403`
  the token isn't allowed to do this, `404` no such item.
- **Settings are patched by field.** `PATCH /api/v1/settings` changes only
  the fields you send. List fields (`lists`, `allowlists`, `rules`,
  `records`, `blocked_services`) are replaced as a whole, so to add one item
  read the list first, add to it, and send it back (see the recipes).
  `GET /api/v1/settings` returns `saved` (what was changed from the
  dashboard or API) and `effective` (what each server actually uses).
- **Everything is recorded.** Each change shows in the Audit log as
  `you (token nightly-script)`, and settings changes land in
  **Settings history**, so you can undo a script's mistake from the dashboard.
- **HTTPS.** If you turned on [dashboard HTTPS](https.md),
  use `https://` so the token isn't sent in the clear. With a self-signed
  certificate, add `--cacert` with the certificate rather than `-k`.

The examples below use [`jq`](https://jqlang.org/) to edit JSON. Install it
with `apt install jq` or `brew install jq`.

## 4. Recipes

A small helper keeps the examples short:

```sh
dnserv() {  # dnserv METHOD PATH [JSON]
  curl -sS -X "$1" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' ${3:+-d "$3"} "$DNSERV/api/v1$2"
}
```

### Block or allow one domain

Needs `domains.allowblock`.

```sh
dnserv POST /domains '{"domain":"ads.example.com","action":"block"}'
dnserv POST /domains '{"domain":"cdn.example.com","action":"allow"}'
dnserv POST /domains '{"domain":"ads.example.com","action":"clear"}'   # remove either
```

Changes take effect on every server within about a second. Check what
DNServ would do with a name, and why:

```sh
dnserv GET '/domains/check?name=ads.example.com'
```

```json
{"name":"ads.example.com","blocked":true,"allowed":false,"custom":true,"list":"Custom rules","rule":"||ads.example.com^"}
```

### Add a blocklist

Needs `dashboard.view` and `lists.manage`. Read the current lists, add one,
send them all back:

```sh
NEW=$(dnserv GET /settings | jq '.effective.Filtering.Lists // [] | . + [{
  "name": "HaGeZi Pro",
  "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
  "enabled": true }]')
dnserv PATCH /settings "{\"lists\": $NEW}" > /dev/null
dnserv POST /lists/update          # download it now instead of at the next refresh
```

To turn a list off without removing it, set its `enabled` to `false`:

```sh
NEW=$(dnserv GET /settings | jq '.effective.Filtering.Lists
  | map(if .name == "HaGeZi Pro" then .enabled = false else . end)')
dnserv PATCH /settings "{\"lists\": $NEW}" > /dev/null
```

Allowlists work the same way with the `allowlists` field
(`.effective.Filtering.Allowlists`).

### Replace the custom rules

Needs `rules.edit`. Useful for keeping your rules in a git repository and
pushing them from CI. Rules use the [filter syntax](filtering.md):

```sh
jq -Rn '[inputs | select(length > 0 and (startswith("#") | not))] | {rules: .}' my-rules.txt \
  | dnserv PATCH /settings "$(cat)" > /dev/null
```

### Add a device and put it in a group

Needs `devices.manage`.

```sh
GROUP=$(dnserv GET /groups | jq -r '.groups[] | select(.name=="Kids") | .id')
dnserv POST /devices "{\"name\":\"Tablet\",\"addrs\":[\"192.168.1.60\"],\"group\":\"$GROUP\"}"
```

`PUT /devices/{id}` changes a device. Send its `name` and `addrs`; leave
out `group` to keep the group it has, or send `"group": ""` to move it back
to the household settings.

### Make a group with a bedtime

Needs `devices.manage`. Days are numbers, `0` for Sunday through `6` for
Saturday, and times are in the time zone set under Settings:

```sh
dnserv POST /groups '{
  "name": "Kids",
  "services": ["tiktok"],
  "safe_search": "on",
  "schedules": [{
    "name": "School nights",
    "days": [0, 1, 2, 3, 4],
    "start": "21:00", "end": "07:00",
    "block_all": true
  }]
}'
```

`dnserv GET /services | jq -r '.services[].id'` lists the service ids you
can block. `PUT /groups/{id}`
replaces a group, so send all of its fields, not only the one you're
changing: read it with `GET /groups` first.

### Pause filtering for a while

Needs `filtering.pause`. Handy for a "something's broken, turn blocking
off" button:

```sh
dnserv POST /pause '{"minutes": 15}'   # every server; 0 = until turned back on
dnserv DELETE /pause                    # back on
```

### Read numbers for your own dashboard

Needs `dashboard.view` (and `querylog.view` for anything per lookup).

```sh
dnserv GET '/analytics/summary?range=24h' | jq '.counts'
dnserv GET '/analytics/top?by=blocked&range=24h'
dnserv GET /status | jq '{version, uptime_seconds, leader: .cluster.leader}'
```

## 5. Home Assistant

Put the token in `secrets.yaml`:

```yaml
dnserv_auth: "Bearer dns_xxxxxxxxxxxx.yyyyyyyyyyyy"
```

Then in `configuration.yaml`, a pause button and a sensor for today's
blocked lookups:

```yaml
rest_command:
  dnserv_pause:
    url: "http://192.168.1.10:8080/api/v1/pause"
    method: POST
    headers:
      Authorization: !secret dnserv_auth
    content_type: "application/json"
    payload: '{"minutes": {{ minutes | default(15) }}}'
  dnserv_resume:
    url: "http://192.168.1.10:8080/api/v1/pause"
    method: DELETE
    headers:
      Authorization: !secret dnserv_auth

rest:
  - resource: "http://192.168.1.10:8080/api/v1/analytics/summary?range=24h"
    headers:
      Authorization: !secret dnserv_auth
    scan_interval: 300
    sensor:
      - name: "DNServ lookups (24h)"
        value_template: "{{ value_json.counts.total }}"
      - name: "DNServ blocked (24h)"
        value_template: "{{ value_json.counts.blocked }}"
```

Give this token `dashboard.view` and `filtering.pause` only.

## 6. Python

No extra packages needed:

```python
import json, os, urllib.request

BASE = os.environ["DNSERV"] + "/api/v1"
TOKEN = os.environ["TOKEN"]

def call(method, path, body=None):
    req = urllib.request.Request(
        BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{method} {path}: {e.code} {json.loads(e.read())['error']}")

# Block every domain in a file.
for line in open("block-these.txt"):
    if line.strip():
        call("POST", "/domains", {"domain": line.strip(), "action": "block"})
```

## 7. Keeping tokens safe

- Give each script or app its own token, so you can revoke one without
  breaking the others, and so the Audit log says which one made a change.
- Tick only what it needs. A sensor needs `dashboard.view`, nothing else.
- Set an expiry for anything you won't look after, and make the token for
  a power user rather than an admin where you can.
- Keep tokens in a secrets file or your CI's secret store, never in a git
  repository.
- Glance at **Last used** under **Account > API tokens** now and then. It
  shows when and from which address each token was last used (updated
  every few minutes). A token that's never used can go; one used from an
  address you don't recognise has probably leaked.
- If a token leaks, revoke it under **Account > API tokens**. Admins can
  revoke anyone's token the same way (or delete the user).

[Admin API reference](api.md) · [Back to the README](../README.md)
