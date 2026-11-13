# Admin API

Everything is under `/api/v1` on port 8080. Browsers use a session cookie
plus the `X-CSRF-Token` header from the sign-in response; scripts use
`Authorization: Bearer dns_…` tokens.

| | Endpoint |
|---|---|
| First run | `GET /setup`, `POST /setup` `{code, username, password}`, `POST /setup/join` `{code, join_code, host}`, or `POST /setup/restore` (multipart: `file`, `passphrase`, `code`) |
| Sign in | `POST /auth/login`, then `POST /auth/mfa` `{code}` (authenticator or recovery code) |
| Enroll MFA | `POST /auth/totp/begin` (returns the secret and `otpauth://` URL), `POST /auth/totp/confirm` `{code}` |
| You | `GET /auth/me` (includes your `dashboard` layout), `PUT /auth/dashboard` `{layout}` (card names in order; `-name` hides a card, `name:s\|m\|l\|f` sets its size: small, medium, large or full width; `[]` is the default), `POST /auth/password`, `GET`/`DELETE /auth/sessions`, `POST /auth/logout`, `POST /auth/recovery-codes` `{password}`, `POST /auth/authenticator/begin` `{password}` then `/confirm` `{code}` |
| Users | `GET`/`POST /users`, `PATCH`/`DELETE /users/{id}`, `POST /users/{id}/password`, `POST /users/{id}/reset-mfa` |
| Tokens | `GET`/`POST /tokens`, `DELETE /tokens/{id}` |
| Settings | `GET`/`PATCH /settings`, `POST /settings/reset` `{fields}`. `cache_size` (1,000 to 5,000,000 answers, upstream.manage) resizes each server's cache at once |
| Local names | `PATCH /settings` `{records: [{name, value, note}]}` (the whole list; `value` is an IP address or another name) |
| Lists | `POST /lists/update` (download every list again now) |
| Dashboard HTTPS (admin) | `GET /https` (settings without the key or password, and each server's status); `PUT /https` `{mode: ""\|self_signed\|upload\|files\|npm, redirect, names, cert_pem, key_pem, cert_file, key_file, npm: {url, email, password, cert_id}}`; `POST /https/npm/certificates` `{url, email, password}` lists Nginx Proxy Manager's certificates |
| Clear history (admin) | `POST /analytics/clear` `{what: performance\|history}` deletes performance stats, or all query history, on every server |
| Pause filtering | `GET /pause`; `POST /pause` `{minutes, node}` (`minutes` 0 = until turned back on, up to 24 h; `node` omitted = every server); `DELETE /pause` (everything back on) or `DELETE /pause?node=<id>` |
| Block or allow | `POST /domains` `{domain, action: block\|allow\|clear}`, `GET /domains/check?name=` |
| AdGuard Home import (admin) | `POST /import/adguard/preview` `{url, username, password, insecure}` returns `{id, plan}`; `POST /import/adguard/apply` `{id, sections, exclude}` |
| Devices | `GET`/`POST /devices` `{name, addrs, group}`, `PUT`/`DELETE /devices/{id}` |
| Groups | `GET`/`POST /groups` `{name, rules, skip_blocklists, schedules: [{name, days, start, end, block_all, rules}], devices}`, `PUT`/`DELETE /groups/{id}` |
| Recent queries | `GET /queries?client=&search=&result=&before=&limit=` (`client` is an IP or device id; `result` is `blocked`, `allowed`, `failed`, …) |
| Analytics | `GET /analytics/summary`, `/analytics/top?by=domains\|allowed\|blocked\|clients\|lists` (`allowed` leaves out blocked lookups), `/analytics/performance`, `/analytics/domain?name=`, `/analytics/queries?search=&result=&before=`, `/analytics/export` (CSV), `/analytics/risky`, `/analytics/intel` (sources), `/analytics/alsoon?name=`, `POST /analytics/virustotal?name=`; `GET`/`PUT /virustotal` `{key}` (never returned); `PUT /abusech` `{key}` (never returned). `/analytics/queries` and `/analytics/export` also take `risk=low\|medium\|high`. The history views take `range=15m\|1h\|24h\|7d\|30d\|90d` and `client=` (IP or device id), and merge every node's history |
| Settings history | `GET /config/versions`, `GET /config/versions/{id}` (with the changes going back would make), `POST /config/versions/{id}/restore` |
| Backups | `GET /backups`, `POST /backups/passphrase` `{passphrase, password}`, `PUT /backups/schedule` `{every: daily\|weekly\|"", at: "HH:MM", keep, offsite}`, `POST /backups/download`, `GET /backups/files/{local\|offsite}/{name}`, `POST /backups/restore` (multipart: `file`, `passphrase`, `password`) |
| Security and traffic | `GET /analytics/security` (verdict, high-risk domains that got answers and who reached them, threats blocked, risky hours), `POST /analytics/dismiss` `{name, undo}` (domains.allowblock), `GET /analytics/flow?group=company\|type` (traffic map). Take `range=` and `client=` like the other history views |
| Cache and repeating lookups | `GET /analytics/cache` (up to 7 days: cache hits, misses and why they missed: `first`, `short` cache time, `expired`, `early`, `failed`, `unknown`, each with its top domains, plus `fill`: each server's cache right now, `{server, fill: {entries, fresh, usable, max, evicted}}`), `GET /analytics/beacons?limit=` (names devices look up on a steady beat in the last 24 hours, with the devices and their period when you may see the Query log). Take `range=` and `client=` |
| Risk scoring | `GET /analytics/scoring` (scoring in force, defaults, presets, sources, name checks), `POST /analytics/scoring/preview` with a scoring (levels now vs proposed over the last 7 days, and what would rise or drop). Save with `PATCH /settings` `{risk_scoring}` (lists.manage); reset with `POST /settings/reset` `{fields: ["risk_scoring"]}` |
| Cluster | `GET /cluster`, `POST /cluster/join-codes` `{host}`, `PUT /cluster/nodes/{id}` `{name, never_leader}`, `DELETE /cluster/nodes/{id}`, `POST /cluster/preferred` `{id}`, `POST /cluster/transfer` `{to}`, `POST /cluster/recover` `{password, accept_risk}`, `POST /cluster/join` `{join_code, host, password}` |
| Status and audit | `GET /status` (each list's status includes `changed`, when its owner last changed it, and `changed_from`: `list` header date, `server` Last-Modified, or `seen` when new contents arrived), `GET /audit` |

Permissions: `dashboard.view`, `querylog.view`, `data.export`,
`domains.allowblock`, `rules.edit`, `lists.manage`, `devices.manage`,
`upstream.manage`, `network.manage` (any of these can be given to a power
user), and the admin-only `users.manage`, `cluster.manage`,
`backups.manage`, `audit.view`.

Lost your phone? Sign in with a recovery code, or have another admin reset
your MFA. If the only admin is locked out, stop the node and run:

```bash
docker stop dnserv
docker run --rm -v dnserv-data:/data ghcr.io/prezmc/dnserv -reset-mfa USERNAME
docker start dnserv
```

That clears the account's second factor when the node starts (you set it up
again at the next sign-in) and is recorded in the audit log. In a cluster
the node must reach the leader for it to apply. Add `-reset-password` to also
print a new temporary password.

[Back to the README](../README.md)
