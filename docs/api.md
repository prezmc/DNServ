# Admin API

Everything is under `/api/v1` on port 8080. Browsers use a session cookie
plus the `X-CSRF-Token` header from the sign-in response; scripts use
`Authorization: Bearer dns_…` tokens.

| | Endpoint |
|---|---|
| First run | `GET /setup`, `POST /setup` `{code, username, password}`, `POST /setup/join` `{code, join_code, host}`, or `POST /setup/restore` (multipart: `file`, `passphrase`, `code`) |
| Sign in | `POST /auth/login`, then `POST /auth/mfa` `{code}` (authenticator or recovery code) |
| Enroll MFA | `POST /auth/totp/begin` (returns the secret and `otpauth://` URL), `POST /auth/totp/confirm` `{code}` |
| You | `GET /auth/me`, `POST /auth/password`, `GET`/`DELETE /auth/sessions`, `POST /auth/logout`, `POST /auth/recovery-codes` `{password}`, `POST /auth/authenticator/begin` `{password}` then `/confirm` `{code}` |
| Users | `GET`/`POST /users`, `PATCH`/`DELETE /users/{id}`, `POST /users/{id}/password`, `POST /users/{id}/reset-mfa` |
| Tokens | `GET`/`POST /tokens`, `DELETE /tokens/{id}` |
| Settings | `GET`/`PATCH /settings`, `POST /settings/reset` `{fields}` |
| Local names | `PATCH /settings` `{records: [{name, value, note}]}` (the whole list; `value` is an IP address or another name) |
| Lists | `POST /lists/update` (download every list again now) |
| Pause filtering | `GET /pause`; `POST /pause` `{minutes, node}` (`minutes` 0 = until turned back on, up to 24 h; `node` omitted = every server); `DELETE /pause` (everything back on) or `DELETE /pause?node=<id>` |
| Block or allow | `POST /domains` `{domain, action: block\|allow\|clear}`, `GET /domains/check?name=` |
| AdGuard Home import (admin) | `POST /import/adguard/preview` `{url, username, password, insecure}` returns `{id, plan}`; `POST /import/adguard/apply` `{id, sections, exclude}` |
| Devices | `GET`/`POST /devices` `{name, addrs, group}`, `PUT`/`DELETE /devices/{id}` |
| Groups | `GET`/`POST /groups` `{name, rules, skip_blocklists, schedules: [{name, days, start, end, block_all, rules}], devices}`, `PUT`/`DELETE /groups/{id}` |
| Recent queries | `GET /queries?client=&search=&result=&before=&limit=` (`client` is an IP or device id; `result` is `blocked`, `allowed`, `failed`, …) |
| Analytics | `GET /analytics/summary`, `/analytics/top?by=domains\|blocked\|clients\|lists`, `/analytics/performance`, `/analytics/domain?name=`, `/analytics/queries?search=&result=&before=`, `/analytics/export` (CSV), `/analytics/risky`, `/analytics/intel` (sources), `/analytics/alsoon?name=`, `POST /analytics/virustotal?name=`; `GET`/`PUT /virustotal` `{key}` (never returned). The history views take `range=1h\|24h\|7d\|30d\|90d` and `client=` (IP or device id), and merge every node's history |
| Settings history | `GET /config/versions`, `GET /config/versions/{id}` (with the changes going back would make), `POST /config/versions/{id}/restore` |
| Backups | `GET /backups`, `POST /backups/passphrase` `{passphrase, password}`, `PUT /backups/schedule` `{every: daily\|weekly\|"", at: "HH:MM", keep, offsite}`, `POST /backups/download`, `GET /backups/files/{local\|offsite}/{name}`, `POST /backups/restore` (multipart: `file`, `passphrase`, `password`) |
| Cluster | `GET /cluster`, `POST /cluster/join-codes` `{host}`, `PUT /cluster/nodes/{id}` `{name, never_leader}`, `DELETE /cluster/nodes/{id}`, `POST /cluster/preferred` `{id}`, `POST /cluster/transfer` `{to}`, `POST /cluster/recover` `{password, accept_risk}`, `POST /cluster/join` `{join_code, host, password}` |
| Status and audit | `GET /status`, `GET /audit` |

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
