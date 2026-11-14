# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue.

Use **Report a vulnerability** on this repository's
[Security tab](https://github.com/prezmc/DNServ/security). If that
button isn't there, open an issue that only asks for a private contact,
without any details of the problem.

Include what you found, the version (image tag or commit), and steps to
reproduce it if you can. You should get a reply within a few days.

## Supported versions

Only the latest image (`ghcr.io/prezmc/dnserv:latest`) and the `main`
branch get security fixes. Update with
`docker compose pull && docker compose up -d`.

## Looking for the risk scores?

DNServ's threat feeds, Security card and risk scoring are described in
[docs/risk-scoring.md](../docs/risk-scoring.md).
