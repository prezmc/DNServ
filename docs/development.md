# Development

```bash
go test -race ./...
go test -run '^$' -bench . ./internal/...
go test -tags failover -v -timeout 30m ./test/failover/   # needs Docker
go run ./cmd/dnserve -config dnserve.example.yaml
```

Layout: `cmd/dnserve` (entry point), `internal/config`, `internal/filter`
(rule parsing, compiled index, list downloads, bypass list),
`internal/cache`, `internal/upstream` (DoH, DoT, plain),
`internal/recursive` (Unbound config and supervisor, tunnel checks),
`internal/server` (DNS handler, DoT/DoH listeners, metrics).

The Unbound integration test runs when `unbound` and a DNSSEC root key are
installed (`apt install unbound` or `apk add unbound dnssec-root`).

Images: `.github/workflows/publish.yml` builds amd64 and arm64 images and
pushes `ghcr.io/prezmc/dnserve` on every push to `main` and on version tags.
Adding `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` repository secrets also
pushes `prezmcmahon/dnserve` to Docker Hub.

## Roadmap

1. **DNS node.** 1a core node. 1b Unbound recursive mode, WireGuard
   tunnel mode, DoH/DoT for clients. 1c admin API with users, roles and
   mandatory MFA, and the web UI with a setup wizard. 1d devices, recent
   queries, router names, groups with schedules, and a load tester.
2. **Clustering and backups.** Embedded Raft so any node can lead, join
   codes, owner overrides (preferred leader, never lead, transfer, forced
   recovery), witness mode, settings history with restore, and scheduled
   encrypted backups (this). Later: backups to S3-compatible storage.
3. **Analytics.** Per-node query history merged across nodes, charts,
   top lists, "caught by", search and export, and the AdGuard Insight
   features: threat-feed risk scores, domain types and owners, answer
   IP and CNAME checks, "also on" lists and VirusTotal lookups (this).
4. **Multi-server deploy and failover testing.** A failover test suite
   that runs real containers (two nodes and a witness on separate
   networks) in CI and breaks them on purpose while a client queries
   nonstop: leader and follower loss, witness loss, loss of quorum, a
   broken link between servers, everything restarting at once, rolling
   upgrades, recovery after a lost server, and both sides of a split
   trying to recover. Plus the [two-server guide](deploy-two-servers.md)
   (this).

[Back to the README](../README.md)
