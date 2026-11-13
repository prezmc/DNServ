# Testing

DNServ is tested in four layers. All of them run in CI on every pull
request; the scans in [Security](#security-scans) also run weekly.

| Layer | What it covers | Run it |
| --- | --- | --- |
| Unit and API tests | Each package on its own, and the HTTP API against an in-memory node | `go test -race ./...` |
| Browser tests | The dashboard in Chromium against a real node, with DNS lookups checking that what the page says is what DNS does | see [Browser tests](#browser-tests) |
| Failover lab | Two nodes and a witness in Docker, broken on purpose while a client sends DNS nonstop | `go test -tags failover ./test/failover/` (needs Docker) |
| Benchmarks | Query path speed | `go test -run '^$' -bench . ./internal/...` and `cmd/dnsbench` |

## Browser tests

```sh
go build -o dnserv-browser-test ./cmd/dnserv
cd test/browser
npm ci && npx playwright install chromium
node --test
```

Each run starts a fresh node in a temporary folder, with a fake upstream
DNS server (it answers every A lookup with 203.0.113.7) and a local web
server for a blocklist, so nothing leaves the machine. Set
`BROWSER_SHOTS=<folder>` to keep a screenshot of each failing step. A step
also fails if the page throws an error or an API call returns a 5xx.

## Feature checklist

Each feature, and where it is tested. **Unit/API** names Go tests,
**Browser** the step in `test/browser/ui.test.js`, **Lab** the failover
lab.

| Feature | Unit/API | Browser | Lab |
| --- | --- | --- | --- |
| **Setup and accounts** | | | |
| First-run setup code and wizard | `api.TestSetupAndSignIn` | setup wizard | yes |
| Two-factor sign-in, recovery codes, new authenticator | `auth.TestTOTPVectors`, `api.TestRecoveryCodeSignIn`, `api.TestSelfServiceSecondFactor`, `store.TestTOTPReplayAndRecovery` | setup wizard, sign out and back in | |
| Passkeys: add, sign in alone or instead of the code, rename, remove | `api.TestPasskeys`, `api.TestRPCandidates` | add a passkey, then sign in with it | |
| Roles and permissions, API tokens | `api.TestRolesTokensAndSettings`, `api.TestPausePermissions` | a viewer can only look | |
| User admin: passwords, reset two-factor, delete, sessions, tokens | `api.TestUserAdministration`, `api.TestPasswordChangeEndsOtherSessions` | a viewer signs in | |
| Sign-in throttling, cross-origin requests refused | `api.TestLoginThrottle`, `api.TestCrossOriginBlocked`, `auth.TestThrottle` | | |
| Audit log | `api.TestRolesTokensAndSettings` | every page opens | |
| **DNS** | | | |
| Forwarding, cache, serve-stale, prefetch | `server.TestForwardAndCache`, `server.TestServeStaleWhenUpstreamFails`, `cache.*` | DNS answers through the fake upstream | yes |
| Cache size and how full it is | `cache.TestFill`, `cache.TestResize`, `api.TestCacheAndBeaconEndpoints` | performance shows how full the cache is | |
| Upstream strategies, failover, DoH/DoT upstreams | `upstream.TestStrategies`, `upstream.TestFailover`, `upstream.TestDoH`, `upstream.TestRecoversAfterFailure` | | |
| Recursive mode (bundled Unbound) | `recursive.TestUnboundLifecycle` (CI installs Unbound) | | |
| Tunnel mode | `recursive.TestTunnelStates`, `config.TestTunnelValidation` | | |
| DNS over HTTPS / TLS for devices | `server.TestDoHGetAndPost`, `server.TestDoT` | | |
| Local names, aliases, wildcards, reverse lookups | `server.TestLocalRecords`, `api.TestLocalRecordsSetting` | local names answer on DNS | yes |
| Device names from the router | `server.TestLocalNamesGoToRouter` | | |
| Only private networks may query, rate limit | `server.TestACLRefusesOutsideClients`, `server.TestRateLimiter` | | |
| **Filtering** | | | |
| Blocklists: download, cache on disk, follower copies | `filter.TestEngineDownloadsAndFallsBackToCache`, `filter.TestFollowerUsesLeadersListCopy`, `filter.TestDownloadURL` | a blocklist added in Settings | yes |
| List "last changed" | `filter.TestParseHeaderDate`, `filter.TestListChangedSeen` | a blocklist added in Settings | |
| Rules: AdBlock syntax, wildcards, regex, `$denyallow`, `$badfilter` | `filter.TestParseLine`, `filter.TestPatternRules`, `filter.TestBadfilter` | | |
| Block, allow and check a domain | `api.TestDevicesQueriesAndCheck`, `filter.TestCustomBlockBeatsListAllow` | block a domain from the dashboard | yes |
| CNAME and answer-IP blocking | `server.TestCNAMEBlocking`, `server.TestAnswerIPBlocking` | | |
| Block modes, bypass blocking | `server.TestBlockModes`, `filter.TestBlockBypass` | | |
| Blocked services, safe search | `server.TestGroupServices`, `server.TestSafeSearch`, `filter.TestBlockedServicesForEveryone` | | |
| Devices, groups and schedules | `policy.TestGroupPolicy`, `server.TestGroupPolicies`, `api.TestGroups` | | |
| Pause filtering (all servers or one) | `server.TestPauseFiltering`, `api.TestPauseFiltering`, `api.TestPauseOneNode` | pause filtering | |
| **Analytics** | | | |
| History, retention, migrations of old databases | `analytics.TestRetention`, `analytics.TestMigrateOldDatabase`, `analytics.TestClear` | | |
| Summary, top lists, devices, merged across nodes | `analytics.TestSummaryAndTop`, `analytics.TestMerge`, `api.TestAnalytics` | dashboard shows the lookups | |
| Query log search and CSV export | `analytics.TestSearch`, `querylog.TestRingAndFilters` | the query log finds lookups | |
| Performance, anomalies | `analytics.TestPerfRecordAndRun`, `analytics.TestAnomalies`, `api.TestPerformanceAndTopLists` | every page opens | |
| Cache-miss reasons | `analytics.TestCacheMiss`, `api.TestCacheAndBeaconEndpoints` | every page opens | |
| Repeating lookups | `analytics.TestBeacons`, `api.TestCacheAndBeaconEndpoints` | | |
| Traffic map and device profile | `analytics.TestFlow`, `api.TestTrafficMap` | dashboard shows the lookups | |
| Risk scores, threat feeds, scoring tuning, domain types | `threat.*`, `api.TestRiskyDomainsAndTypes` | | |
| VirusTotal | `virustotal.TestLookup`, `api.TestVirusTotal` | | |
| Arrange the dashboard | `api.TestDashboardLayout` | arranging the dashboard | |
| **Cluster** | | | |
| Join, replicate, forward writes to the leader | `cluster.TestJoinReplicateAndForward`, `cluster.TestAskPeers` | | yes |
| Leadership controls, forced recovery, witness | `cluster.TestLeadershipControls`, `cluster.TestForceRecoverTwoNodes`, `cluster.TestWitnessKeepsTwoNodesWorking` | | yes |
| Restart catch-up, changes before cluster start | `cluster.TestRestartKeepsStateWithoutQuorum`, `cluster.TestChangeBeforeInitSurvives` | | yes |
| **Data** | | | |
| Backups: encryption, schedule, restore | `backup.*`, `api.TestHistoryAndBackups`, `store.TestBackupRestoreKeepsCluster` | backups | |
| Settings history and going back | `store.TestConfigHistoryAndRestore`, `api.TestDiffConfigWholeItems` | | |
| AdGuard Home import | `adguard.*`, `api.TestAdGuardImport` | every page opens | |
| Dashboard HTTPS (self-signed, files, upload, Nginx Proxy Manager) | `certs.*`, `api.TestHTTPSSettings` | | |
| **Pages** | | | |
| Every page opens without errors | | every page opens | |
| Pages fit a phone screen | | pages fit a phone screen | |

### Checked by hand

These need things CI doesn't have: a real Nginx Proxy Manager, a real
WireGuard tunnel, a router that answers reverse lookups, live threat feeds
and VirusTotal with a key, and a two-server home network (the checklist in
[deploy-two-servers.md](deploy-two-servers.md)).

## Security scans

| Scan | When | Where results go |
| --- | --- | --- |
| `govulncheck` (known Go vulnerabilities in code DNServ calls) | every change, weekly | CI log |
| CodeQL (Go, the dashboard's JavaScript, the workflows) | every change, weekly | Security → Code scanning |
| Trivy on a freshly built image, and on the Dockerfile | every change, weekly | Security → Code scanning; high or critical problems with a fix fail the job |
| Trivy on the published `ghcr.io/prezmc/dnserv:latest` | weekly | Security → Code scanning |
| Dependabot (Go modules, Actions, base images, Playwright) | weekly, and at once for security fixes | pull requests |

Code scanning results need GitHub's code scanning, which is free for
public repositories.
