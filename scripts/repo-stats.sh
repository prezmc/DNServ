#!/usr/bin/env bash
# Prints one CSV row of download and interest numbers for DNServ, for
# .github/workflows/repo-stats.yml. Needs GH_TOKEN. A number it can't get
# is left empty rather than failing the run.
set -uo pipefail
repo=${REPO:-prezmc/DNServ}
owner=${repo%%/*}
pkg=${PACKAGE:-dnserv}

q() { local out; out=$(gh api "$@" 2>/dev/null) && printf "%s\n" "$out"; }

info=$(q "repos/$repo") || info='{}'
stars=$(jq -r '.stargazers_count // empty' <<<"$info")
forks=$(jq -r '.forks_count // empty' <<<"$info")
watchers=$(jq -r '.subscribers_count // empty' <<<"$info")
issues=$(jq -r '.open_issues_count // empty' <<<"$info")

release_dl=$(q --paginate "repos/$repo/releases" --jq '[.[].assets[].download_count] | add // 0' | awk '{s+=$1} END {print s+0}')
releases=$(q --paginate "repos/$repo/releases" --jq 'length' | awk '{s+=$1} END {print s+0}')

# Traffic is kept 14 days by GitHub; yesterday's numbers, saved daily.
# It needs a token that can push to the repo; empty when it can't.
day=$(date -u -d yesterday +%Y-%m-%dT00:00:00Z)
views=$(q "repos/$repo/traffic/views" --jq ".views[] | select(.timestamp==\"$day\") | \"\(.count),\(.uniques)\"")
clones=$(q "repos/$repo/traffic/clones" --jq ".clones[] | select(.timestamp==\"$day\") | \"\(.count),\(.uniques)\"")
[ -n "$views" ] || views=","
[ -n "$clones" ] || clones=","

# ghcr.io has no API for pull counts; its package page shows the total.
ghcr=$(curl -fsSL "https://github.com/users/$owner/packages/container/package/$pkg" 2>/dev/null |
  tr '\n' ' ' | grep -o -i 'Total downloads.\{0,400\}' | grep -o 'title="[0-9]*"' | head -1 | tr -dc '0-9')

echo "$(date -u +%F),${ghcr},${release_dl},${releases},${stars},${forks},${watchers},${issues},${views},${clones}"
