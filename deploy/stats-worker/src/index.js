// DNServ usage summary receiver. See docs/usage-stats.md.
//
// POST /v1/report  one weekly summary from a cluster that opted in
// GET  /v1/totals  public weekly totals (what dnserv.dev/stats shows)
//
// It never reads or stores the sender's IP address. Only the fields
// below are kept; anything else in a report is dropped.

const MAX_BODY = 4096;
const KEEP_DAYS = 90;
// A country is shown only when at least this many clusters share it.
const MIN_GROUP = 5;

const RANGES = ['0', '1-10', '11-50', '51-100', '101-250', '251-1000', '1000+'];
const DAY_RANGES = ['0', '<1k', '1k-10k', '10k-100k', '100k-1M', '1M+'];
const MODES = ['forward', 'recursive', 'tunnel'];
const FEATURES = ['https', 'backups', 'backups_s3', 'backups_smb', 'passkeys', 'groups', 'schedules',
  'blocked_services', 'safe_search', 'block_bypass', 'local_names', 'query_history', 'threat_feeds', 'auto_updates'];

const json = (body, status = 200, extra = {}) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json', 'access-control-allow-origin': '*', ...extra },
});

const str = (v, max, re) => (typeof v === 'string' && v.length <= max && (!re || re.test(v)) ? v : null);
const int = (v, lo, hi) => (Number.isInteger(v) && v >= lo && v <= hi ? v : null);
const num = (v, lo, hi) => (typeof v === 'number' && Number.isFinite(v) && v >= lo && v <= hi ? Math.round(v * 100) / 100 : null);
const oneOf = (v, list) => (list.includes(v) ? v : null);

// clean keeps only known fields with sane values.
export function clean(r) {
  if (!r || typeof r !== 'object') return null;
  const out = {
    report_id: str(r.report_id, 64, /^[0-9a-f]{16,64}$/),
    week: str(r.week, 8, /^\d{4}-W\d{2}$/),
    schema: int(r.schema, 1, 1000),
    version: str(r.version, 40, /^[0-9A-Za-z.+_-]+$/),
    channel: oneOf(r.channel, ['stable', 'latest']),
    arch: str(r.arch, 16, /^[a-z0-9]+$/),
    servers: int(r.servers, 0, 100),
    witnesses: int(r.witnesses, 0, 100),
    upstream_mode: oneOf(r.upstream_mode, MODES),
    devices: oneOf(r.devices, RANGES),
    lookups_per_day: oneOf(r.lookups_per_day, DAY_RANGES),
    answer_ms_p50: num(r.answer_ms_p50, 0, 60000),
    answer_ms_p95: num(r.answer_ms_p95, 0, 60000),
    cache_hit_pct: num(r.cache_hit_pct, 0, 100),
    blocked_pct: num(r.blocked_pct, 0, 100),
    failed_pct: num(r.failed_pct, 0, 100),
    lists: int(r.lists, 0, 1000),
    features: Array.isArray(r.features) ? [...new Set(r.features.filter(f => FEATURES.includes(f)))] : [],
  };
  if (!out.report_id || !out.week || !out.schema) return null;
  return out;
}

async function report(request, env) {
  const len = Number(request.headers.get('content-length') || 0);
  if (len > MAX_BODY) return json({ error: 'too big' }, 413);
  const text = await request.text();
  if (text.length > MAX_BODY) return json({ error: 'too big' }, 413);
  let r;
  try { r = clean(JSON.parse(text)); } catch (_) { r = null; }
  if (!r) return json({ error: 'not a DNServ usage summary' }, 400);
  // Country comes from Cloudflare's own lookup; the address itself is
  // never read.
  const country = str(request.cf && request.cf.country, 2, /^[A-Z]{2}$/);
  const day = new Date().toISOString().slice(0, 10);
  await env.DB.prepare(`INSERT OR IGNORE INTO reports (report_id, week, received, country, schema, version, channel, arch,
      servers, witnesses, upstream_mode, devices, lookups_per_day, answer_ms_p50, answer_ms_p95, cache_hit_pct,
      blocked_pct, failed_pct, lists, features) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .bind(r.report_id, r.week, day, country, r.schema, r.version, r.channel, r.arch, r.servers, r.witnesses,
      r.upstream_mode, r.devices, r.lookups_per_day, r.answer_ms_p50, r.answer_ms_p95, r.cache_hit_pct,
      r.blocked_pct, r.failed_pct, r.lists, JSON.stringify(r.features))
    .run();
  return new Response(null, { status: 204 });
}

const median = (xs) => {
  const v = xs.filter(x => typeof x === 'number').sort((a, b) => a - b);
  if (!v.length) return null;
  const m = v.length >> 1;
  return v.length % 2 ? v[m] : Math.round(((v[m - 1] + v[m]) / 2) * 100) / 100;
};

// summarize turns one week's reports into totals nobody can be picked
// out of.
export function summarize(week, rows) {
  const count = (key) => {
    const c = {};
    for (const r of rows) { const k = r[key] == null ? 'unknown' : String(r[key]); c[k] = (c[k] || 0) + 1; }
    return c;
  };
  const features = {};
  for (const r of rows) for (const f of JSON.parse(r.features || '[]')) features[f] = (features[f] || 0) + 1;
  const countries = {};
  let otherCountries = 0;
  for (const [k, n] of Object.entries(count('country'))) {
    if (n >= MIN_GROUP && k !== 'unknown') countries[k] = n; else otherCountries += n;
  }
  if (otherCountries) countries.other = otherCountries;
  return {
    week, clusters: rows.length,
    servers: rows.reduce((a, r) => a + (r.servers || 0), 0),
    versions: count('version'), channels: count('channel'), arch: count('arch'),
    upstream_modes: count('upstream_mode'), devices: count('devices'), lookups_per_day: count('lookups_per_day'),
    cluster_sizes: count('servers'), features, countries,
    median: {
      answer_ms_p50: median(rows.map(r => r.answer_ms_p50)), answer_ms_p95: median(rows.map(r => r.answer_ms_p95)),
      cache_hit_pct: median(rows.map(r => r.cache_hit_pct)), blocked_pct: median(rows.map(r => r.blocked_pct)),
      failed_pct: median(rows.map(r => r.failed_pct)), lists: median(rows.map(r => r.lists)),
    },
  };
}

async function totals(env) {
  const { results: weeks } = await env.DB.prepare('SELECT week, totals FROM weeks ORDER BY week').all();
  const done = new Map(weeks.map(w => [w.week, JSON.parse(w.totals)]));
  const { results: open } = await env.DB.prepare('SELECT DISTINCT week FROM reports ORDER BY week').all();
  for (const { week } of open) {
    if (done.has(week)) continue;
    const { results } = await env.DB.prepare('SELECT * FROM reports WHERE week = ?').bind(week).all();
    done.set(week, summarize(week, results));
  }
  const list = [...done.values()].sort((a, b) => a.week.localeCompare(b.week));
  return json({ weeks: list, updated: new Date().toISOString() }, 200, { 'cache-control': 'public, max-age=3600' });
}

// tidy saves totals for weeks that are over, then deletes old reports.
async function tidy(env) {
  const { results } = await env.DB.prepare(
    "SELECT DISTINCT week FROM reports WHERE received < date('now', '-8 days') AND week NOT IN (SELECT week FROM weeks)").all();
  for (const { week } of results) {
    const { results: rows } = await env.DB.prepare('SELECT * FROM reports WHERE week = ?').bind(week).all();
    await env.DB.prepare('INSERT OR REPLACE INTO weeks (week, totals) VALUES (?, ?)').bind(week, JSON.stringify(summarize(week, rows))).run();
  }
  await env.DB.prepare(`DELETE FROM reports WHERE received < date('now', '-${KEEP_DAYS} days')`).run();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET' } });
    if (url.pathname === '/v1/report' && request.method === 'POST') return report(request, env);
    if (url.pathname === '/v1/totals' && request.method === 'GET') return totals(env);
    if (url.pathname === '/') return Response.redirect('https://dnserv.dev/stats.html', 302);
    return json({ error: 'not found' }, 404);
  },
  async scheduled(_event, env) { await tidy(env); },
};
