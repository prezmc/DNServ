// DNServe dashboard. Plain JavaScript, no build step, no external assets.
// All text from the server is inserted with textContent, never as HTML.
'use strict';

// ---------- helpers ----------

const app = document.getElementById('app');
let csrf = '';
let ME = null;
let timer = null;

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = !!v;
    else if (k === 'disabled') el.disabled = !!v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function render(...nodes) {
  if (timer) { clearInterval(timer); timer = null; }
  app.replaceChildren(...nodes);
  const f = app.querySelector('[autofocus]');
  if (f) f.focus();
}

async function api(method, path, body) {
  const opt = { method, headers: {}, credentials: 'same-origin' };
  if (body !== undefined) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  if (csrf) opt.headers['X-CSRF-Token'] = csrf;
  const r = await fetch('/api/v1' + path, opt);
  const text = await r.text();
  let data = null;
  if (text) { try { data = JSON.parse(text); } catch (_) { /* not JSON */ } }
  if (data && typeof data.csrf === 'string') csrf = data.csrf;
  if (!r.ok) {
    const e = new Error((data && data.error) || ('Request failed (HTTP ' + r.status + ')'));
    e.status = r.status;
    if (r.status === 401 && ME && ME.signed_in) { ME = null; setTimeout(boot, 0); }
    throw e;
  }
  return data;
}

function msg(kind, text) { return h('div', { class: 'msg ' + kind, role: kind === 'err' ? 'alert' : 'status' }, text); }

// form wires a <form> to an async handler, showing errors in place and
// disabling the submit button while it runs.
function form(attrs, kids, handler) {
  const out = h('div');
  const f = h('form', Object.assign({}, attrs, {
    onsubmit: async (ev) => {
      ev.preventDefault();
      const btns = f.querySelectorAll('button');
      btns.forEach(b => (b.disabled = true));
      out.replaceChildren();
      try {
        const note = await handler(f, ev.submitter);
        if (note) out.replaceChildren(msg('ok', note));
      } catch (e) {
        out.replaceChildren(msg('err', e.message));
      } finally {
        btns.forEach(b => (b.disabled = false));
      }
    },
  }), kids, out);
  return f;
}

const val = (f, name) => (f.elements[name] ? f.elements[name].value : '');
const lines = (s) => s.split('\n').map(x => x.trim()).filter(Boolean);
const can = (perm) => !!(ME && ME.perms && ME.perms.includes(perm));
const isAdmin = () => !!(ME && ME.user && ME.user.role === 'admin');
const fmtNum = (n) => (n || 0).toLocaleString();
function fmtTime(t) {
  if (!t || t.startsWith('0001')) return '—';
  return new Date(t).toLocaleString();
}
function fmtDur(sec) {
  const d = Math.floor(sec / 86400), hr = Math.floor(sec / 3600) % 24, m = Math.floor(sec / 60) % 60;
  if (d) return d + 'd ' + hr + 'h';
  if (hr) return hr + 'h ' + m + 'm';
  return m + 'm';
}
const store = {
  get(k) { try { return sessionStorage.getItem('dnserve.' + k); } catch (_) { return null; } },
  set(k, v) { try { v === null ? sessionStorage.removeItem('dnserve.' + k) : sessionStorage.setItem('dnserve.' + k, v); } catch (_) { /* ignore */ } },
};

function download(name, text) {
  const a = h('a', { href: URL.createObjectURL(new Blob([text], { type: 'text/plain' })), download: name });
  document.body.append(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}

// ---------- constants ----------

const PERMS = {
  'dashboard.view': 'View dashboard',
  'querylog.view': 'View query logs',
  'data.export': 'Export data',
  'domains.allowblock': 'Block or allow domains',
  'rules.edit': 'Edit custom rules',
  'lists.manage': 'Manage blocklists',
  'devices.manage': 'Manage devices and groups',
  'upstream.manage': 'Change how DNS is resolved',
  'network.manage': 'Change allowed networks',
  'users.manage': 'Manage users (admin)',
  'cluster.manage': 'Manage the cluster (admin)',
  'backups.manage': 'Manage backups (admin)',
  'audit.view': 'View the audit log (admin)',
};
const POWER_PERMS = ['dashboard.view', 'querylog.view', 'data.export', 'domains.allowblock', 'rules.edit', 'lists.manage', 'devices.manage', 'upstream.manage', 'network.manage'];
const VIEWER_PERMS = ['dashboard.view', 'querylog.view'];

const PROVIDERS = {
  cloudflare: { name: 'Cloudflare (1.1.1.1)', servers: ['https://cloudflare-dns.com/dns-query', 'tls://one.one.one.one'] },
  quad9: { name: 'Quad9 (9.9.9.9, blocks malware)', servers: ['https://dns.quad9.net/dns-query', 'tls://dns.quad9.net'] },
};

const HAGEZI = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/';
const PRESET_LISTS = [
  { name: 'HaGeZi Light', url: HAGEZI + 'light.txt', note: 'Ads and trackers; almost never breaks a site.' },
  { name: 'HaGeZi Multi Normal', url: HAGEZI + 'multi.txt', note: 'Balanced ads, tracking and malware.' },
  { name: 'HaGeZi Multi Pro', url: HAGEZI + 'pro.txt', note: 'Stricter; the default. Rarely needs an allow rule.' },
  { name: 'HaGeZi Threat Intelligence', url: HAGEZI + 'tif.txt', note: 'Malware, phishing and scam domains.' },
  { name: 'StevenBlack hosts', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', note: 'Classic unified hosts list.' },
];

// ---------- boot ----------

async function boot() {
  try {
    ME = await api('GET', '/auth/me');
  } catch (e) {
    return render(h('div', { class: 'center' }, h('div', { class: 'card' }, h('h1', {}, 'DNServe'), msg('err', 'Could not reach the node: ' + e.message), h('button', { onclick: boot }, 'Try again'))));
  }
  if (!ME.signed_in) {
    if (ME.setup_needed) return setupAccount();
    if (ME.stage === 'enroll') return enroll();
    if (ME.stage === 'mfa') return mfa();
    return login();
  }
  if (store.get('wizard') && can('upstream.manage')) return setupBasics();
  route();
}

window.addEventListener('hashchange', () => { if (ME && ME.signed_in) route(); });
document.addEventListener('DOMContentLoaded', boot);

// ---------- sign-in pages ----------

function wizardSteps(n) {
  return h('div', { class: 'steps', 'aria-label': 'Step ' + n + ' of 4' }, [1, 2, 3, 4].map(i => h('span', { class: i <= n ? 'on' : '' })));
}

function centered(...kids) { return h('div', { class: 'center' }, h('div', { class: 'card' }, kids)); }

function setupAccount() {
  render(centered(
    wizardSteps(1),
    h('h1', {}, 'Welcome to DNServe'),
    h('p', { class: 'muted' }, 'Create the admin account for this node. To prove you own it, enter the setup code from the container log:'),
    h('p', {}, h('code', {}, 'docker logs dnserve 2>&1 | grep setup_code')),
    form({}, [
      h('label', { for: 'code' }, 'Setup code'),
      h('input', { id: 'code', name: 'code', type: 'text', autocomplete: 'off', placeholder: 'ABCD-EFGH', required: true, autofocus: true }),
      h('label', { for: 'username' }, 'Admin username'),
      h('input', { id: 'username', name: 'username', type: 'text', autocomplete: 'username', value: 'admin', required: true }),
      h('label', { for: 'password' }, 'Password'),
      h('input', { id: 'password', name: 'password', type: 'password', autocomplete: 'new-password', minlength: 12, required: true }),
      h('p', { class: 'muted small' }, 'At least 12 characters. A few random words works well.'),
      h('label', { for: 'confirm' }, 'Confirm password'),
      h('input', { id: 'confirm', name: 'confirm', type: 'password', autocomplete: 'new-password', required: true }),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Create admin account')),
    ], async (f) => {
      if (val(f, 'password') !== val(f, 'confirm')) throw new Error("The passwords don't match.");
      await api('POST', '/setup', { code: val(f, 'code'), username: val(f, 'username').trim(), password: val(f, 'password') });
      store.set('wizard', '1');
      await boot();
    }),
  ));
}

function login() {
  render(centered(
    h('h1', {}, 'Sign in'),
    h('p', { class: 'muted' }, 'DNServe on ' + location.hostname),
    form({}, [
      h('label', { for: 'username' }, 'Username'),
      h('input', { id: 'username', name: 'username', type: 'text', autocomplete: 'username', required: true, autofocus: true }),
      h('label', { for: 'password' }, 'Password'),
      h('input', { id: 'password', name: 'password', type: 'password', autocomplete: 'current-password', required: true }),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Continue')),
    ], async (f) => {
      await api('POST', '/auth/login', { username: val(f, 'username').trim(), password: val(f, 'password') });
      await boot();
    }),
  ));
}

function startOver() {
  return h('button', { class: 'link', type: 'button', onclick: async () => { try { await api('POST', '/auth/logout'); } catch (_) { /* ignore */ } csrf = ''; boot(); } }, 'Start over');
}

function mfa() {
  let recovery = false;
  const draw = () => render(centered(
    h('h1', {}, 'Two-factor sign-in'),
    h('p', { class: 'muted' }, recovery
      ? 'Enter one of your recovery codes. Each code works once.'
      : 'Enter the 6-digit code from your authenticator app.'),
    form({}, [
      recovery
        ? h('input', { name: 'code', type: 'text', autocomplete: 'off', placeholder: 'xxxx-xxxx-xxxx', required: true, autofocus: true, 'aria-label': 'Recovery code' })
        : h('input', { name: 'code', class: 'code', type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', pattern: '[0-9 ]{6,7}', maxlength: 7, required: true, autofocus: true, 'aria-label': 'Authentication code' }),
      h('div', { class: 'actions' },
        h('button', { class: 'primary', type: 'submit' }, 'Verify'),
        h('button', { class: 'link', type: 'button', onclick: () => { recovery = !recovery; draw(); } }, recovery ? 'Use the authenticator app' : 'Use a recovery code'),
        startOver()),
    ], async (f) => {
      await api('POST', '/auth/mfa', { code: val(f, 'code') });
      await boot();
    }),
  ));
  draw();
}

async function enroll() {
  const wizard = !!store.get('wizard');
  render(centered(h('p', { class: 'muted' }, 'Preparing your authenticator setup…')));
  let t;
  try {
    t = await api('POST', '/auth/totp/begin');
  } catch (e) {
    return render(centered(msg('err', e.message), startOver()));
  }
  const secretGroups = t.secret.match(/.{1,4}/g).join(' ');
  render(centered(
    wizard ? wizardSteps(2) : null,
    h('h1', {}, 'Set up two-factor sign-in'),
    h('p', { class: 'muted' }, 'Every DNServe account needs an authenticator app, such as 1Password, Bitwarden, Google Authenticator, Microsoft Authenticator or Authy. Scan this code with it:'),
    t.qr_png ? h('img', { class: 'qr', src: t.qr_png, alt: 'QR code for your authenticator app' }) : null,
    h('details', {}, h('summary', { class: 'small' }, "Can't scan? Enter the key by hand"),
      h('p', { class: 'small' }, 'Account: ', h('b', {}, ME.user ? ME.user.username : ''), ', key: ', h('code', {}, secretGroups), ' (time-based, 6 digits).')),
    form({}, [
      h('label', { for: 'code' }, 'Then enter the 6-digit code it shows'),
      h('input', { id: 'code', name: 'code', class: 'code', type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 7, required: true, autofocus: true }),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Turn on two-factor sign-in'), startOver()),
    ], async (f) => {
      const r = await api('POST', '/auth/totp/confirm', { code: val(f, 'code') });
      ME = await api('GET', '/auth/me');
      recoveryCodes(r.recovery_codes, wizard);
    }),
  ));
}

function recoveryCodes(codes, wizard) {
  const text = 'DNServe recovery codes for ' + (ME.user ? ME.user.username : '') + ' on ' + location.hostname + '\n' +
    'Each code works once. Keep them somewhere safe.\n\n' + codes.join('\n') + '\n';
  const cont = h('button', { class: 'primary', disabled: true, onclick: () => (wizard && can('upstream.manage') ? setupBasics() : boot()) }, 'Continue');
  render(h('div', { class: 'center' }, h('div', { class: 'card' },
    wizard ? wizardSteps(3) : null,
    h('h1', {}, 'Save your recovery codes'),
    h('p', { class: 'muted' }, "If you lose your phone, each of these codes lets you sign in once. They won't be shown again."),
    h('div', { class: 'codes mono' }, codes.map(c => h('div', {}, c))),
    h('div', { class: 'actions' },
      h('button', { type: 'button', onclick: () => download('dnserve-recovery-codes.txt', text) }, 'Download'),
      h('button', { type: 'button', onclick: (ev) => { navigator.clipboard.writeText(text).then(() => { ev.target.textContent = 'Copied'; }); } }, 'Copy')),
    h('label', { class: 'inline' }, h('input', { type: 'checkbox', onchange: (ev) => { cont.disabled = !ev.target.checked; } }), "I've saved these codes"),
    h('div', { class: 'actions' }, cont),
  )));
}

// ---------- first-run basics ----------

async function setupBasics() {
  let s;
  try {
    s = await api('GET', '/settings');
  } catch (e) {
    return render(centered(msg('err', e.message)));
  }
  const eff = s.effective;
  const curURLs = new Set((eff.Filtering.Lists || []).filter(l => l.enabled).map(l => l.url));
  const mode = eff.Upstream.Mode;
  const choice = (value, title, note) => h('label', { class: 'choice' },
    h('input', { type: 'radio', name: 'mode', value, checked: mode === value }),
    h('span', {}, h('b', {}, title), h('span', { class: 'muted small' }, note)));

  render(h('div', { class: 'center' }, h('div', { class: 'card wide' },
    wizardSteps(4),
    h('h1', {}, 'Choose how DNServe works'),
    h('p', { class: 'muted' }, 'You can change all of this later in Settings.'),
    form({}, [
      h('h2', {}, 'How lookups leave your network'),
      h('div', { class: 'choices' },
        choice('forward', 'Encrypted forwarding (recommended)', ' Lookups go encrypted (DNS over HTTPS) to a public resolver, so your ISP can\'t see or change them.'),
        choice('recursive', 'Full recursion', ' DNServe asks the root and domain servers itself, checking DNSSEC. No single resolver sees all your lookups, but your ISP can see them.'),
        choice('tunnel', 'Recursion through a VPN', ' Recursion with every lookup sent through a WireGuard VPN. Needs the gluetun sidecar from deploy/docker-compose.tunnel.yml.')),
      h('label', { for: 'provider' }, 'Resolver for encrypted forwarding'),
      h('select', { id: 'provider', name: 'provider' },
        Object.entries(PROVIDERS).map(([k, p]) => h('option', { value: k, selected: JSON.stringify(eff.Upstream.Servers) === JSON.stringify(p.servers) }, p.name)),
        h('option', { value: 'keep', selected: !Object.values(PROVIDERS).some(p => JSON.stringify(eff.Upstream.Servers) === JSON.stringify(p.servers)) }, 'Keep current: ' + (eff.Upstream.Servers || []).join(', '))),

      h('h2', { class: 'mt' }, 'Blocklists'),
      PRESET_LISTS.map(l => h('label', { class: 'inline' },
        h('input', { type: 'checkbox', name: 'list', value: l.url, checked: curURLs.has(l.url) }),
        h('span', {}, h('b', {}, l.name), ' ', h('span', { class: 'muted small' }, l.note)))),
      h('label', { class: 'inline' }, h('input', { type: 'checkbox', name: 'bypass', checked: eff.Filtering.BlockBypass }),
        h('span', {}, h('b', {}, 'Stop devices from bypassing DNServe'), ' ', h('span', { class: 'muted small' }, 'Blocks public DNS-over-HTTPS resolvers and iCloud Private Relay.'))),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save and finish'), h('button', { type: 'button', onclick: setupDone }, 'Skip')),
    ], async (f) => {
      const patch = { upstream_mode: f.elements.mode.value };
      const prov = val(f, 'provider');
      if (prov !== 'keep') patch.upstream_servers = PROVIDERS[prov].servers;
      const picked = new Set([...f.querySelectorAll('input[name=list]:checked')].map(i => i.value));
      const keep = (eff.Filtering.Lists || []).filter(l => !PRESET_LISTS.some(p => p.url === l.url));
      patch.lists = keep.concat(PRESET_LISTS.filter(p => picked.has(p.url)).map(p => ({ name: p.name, url: p.url, enabled: true })));
      patch.block_bypass = f.elements.bypass.checked;
      if (!can('lists.manage')) { delete patch.lists; delete patch.block_bypass; }
      await api('PATCH', '/settings', patch);
      setupDone();
    }),
  )));
}

function setupDone() {
  store.set('wizard', null);
  render(centered(
    h('h1', {}, "You're set up"),
    h('p', {}, 'Now point your devices at this server for DNS. The easiest way is your router: set its DHCP DNS server to'),
    h('p', {}, h('code', {}, location.hostname)),
    h('p', { class: 'muted small' }, "Use this machine's LAN address if that isn't it. Devices pick up the change when they reconnect or renew their lease."),
    h('div', { class: 'actions' }, h('button', { class: 'primary', onclick: () => { location.hash = '#/'; boot(); } }, 'Open the dashboard')),
  ));
}

// ---------- app shell ----------

const ROUTES = [
  { path: '', title: 'Dashboard', page: dashboard, show: () => true },
  { path: 'settings', title: 'Settings', page: settings, show: () => ['upstream.manage', 'network.manage', 'lists.manage', 'rules.edit'].some(can) },
  { path: 'users', title: 'Users', page: users, show: () => can('users.manage') },
  { path: 'audit', title: 'Audit log', page: audit, show: () => can('audit.view') },
  { path: 'account', title: 'Your account', page: account, show: () => true },
];

function route() {
  const path = location.hash.replace(/^#\/?/, '');
  const r = ROUTES.find(x => x.path === path && x.show()) || ROUTES[0];
  const nav = h('nav', { class: 'side', 'aria-label': 'Main' },
    h('div', { class: 'brand' }, 'DNServe'),
    ROUTES.filter(x => x.show()).map(x => h('a', { href: '#/' + x.path, class: x === r ? 'active' : '', 'aria-current': x === r ? 'page' : null }, x.title)),
    h('div', { class: 'spacer' }),
    h('div', { class: 'who' }, ME.user.username, ' · ', ME.user.role),
    h('button', { class: 'link', onclick: async () => { try { await api('POST', '/auth/logout'); } catch (_) { /* ignore */ } csrf = ''; ME = null; boot(); } }, 'Sign out'));
  const main = h('main', {});
  render(h('div', { class: 'shell' }, nav, main));
  document.title = r.title + ' · DNServe';
  r.page(main);
}

function fill(el, ...kids) { el.replaceChildren(...kids.flat(Infinity).filter(k => k !== null && k !== undefined && k !== false)); }
function page(main, title, ...kids) { fill(main, h('h1', {}, title), kids); }

// ---------- dashboard ----------

async function dashboard(main) {
  const body = h('div', {}, h('p', { class: 'muted' }, 'Loading…'));
  const quick = can('domains.allowblock') ? h('div', { class: 'card' },
    h('h2', {}, 'Block or allow a domain'),
    form({}, [
      h('div', { class: 'row' },
        h('input', { name: 'domain', type: 'text', placeholder: 'ads.example.com', required: true, 'aria-label': 'Domain' }),
        h('button', { type: 'submit', value: 'block' }, 'Block'),
        h('button', { type: 'submit', value: 'allow' }, 'Allow'),
        h('button', { type: 'submit', value: 'clear' }, 'Clear')),
      h('p', { class: 'muted small' }, 'Applies to the domain and all its subdomains. Allow always wins over blocklists.'),
    ], async (f, btn) => {
      const action = btn ? btn.value : 'block';
      const d = val(f, 'domain').trim();
      await api('POST', '/domains', { domain: d, action });
      return { block: 'Blocked ', allow: 'Allowed ', clear: 'Cleared rules for ' }[action] + d + '.';
    })) : null;
  page(main, 'Dashboard', body, quick);

  const load = async () => {
    let s;
    try { s = await api('GET', '/status'); } catch (e) { body.replaceChildren(msg('err', e.message)); return; }
    const q = s.queries || {};
    const total = ['upstream', 'cached', 'stale', 'blocked', 'local', 'error'].reduce((a, k) => a + (q[k] || 0), 0);
    const pct = (n) => (total ? (100 * n / total).toFixed(1) + '%' : '—');
    const tile = (label, value) => h('div', { class: 'tile' }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, value));
    const health = [];
    health.push(h('p', {}, 'Resolution: ', h('b', {}, { forward: 'encrypted forwarding', recursive: 'full recursion (Unbound)', tunnel: 'recursion through VPN' }[s.upstream_mode] || s.upstream_mode)));
    if (s.unbound) health.push(h('p', {}, h('span', { class: 'dot ' + (s.unbound.ready ? 'ok' : 'bad') }), 'Unbound ', s.unbound.ready ? 'running' : 'not answering', s.unbound.restarts ? ' (restarted ' + s.unbound.restarts + '×)' : ''));
    if (s.tunnel) health.push(h('p', {}, h('span', { class: 'dot ' + (s.tunnel.up ? 'ok' : 'bad') }), 'VPN tunnel ', s.tunnel.up ? 'up' : 'down', s.tunnel.detail ? ' — ' + s.tunnel.detail : ''));
    if (s.filter && !s.filter.ready) health.push(msg('warn', 'Blocklists are still loading.'));
    fill(body,
      h('div', { class: 'grid' },
        tile('Queries', fmtNum(total)),
        tile('Blocked', fmtNum(q.blocked) + ' · ' + pct(q.blocked || 0)),
        tile('Answered from cache', pct((q.cached || 0) + (q.stale || 0))),
        tile('Blocking rules', fmtNum(s.filter ? s.filter.rules : 0)),
        tile('Uptime', fmtDur(s.uptime_seconds || 0))),
      h('div', { class: 'card' }, h('h2', {}, 'Health'), health,
        (s.upstreams && s.upstreams.length) ? h('div', { class: 'scroll' }, h('table', {},
          h('thead', {}, h('tr', {}, h('th', {}, 'Upstream'), h('th', {}, 'Latency'), h('th', {}, 'Queries'), h('th', {}, 'Failures'))),
          h('tbody', {}, s.upstreams.map(u => h('tr', {}, h('td', { class: 'mono' }, u.server), h('td', {}, u.latency_ms ? u.latency_ms.toFixed(1) + ' ms' : '—'), h('td', {}, fmtNum(u.queries)), h('td', {}, fmtNum(u.failures))))))) : null),
      (s.filter && s.filter.lists && s.filter.lists.length) ? h('div', { class: 'card' }, h('h2', {}, 'Lists'), h('div', { class: 'scroll' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'List'), h('th', {}, 'Rules'), h('th', {}, 'Updated'), h('th', {}, 'Status'))),
        h('tbody', {}, s.filter.lists.map(l => h('tr', {}, h('td', {}, l.name, l.allowlist ? ' (allow)' : ''), h('td', {}, fmtNum(l.rules)), h('td', {}, fmtTime(l.updated)),
          h('td', {}, l.error ? h('span', { class: 'badge bad' }, l.error) : h('span', { class: 'badge ok' }, l.from_cache ? 'from cache' : 'ok')))))))) : null,
      h('p', { class: 'muted small' }, 'DNServe ', s.version, '. Per-device analytics arrive in a later step.'),
    );
  };
  await load();
  timer = setInterval(() => { if (!document.hidden) load(); }, 5000);
}

// ---------- settings ----------

async function settings(main) {
  page(main, 'Settings', h('p', { class: 'muted' }, 'Loading…'));
  let s;
  try { s = await api('GET', '/settings'); } catch (e) { return page(main, 'Settings', msg('err', e.message)); }
  const eff = s.effective, saved = s.saved || {};
  const sections = [];

  // A badge and reset link for fields saved here (they override the file
  // and environment).
  const origin = (...fields) => {
    const set = fields.filter(f => saved[f] !== undefined && saved[f] !== null);
    if (!set.length) return h('span', { class: 'badge' }, 'from file or defaults');
    return h('span', {}, h('span', { class: 'badge' }, 'saved here'),
      isAdmin() ? h('button', { class: 'link small', type: 'button', onclick: async () => {
        if (!confirm('Go back to the value from the config file or defaults?')) return;
        try { await api('POST', '/settings/reset', { fields: set }); route(); } catch (e) { alert(e.message); }
      } }, 'reset') : null);
  };
  // save sends only the fields that differ from what's in force, so
  // untouched values keep following the config file.
  const save = async (patch, current) => {
    for (const k of Object.keys(patch)) {
      if (JSON.stringify(patch[k]) === JSON.stringify(current[k])) delete patch[k];
    }
    if (!Object.keys(patch).length) return 'Nothing changed.';
    await api('PATCH', '/settings', patch);
    setTimeout(route, 900);
    return 'Saved. Changes apply right away.';
  };
  const norm = (a) => (a || []);

  if (can('upstream.manage')) {
    const u = eff.Upstream;
    const opt = (v, t) => h('option', { value: v, selected: u.Mode === v }, t);
    sections.push(h('div', { class: 'card' },
      h('h2', {}, 'Resolution ', origin('upstream_mode', 'upstream_servers', 'tunnel_interface', 'tunnel_expected_egress', 'tunnel_on_down')),
      form({}, [
        h('label', { for: 'mode' }, 'Mode'),
        h('select', { id: 'mode', name: 'mode' }, opt('forward', 'Encrypted forwarding'), opt('recursive', 'Full recursion (Unbound)'), opt('tunnel', 'Recursion through a VPN tunnel')),
        h('label', { for: 'servers' }, 'Forwarding servers (one per line; also the fallback in tunnel mode)'),
        h('textarea', { id: 'servers', name: 'servers', spellcheck: 'false' }, (u.Servers || []).join('\n')),
        h('p', { class: 'muted small' }, 'https://… for DNS over HTTPS, tls://… for DNS over TLS, udp:// or tcp:// for plain DNS.'),
        h('details', { open: u.Mode === 'tunnel' }, h('summary', {}, 'Tunnel options'),
          h('label', { for: 'tif' }, 'VPN interface that must be up'),
          h('input', { id: 'tif', name: 'tif', type: 'text', value: u.Tunnel.Interface || '' }),
          h('label', { for: 'egress' }, 'Expected VPN exit IPs or ranges (optional, one per line)'),
          h('textarea', { id: 'egress', name: 'egress', spellcheck: 'false', class: 'short' }, (u.Tunnel.ExpectedEgress || []).join('\n')),
          h('label', { for: 'ondown' }, 'When the tunnel is down'),
          h('select', { id: 'ondown', name: 'ondown' },
            h('option', { value: 'forward', selected: u.Tunnel.OnDown === 'forward' }, 'Use encrypted forwarding until it is back'),
            h('option', { value: 'block', selected: u.Tunnel.OnDown === 'block' }, 'Fail lookups (never leak outside the VPN)'))),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save')),
      ], (f) => save({
        upstream_mode: val(f, 'mode'), upstream_servers: lines(val(f, 'servers')),
        tunnel_interface: val(f, 'tif').trim(), tunnel_expected_egress: lines(val(f, 'egress')), tunnel_on_down: val(f, 'ondown'),
      }, {
        upstream_mode: u.Mode, upstream_servers: norm(u.Servers),
        tunnel_interface: u.Tunnel.Interface || '', tunnel_expected_egress: norm(u.Tunnel.ExpectedEgress), tunnel_on_down: u.Tunnel.OnDown,
      }))));
  }

  if (can('lists.manage')) {
    const fl = eff.Filtering;
    const listEditor = (name, items) => {
      const body = h('tbody');
      const addRow = (l) => body.append(h('tr', {},
        h('td', {}, h('input', { type: 'checkbox', 'data-f': 'enabled', checked: l.enabled, 'aria-label': 'Enabled' })),
        h('td', {}, h('input', { type: 'text', 'data-f': 'name', value: l.name, 'aria-label': 'Name' })),
        h('td', {}, h('input', { type: 'text', 'data-f': 'url', value: l.url, 'aria-label': 'URL', spellcheck: 'false' })),
        h('td', {}, h('button', { type: 'button', class: 'link danger', onclick: (ev) => ev.target.closest('tr').remove() }, 'Remove'))));
      (items || []).forEach(addRow);
      const presets = name === 'lists' ? h('select', { 'aria-label': 'Add a known list', onchange: (ev) => {
        const p = PRESET_LISTS.find(x => x.url === ev.target.value);
        if (p) addRow({ name: p.name, url: p.url, enabled: true });
        ev.target.value = '';
      } }, h('option', { value: '' }, 'Add a known list…'), PRESET_LISTS.map(p => h('option', { value: p.url }, p.name))) : null;
      const el = h('div', { 'data-list': name },
        h('div', { class: 'scroll' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'On'), h('th', {}, 'Name'), h('th', {}, 'URL or file path'), h('th', {}))), body)),
        h('div', { class: 'row mt-s' },
          h('button', { type: 'button', onclick: () => addRow({ name: '', url: '', enabled: true }) }, 'Add list'), presets));
      el.read = () => [...body.rows].map(r => ({
        name: r.querySelector('[data-f=name]').value.trim(), url: r.querySelector('[data-f=url]').value.trim(), enabled: r.querySelector('[data-f=enabled]').checked,
      })).filter(l => l.url);
      return el;
    };
    const block = listEditor('lists', fl.Lists), allow = listEditor('allowlists', fl.Allowlists);
    sections.push(h('div', { class: 'card' },
      h('h2', {}, 'Filtering ', origin('filtering_enabled', 'block_mode', 'block_bypass', 'lists', 'allowlists')),
      form({}, [
        h('label', { class: 'inline' }, h('input', { type: 'checkbox', name: 'enabled', checked: fl.Enabled }), 'Filtering on'),
        h('label', { class: 'inline' }, h('input', { type: 'checkbox', name: 'bypass', checked: fl.BlockBypass }), 'Stop devices from bypassing DNServe (blocks public DoH resolvers and iCloud Private Relay)'),
        h('label', { for: 'bmode' }, 'Blocked domains answer with'),
        h('select', { id: 'bmode', name: 'bmode' },
          h('option', { value: 'null_ip', selected: fl.BlockMode === 'null_ip' }, '0.0.0.0 / :: (fastest for apps)'),
          h('option', { value: 'nxdomain', selected: fl.BlockMode === 'nxdomain' }, 'Domain does not exist (NXDOMAIN)'),
          h('option', { value: 'refused', selected: fl.BlockMode === 'refused' }, 'Refused')),
        h('h3', {}, 'Blocklists'), block,
        h('h3', {}, 'Allowlists'), h('p', { class: 'muted small' }, 'Domains on these lists are never blocked by a blocklist.'), allow,
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save')),
      ], (f) => save({
        filtering_enabled: f.elements.enabled.checked, block_bypass: f.elements.bypass.checked, block_mode: val(f, 'bmode'),
        lists: block.read(), allowlists: allow.read(),
      }, {
        filtering_enabled: fl.Enabled, block_bypass: fl.BlockBypass, block_mode: fl.BlockMode,
        lists: norm(fl.Lists).map(l => ({ name: l.name, url: l.url, enabled: l.enabled })), allowlists: norm(fl.Allowlists).map(l => ({ name: l.name, url: l.url, enabled: l.enabled })),
      }))));
  }

  if (can('rules.edit')) {
    sections.push(h('div', { class: 'card' },
      h('h2', {}, 'Custom rules ', origin('rules')),
      form({}, [
        h('textarea', { name: 'rules', spellcheck: 'false', 'aria-label': 'Custom rules', class: 'tall' }, (eff.Filtering.Rules || []).join('\n')),
        h('p', { class: 'muted small' }, h('code', {}, '||ads.example.com^'), ' blocks a domain and its subdomains · ', h('code', {}, '@@||cdn.example.com^'), ' always allows · ',
          h('code', {}, '*.tracker.example'), ' subdomains only · ', h('code', {}, 'exact.example.com'), ' just that name. Custom rules beat every list.'),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save')),
      ], (f) => save({ rules: lines(val(f, 'rules')).filter(l => !l.startsWith('#') && !l.startsWith('!')) }, { rules: norm(eff.Filtering.Rules) }))));
  }

  if (can('network.manage')) {
    sections.push(h('div', { class: 'card' },
      h('h2', {}, 'Allowed networks ', origin('allowed_nets')),
      form({}, [
        h('p', { class: 'muted' }, 'Only devices in these networks may use this DNS server. Leave empty to allow private networks only (the safe default).'),
        h('textarea', { name: 'nets', spellcheck: 'false', 'aria-label': 'Allowed networks', class: 'short' }, (eff.DNS.AllowedNets || []).join('\n')),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save')),
      ], (f) => save({ allowed_nets: lines(val(f, 'nets')) }, { allowed_nets: norm(eff.DNS.AllowedNets) }))));
  }

  page(main, 'Settings', h('p', { class: 'muted' }, 'Settings saved here are stored on the node and take priority over its config file and environment variables.'), sections);
}

// ---------- users ----------

function permPicker(role, selected) {
  const box = h('div', { class: 'perms' });
  const draw = (r) => {
    const allowed = r === 'admin' ? Object.keys(PERMS) : r === 'power' ? POWER_PERMS : VIEWER_PERMS;
    box.replaceChildren(...allowed.map(p => h('label', { class: 'inline' },
      h('input', { type: 'checkbox', name: 'perm', value: p, checked: r === 'admin' || p === 'dashboard.view' || selected.includes(p), disabled: r === 'admin' || p === 'dashboard.view' }), PERMS[p])));
  };
  draw(role);
  box.redraw = draw;
  box.read = () => [...box.querySelectorAll('input[name=perm]:checked:not(:disabled)')].map(i => i.value);
  return box;
}

function roleSelect(current, picker) {
  return h('select', { name: 'role', onchange: (ev) => picker.redraw(ev.target.value) },
    h('option', { value: 'viewer', selected: current === 'viewer' }, 'Viewer: sees the dashboard'),
    h('option', { value: 'power', selected: current === 'power' }, 'Power user: changes what you allow'),
    h('option', { value: 'admin', selected: current === 'admin' }, 'Admin: everything, including users'));
}

function dialog(title, kids) {
  const d = h('dialog', {}, h('h2', {}, title), kids);
  d.addEventListener('close', () => d.remove());
  document.body.append(d);
  d.showModal();
  return d;
}

async function users(main) {
  page(main, 'Users', h('p', { class: 'muted' }, 'Loading…'));
  let list;
  try { list = await api('GET', '/users'); } catch (e) { return page(main, 'Users', msg('err', e.message)); }

  const act = async (fn) => { try { const note = await fn(); if (note) alert(note); route(); } catch (e) { alert(e.message); } };
  const rows = list.map(u => h('tr', {},
    h('td', {}, h('b', {}, u.username), u.id === ME.user.id ? ' (you)' : '', u.disabled ? ' ' : null, u.disabled ? h('span', { class: 'badge bad' }, 'disabled') : null),
    h('td', {}, u.role),
    h('td', {}, u.mfa_enrolled ? h('span', { class: 'badge ok' }, 'on · ' + u.recovery_codes_left + ' recovery codes') : h('span', { class: 'badge' }, 'set up at next sign-in')),
    h('td', {}, fmtTime(u.created_at)),
    h('td', {}, h('div', { class: 'row' },
      h('button', { class: 'link', onclick: () => editUser(u) }, 'Edit'),
      h('button', { class: 'link', onclick: () => act(() => api('PATCH', '/users/' + u.id, { disabled: !u.disabled })) }, u.disabled ? 'Enable' : 'Disable'),
      h('button', { class: 'link', onclick: () => tempPassword(u) }, 'Set password'),
      u.mfa_enrolled ? h('button', { class: 'link', onclick: () => confirm('Reset two-factor sign-in for ' + u.username + '? They will set it up again at their next sign-in.') && act(() => api('POST', '/users/' + u.id + '/reset-mfa')) }, 'Reset 2FA') : null,
      u.id !== ME.user.id ? h('button', { class: 'link danger', onclick: () => confirm('Delete ' + u.username + '? Their API tokens stop working.') && act(() => api('DELETE', '/users/' + u.id)) }, 'Delete') : null))));

  const picker = permPicker('viewer', []);
  page(main, 'Users',
    h('div', { class: 'card scroll' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'User'), h('th', {}, 'Role'), h('th', {}, 'Two-factor'), h('th', {}, 'Created'), h('th', {}))),
      h('tbody', {}, rows))),
    h('div', { class: 'card' }, h('h2', {}, 'Add a user'),
      form({}, [
        h('div', { class: 'row' },
          h('input', { name: 'username', type: 'text', placeholder: 'Username', required: true, autocomplete: 'off', 'aria-label': 'Username' }),
          h('input', { name: 'password', type: 'password', placeholder: 'Temporary password (12+ characters)', required: true, autocomplete: 'new-password', minlength: 12, 'aria-label': 'Temporary password' })),
        h('label', {}, 'Role'), roleSelect('viewer', picker),
        h('label', {}, 'Permissions'), picker,
        h('p', { class: 'muted small' }, 'They sign in with this password and must set up an authenticator app before doing anything else.'),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Add user')),
      ], async (f) => {
        await api('POST', '/users', { username: val(f, 'username').trim(), password: val(f, 'password'), role: val(f, 'role'), perms: picker.read() });
        setTimeout(route, 900);
        return 'Added ' + val(f, 'username').trim() + '. Give them the temporary password.';
      })));

  function editUser(u) {
    const p = permPicker(u.role, u.perms || []);
    const d = dialog('Edit ' + u.username, form({}, [
      h('label', {}, 'Role'), roleSelect(u.role, p),
      h('label', {}, 'Permissions'), p,
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save'), h('button', { type: 'button', onclick: () => d.close() }, 'Cancel')),
    ], async (f) => {
      await api('PATCH', '/users/' + u.id, { role: val(f, 'role'), perms: p.read() });
      d.close();
      route();
    }));
  }

  function tempPassword(u) {
    const d = dialog('Set a password for ' + u.username, form({}, [
      h('p', { class: 'muted' }, 'This signs them out everywhere. Their two-factor setup is kept.'),
      h('input', { name: 'password', type: 'password', autocomplete: 'new-password', minlength: 12, required: true, autofocus: true, 'aria-label': 'New password' }),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Set password'), h('button', { type: 'button', onclick: () => d.close() }, 'Cancel')),
    ], async (f) => {
      await api('POST', '/users/' + u.id + '/password', { password: val(f, 'password') });
      d.close();
      route();
    }));
  }
}

// ---------- audit ----------

async function audit(main) {
  page(main, 'Audit log', h('p', { class: 'muted' }, 'Loading…'));
  let log;
  try { log = await api('GET', '/audit?limit=500'); } catch (e) { return page(main, 'Audit log', msg('err', e.message)); }
  const detail = (e) => {
    if (!e.before && !e.after) return null;
    return h('details', {}, h('summary', { class: 'small' }, 'Details'),
      h('pre', { class: 'mono small pre' },
        e.before ? 'Before: ' + JSON.stringify(e.before, null, 1) + '\n' : '', e.after ? 'After: ' + JSON.stringify(e.after, null, 1) : ''));
  };
  page(main, 'Audit log', h('p', { class: 'muted' }, 'Every change to users, tokens and settings, newest first.'),
    h('div', { class: 'card scroll' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'When'), h('th', {}, 'Who'), h('th', {}, 'What'))),
      h('tbody', {}, log.map(e => h('tr', {}, h('td', { class: 'nowrap' }, fmtTime(e.time)), h('td', {}, e.actor), h('td', {}, e.summary, detail(e))))))));
}

// ---------- account ----------

async function account(main) {
  page(main, 'Your account', h('p', { class: 'muted' }, 'Loading…'));
  let sessions = [], tokens = [];
  try {
    [sessions, tokens] = await Promise.all([api('GET', '/auth/sessions'), api('GET', '/tokens')]);
  } catch (e) { return page(main, 'Your account', msg('err', e.message)); }
  sessions = sessions || [];
  tokens = (tokens || []).filter(t => t.user_id === ME.user.id);

  const tokenOut = h('div');
  const myPerms = (ME.perms || []).filter(p => PERMS[p]);
  page(main, 'Your account',
    h('div', { class: 'card' }, h('h2', {}, 'Change password'),
      form({}, [
        h('label', { for: 'cur' }, 'Current password'),
        h('input', { id: 'cur', name: 'current', type: 'password', autocomplete: 'current-password', required: true }),
        h('label', { for: 'new' }, 'New password'),
        h('input', { id: 'new', name: 'new', type: 'password', autocomplete: 'new-password', minlength: 12, required: true }),
        h('p', { class: 'muted small' }, 'Your other sessions are signed out.'),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Change password')),
      ], async (f) => {
        await api('POST', '/auth/password', { current: val(f, 'current'), new: val(f, 'new') });
        f.reset();
        return 'Password changed.';
      })),

    h('div', { class: 'card' }, h('h2', {}, 'Signed-in sessions'),
      h('div', { class: 'scroll' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Device'), h('th', {}, 'IP'), h('th', {}, 'Signed in'), h('th', {}, 'Last used'), h('th', {}))),
        h('tbody', {}, sessions.filter(x => x.stage === 'full').map(x => h('tr', {},
          h('td', { class: 'small' }, x.user_agent || '—'), h('td', {}, x.ip), h('td', {}, fmtTime(x.created)), h('td', {}, fmtTime(x.last_seen)),
          h('td', {}, x.id === ME.session_id ? h('span', { class: 'badge' }, 'this one')
            : h('button', { class: 'link danger', onclick: async () => { try { await api('DELETE', '/auth/sessions/' + x.id); route(); } catch (e) { alert(e.message); } } }, 'Sign out')))))))),

    h('div', { class: 'card' }, h('h2', {}, 'API tokens'),
      h('p', { class: 'muted' }, 'For scripts and home automation. Send as ', h('code', {}, 'Authorization: Bearer <token>'), '. A token can do only what you pick, and never more than your own account.'),
      tokens.length ? h('div', { class: 'scroll' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Name'), h('th', {}, 'Can'), h('th', {}, 'Created'), h('th', {}, 'Expires'), h('th', {}))),
        h('tbody', {}, tokens.map(t => h('tr', {}, h('td', {}, t.name), h('td', { class: 'small' }, (t.perms || []).map(p => PERMS[p] || p).join(', ')), h('td', {}, fmtTime(t.created_at)), h('td', {}, t.expires_at ? fmtTime(t.expires_at) : 'never'),
          h('td', {}, h('button', { class: 'link danger', onclick: async () => { if (!confirm('Revoke ' + t.name + '?')) return; try { await api('DELETE', '/tokens/' + t.id); route(); } catch (e) { alert(e.message); } } }, 'Revoke'))))))) : null,
      h('h3', {}, 'New token'),
      form({}, [
        h('div', { class: 'row' },
          h('input', { name: 'name', type: 'text', placeholder: 'Name, e.g. Home Assistant', required: true, 'aria-label': 'Token name' }),
          h('select', { name: 'days', 'aria-label': 'Expires' }, h('option', { value: '0' }, 'Never expires'), h('option', { value: '30' }, '30 days'), h('option', { value: '90' }, '90 days'), h('option', { value: '365' }, '1 year'))),
        h('div', { class: 'perms mt-s' }, myPerms.map(p => h('label', { class: 'inline' }, h('input', { type: 'checkbox', name: 'perm', value: p, checked: p === 'dashboard.view' }), PERMS[p]))),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Create token')),
        tokenOut,
      ], async (f) => {
        const perms = [...f.querySelectorAll('input[name=perm]:checked')].map(i => i.value);
        const r = await api('POST', '/tokens', { name: val(f, 'name').trim(), perms, expires_days: Number(val(f, 'days')) });
        tokenOut.replaceChildren(msg('warn', "Copy this token now. It won't be shown again."), h('p', {}, h('code', {}, r.token)),
          h('button', { type: 'button', onclick: () => navigator.clipboard.writeText(r.token) }, 'Copy'), ' ',
          h('button', { type: 'button', onclick: () => route() }, 'Done'));
      })),
  );
}
