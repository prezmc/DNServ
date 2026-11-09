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
        if (note) out.replaceChildren(note instanceof Node ? note : msg('ok', note));
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
function ago(t) {
  if (!t || t.startsWith('0001')) return '\u2014';
  const sec = Math.max(0, (Date.now() - new Date(t).getTime()) / 1000);
  if (sec < 90) return 'just now';
  return fmtDur(sec) + ' ago';
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
  cloudflare: { name: 'Cloudflare (1.1.1.1)', note: 'Fast, no filtering of its own.', servers: ['https://cloudflare-dns.com/dns-query', 'tls://one.one.one.one'] },
  quad9: { name: 'Quad9 (9.9.9.9)', note: 'Non-profit; also blocks known malware domains.', servers: ['https://dns.quad9.net/dns-query', 'tls://dns.quad9.net'] },
  mullvad: { name: 'Mullvad', note: 'Privacy-focused, keeps no logs.', servers: ['https://dns.mullvad.net/dns-query', 'tls://dns.mullvad.net'] },
};
const providerFor = (servers) => Object.keys(PROVIDERS).find(k => JSON.stringify(PROVIDERS[k].servers) === JSON.stringify(servers || [])) || 'custom';

const MODES = {
  forward: { title: 'Encrypted forwarding (recommended)', note: "Lookups go encrypted to a public resolver you pick, so your ISP can't see or change them." },
  recursive: { title: 'Full recursion', note: 'DNServe asks the domain servers itself and checks DNSSEC. No single company sees all your lookups, but your ISP can see them.' },
  tunnel: { title: 'Recursion through a VPN', note: 'Full recursion with every lookup sent through a WireGuard VPN, hidden from your ISP.' },
};

// Protection levels are tiers of one list (HaGeZi Multi), so exactly one
// is used. Add-ons stack on top.
const HAGEZI = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/';
const LEVELS = [
  { id: 'off', name: 'Off', note: 'No blocklist. Your own rules still apply.' },
  { id: 'light', name: 'Light', list: { name: 'HaGeZi Light', url: HAGEZI + 'light.txt' }, note: 'Ads and trackers only. Almost never breaks a site.' },
  { id: 'normal', name: 'Standard', list: { name: 'HaGeZi Multi Normal', url: HAGEZI + 'multi.txt' }, note: 'Ads, tracking, malware and scams. A good fit for most homes.' },
  { id: 'pro', name: 'Strong', list: { name: 'HaGeZi Multi Pro', url: HAGEZI + 'pro.txt' }, note: 'Blocks more trackers and telemetry. Now and then a site needs an allow rule.' },
];
const ADDONS = [
  { name: 'HaGeZi Threat Intelligence', url: HAGEZI + 'tif.txt', title: 'Extra malware and phishing protection', note: 'Fresh lists of scam, phishing and malware domains.' },
];
const PRESET_LISTS = LEVELS.filter(l => l.list).map(l => l.list).concat(ADDONS.map(a => ({ name: a.name, url: a.url })),
  [{ name: 'StevenBlack hosts', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts' }]);
const levelOf = (lists) => {
  const on = new Set((lists || []).filter(l => l.enabled).map(l => l.url));
  const hit = LEVELS.filter(l => l.list && on.has(l.list.url));
  return hit.length ? hit[hit.length - 1].id : 'off';
};
// applyLevel returns lists with exactly the chosen level and add-ons from
// the presets, keeping any other lists the user added.
function applyLevel(lists, level, addons) {
  const managed = new Set(LEVELS.filter(l => l.list).map(l => l.list.url).concat(ADDONS.map(a => a.url)));
  const keep = (lists || []).filter(l => !managed.has(l.url));
  const lv = LEVELS.find(l => l.id === level);
  const out = lv && lv.list ? [{ name: lv.list.name, url: lv.list.url, enabled: true }] : [];
  return out.concat(ADDONS.filter(a => addons.has(a.url)).map(a => ({ name: a.name, url: a.url, enabled: true })), keep);
}

// dnsAddress is what devices should use, judged from how this browser
// reached the dashboard.
function dnsAddress() {
  const host = location.hostname.replace(/^\[|\]$/g, '');
  const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':');
  const loopback = host === 'localhost' || host.startsWith('127.') || host === '::1';
  return { host, ok: isIP && !loopback, loopback };
}

function routerHelp() {
  const a = dnsAddress();
  return [
    h('p', {}, "Set your router's DNS server (usually under DHCP or LAN settings) to:"),
    a.loopback ? msg('warn', "You opened the dashboard on this machine itself, so use the machine's LAN address (for example 192.168.1.10), not " + a.host + '.')
      : h('p', {}, h('code', { class: 'big' }, a.host), a.ok ? null : h('span', { class: 'muted small' }, '  (use the IP address this name points to)')),
    h('p', { class: 'muted small' }, "Leave the secondary DNS empty or point it at a second DNServe node. A public one such as 8.8.8.8 lets devices skip filtering. Devices switch over when they reconnect to Wi-Fi."),
  ];
}

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
    h('p', { class: 'muted' }, "First, prove this is your server. DNServe printed a setup code in its container log when it started. It's in a box headed \u201cDNServe first-run setup\u201d. From a terminal:"),
    h('p', {}, h('code', {}, 'docker logs dnserve')),
    h('p', { class: 'muted small' }, 'Using Portainer, Synology, Unraid or similar? Open the container and look at its log.'),
    form({}, [
      h('label', { for: 'code' }, 'Setup code'),
      h('input', { id: 'code', name: 'code', class: 'code', type: 'text', autocomplete: 'off', placeholder: 'ABCD-EFGH', required: true, autofocus: true }),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Continue')),
    ], async (f) => {
      const code = val(f, 'code');
      await api('POST', '/setup/check', { code });
      setupAdmin(code);
    }),
  ));
}

function setupAdmin(code) {
  render(centered(
    wizardSteps(1),
    h('h1', {}, 'Create your admin account'),
    h('p', { class: 'muted' }, 'This account can change everything, including other users.'),
    form({}, [
      h('label', { for: 'username' }, 'Username'),
      h('input', { id: 'username', name: 'username', type: 'text', autocomplete: 'username', value: 'admin', required: true }),
      h('label', { for: 'password' }, 'Password'),
      h('input', { id: 'password', name: 'password', type: 'password', autocomplete: 'new-password', minlength: 12, required: true, autofocus: true }),
      h('p', { class: 'muted small' }, 'At least 12 characters. A few random words works well.'),
      h('label', { for: 'confirm' }, 'Confirm password'),
      h('input', { id: 'confirm', name: 'confirm', type: 'password', autocomplete: 'new-password', required: true }),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Create account'), h('button', { class: 'link', type: 'button', onclick: setupAccount }, 'Back')),
    ], async (f) => {
      if (val(f, 'password') !== val(f, 'confirm')) throw new Error("The passwords don't match.");
      await api('POST', '/setup', { code, username: val(f, 'username').trim(), password: val(f, 'password') });
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
  let s, st;
  try {
    [s, st] = await Promise.all([api('GET', '/settings'), api('GET', '/status')]);
  } catch (e) {
    return render(centered(msg('err', e.message)));
  }
  const eff = s.effective;
  const tunnelOK = st.tunnel_interface_present !== false || eff.Upstream.Mode === 'tunnel';
  const prov = providerFor(eff.Upstream.Servers);
  const onURLs = new Set((eff.Filtering.Lists || []).filter(l => l.enabled).map(l => l.url));

  const providerBox = h('div', { class: 'indent' },
    h('label', { for: 'provider' }, 'Resolver'),
    h('select', { id: 'provider', name: 'provider' },
      Object.entries(PROVIDERS).map(([k, p]) => h('option', { value: k, selected: prov === k }, p.name + ' \u2014 ' + p.note)),
      prov === 'custom' ? h('option', { value: 'custom', selected: true }, 'Keep my custom servers') : null));
  const modeChoice = (m) => {
    const disabled = m === 'tunnel' && !tunnelOK;
    return h('label', { class: 'choice' + (disabled ? ' disabled' : '') },
      h('input', { type: 'radio', name: 'mode', value: m, checked: eff.Upstream.Mode === m, disabled,
        onchange: () => { providerBox.hidden = m !== 'forward'; } }),
      h('span', {}, h('b', {}, MODES[m].title), h('span', { class: 'muted small' }, ' ' + MODES[m].note),
        disabled ? h('span', { class: 'small warn-text' }, ' Needs the VPN setup in deploy/docker-compose.tunnel.yml; no VPN connection was found.') : null,
        m === 'forward' ? providerBox : null));
  };
  providerBox.hidden = eff.Upstream.Mode !== 'forward';
  const level = levelOf(eff.Filtering.Lists);

  render(h('div', { class: 'center' }, h('div', { class: 'card wide' },
    wizardSteps(4),
    h('h1', {}, 'Choose how DNServe protects you'),
    h('p', { class: 'muted' }, 'The defaults suit most homes. You can change all of this later in Settings.'),
    form({}, [
      h('h2', {}, 'Blocking'),
      h('div', { class: 'choices' }, LEVELS.map(l => h('label', { class: 'choice' },
        h('input', { type: 'radio', name: 'level', value: l.id, checked: level === l.id }),
        h('span', {}, h('b', {}, l.name), h('span', { class: 'muted small' }, ' ' + l.note))))),
      ADDONS.map(a => h('label', { class: 'inline' }, h('input', { type: 'checkbox', name: 'addon', value: a.url, checked: onURLs.has(a.url) }),
        h('span', {}, h('b', {}, a.title), ' ', h('span', { class: 'muted small' }, a.note)))),

      h('h2', { class: 'mt' }, 'Privacy'),
      h('div', { class: 'choices' }, ['forward', 'recursive', 'tunnel'].map(modeChoice)),

      h('h2', { class: 'mt' }, 'Extra protection'),
      h('label', { class: 'inline' }, h('input', { type: 'checkbox', name: 'bypass', checked: eff.Filtering.BlockBypass }),
        h('span', {}, h('b', {}, "Don't let devices skip DNServe"), ' ', h('span', { class: 'muted small' }, 'Blocks browsers and apps from using their own encrypted DNS (and iCloud Private Relay). Good for families. A few apps may then fail to connect.'))),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save and finish'), h('button', { type: 'button', onclick: setupDone }, 'Skip')),
    ], async (f) => {
      const mode = f.querySelector('input[name=mode]:checked').value;
      const patch = { upstream_mode: mode };
      const p = val(f, 'provider');
      if (mode === 'forward' && PROVIDERS[p]) patch.upstream_servers = PROVIDERS[p].servers;
      if (can('lists.manage')) {
        const addons = new Set([...f.querySelectorAll('input[name=addon]:checked')].map(i => i.value));
        patch.lists = applyLevel(eff.Filtering.Lists, f.querySelector('input[name=level]:checked').value, addons);
        patch.block_bypass = f.elements.bypass.checked;
      }
      await api('PATCH', '/settings', patch);
      setupDone();
    }),
  )));
}

function setupDone() {
  store.set('wizard', null);
  const seen = h('div', { 'aria-live': 'polite' });
  render(centered(
    h('h1', {}, "You're set up"),
    h('p', {}, 'Last step: send your devices to DNServe.'),
    routerHelp(),
    seen,
    h('div', { class: 'actions' }, h('button', { class: 'primary', onclick: () => { location.hash = '#/'; boot(); } }, 'Open the dashboard')),
  ));
  // Show devices as they arrive, so it's clear the router change worked.
  const poll = async () => {
    let ds;
    try { ds = await api('GET', '/devices'); } catch (_) { return; }
    ds = ds.filter(d => d.queries > 0);
    fill(seen, h('h3', {}, 'Devices using DNServe'),
      ds.length ? h('ul', {}, ds.slice(0, 8).map(d => h('li', {}, deviceLabel(d), ' ', h('span', { class: 'muted small' }, ago(d.last_seen)))))
        : h('p', { class: 'muted small' }, h('span', { class: 'dot' }), 'Waiting for the first device\u2026 (devices pick up the change when they reconnect to Wi\u2011Fi)'));
  };
  poll();
  timer = setInterval(() => { if (!document.hidden) poll(); }, 3000);
}

// ---------- app shell ----------

const ROUTES = [
  { path: '', title: 'Dashboard', page: dashboard, show: () => true },
  { path: 'devices', title: 'Devices', page: devices, show: () => true },
  { path: 'queries', title: 'Recent queries', page: queries, show: () => can('querylog.view') },
  { path: 'settings', title: 'Settings', page: settings, show: () => ['upstream.manage', 'network.manage', 'lists.manage', 'rules.edit'].some(can) },
  { path: 'users', title: 'Users', page: users, show: () => can('users.manage') },
  { path: 'audit', title: 'Audit log', page: audit, show: () => can('audit.view') },
  { path: 'account', title: 'Your account', page: account, show: () => true },
];

// hashParams reads ?a=b from the hash (#/queries?client=x).
function hashParams() {
  const i = location.hash.indexOf('?');
  return new URLSearchParams(i < 0 ? '' : location.hash.slice(i + 1));
}

function route() {
  const path = location.hash.replace(/^#\/?/, '').replace(/\?.*$/, '');
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
  const devBox = h('div');
  const ver = h('p', { class: 'muted small' });
  page(main, 'Dashboard', body, devBox, checkDomainCard(), ver);

  const load = async () => {
    let s;
    try { s = await api('GET', '/status'); } catch (e) { body.replaceChildren(msg('err', e.message)); return; }
    const q = s.queries || {};
    const total = ['upstream', 'cached', 'stale', 'blocked', 'local', 'error'].reduce((a, k) => a + (q[k] || 0), 0);
    const pct = (n) => (total ? (100 * n / total).toFixed(1) + '%' : '—');
    const tile = (label, value) => h('div', { class: 'tile' }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, value));
    const health = [];
    health.push(h('p', {}, 'Lookups: ', h('b', {}, { forward: 'encrypted forwarding', recursive: 'full recursion', tunnel: 'recursion through a VPN' }[s.upstream_mode] || s.upstream_mode)));
    if (s.unbound) health.push(h('p', {}, h('span', { class: 'dot ' + (s.unbound.ready ? 'ok' : 'bad') }), 'Unbound ', s.unbound.ready ? 'running' : 'not answering', s.unbound.restarts ? ' (restarted ' + s.unbound.restarts + '×)' : ''));
    if (s.tunnel) health.push(h('p', {}, h('span', { class: 'dot ' + (s.tunnel.up ? 'ok' : 'bad') }), 'VPN tunnel ', s.tunnel.up ? 'up' : 'down', s.tunnel.detail ? ' — ' + s.tunnel.detail : ''));
    if (s.filter && !s.filter.ready) health.push(msg('warn', 'Blocklists are still loading.'));
    const upName = (u) => (/^udp:\/\/127\.0\.0\.1:/.test(u) ? 'Unbound (built in)' : u.replace(/^https:\/\/([^/]+).*/, '$1 (HTTPS)').replace(/^tls:\/\/([^:]+).*/, '$1 (TLS)'));
    fill(body,
      total === 0 ? h('div', { class: 'card highlight' }, h('h2', {}, 'Waiting for your first device'), routerHelp()) : null,
      h('p', { class: 'muted small' }, 'Counting since DNServe started ', (s.uptime_seconds || 0) < 60 ? 'just now' : fmtDur(s.uptime_seconds) + ' ago', '.'),
      h('div', { class: 'grid' },
        tile('Queries', fmtNum(total)),
        tile('Blocked', total ? fmtNum(q.blocked) + ' (' + pct(q.blocked || 0) + ')' : '0'),
        tile('Answered from cache', pct((q.cached || 0) + (q.stale || 0))),
        tile('Blocking rules', fmtNum(s.filter ? s.filter.rules : 0))),
      h('div', { class: 'card' }, h('h2', {}, 'Health'), health,
        (s.upstreams && s.upstreams.length) ? h('div', { class: 'scroll' }, h('table', {},
          h('thead', {}, h('tr', {}, h('th', {}, 'Resolver'), h('th', {}, 'Latency'), h('th', {}, 'Queries'), h('th', {}, 'Failures'))),
          h('tbody', {}, s.upstreams.map(u => h('tr', {}, h('td', { title: u.server }, upName(u.server)), h('td', {}, u.latency_ms ? u.latency_ms.toFixed(1) + ' ms' : '—'), h('td', {}, fmtNum(u.queries)), h('td', {}, fmtNum(u.failures))))))) : null),
      (s.filter && s.filter.lists && s.filter.lists.length) ? h('div', { class: 'card' }, h('h2', {}, 'Lists'), h('div', { class: 'scroll' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'List'), h('th', {}, 'Rules'), h('th', {}, 'Updated'), h('th', {}, 'Status'))),
        h('tbody', {}, s.filter.lists.map(l => h('tr', {}, h('td', {}, l.name, l.allowlist ? ' (allow)' : ''), h('td', {}, fmtNum(l.rules)), h('td', {}, ago(l.updated)),
          h('td', {}, l.error ? h('span', { class: 'badge bad', title: l.error }, l.rules ? 'update failed, using saved copy' : 'download failed') : h('span', { class: 'badge ok' }, 'ok')))))))) : null,
    );
    ver.textContent = 'DNServe ' + s.version;
  };
  const loadDevices = async () => {
    let ds;
    try { ds = await api('GET', '/devices'); } catch (_) { return; }
    const seen = ds.filter(d => d.queries > 0);
    if (!seen.length) { devBox.replaceChildren(); return; }
    devBox.replaceChildren(h('div', { class: 'card' },
      h('h2', {}, 'Devices ', h('span', { class: 'muted small' }, seen.length + ' seen')),
      deviceTable(seen.slice(0, 5), { compact: true }),
      seen.length > 5 || can('devices.manage') ? h('p', { class: 'small mt-s' }, h('a', { href: '#/devices' }, seen.length > 5 ? 'All ' + seen.length + ' devices' : 'Name your devices')) : null));
  };
  await Promise.all([load(), loadDevices()]);
  let tick = 0;
  timer = setInterval(() => {
    if (document.hidden) return;
    load();
    if (++tick % 3 === 0) loadDevices();
  }, 5000);
}

// ---------- check a domain ----------

function checkDomainCard() {
  const edit = can('domains.allowblock');
  return h('div', { class: 'card' },
    h('h2', {}, edit ? 'Check, block or allow a domain' : 'Check a domain'),
    form({}, [
      h('div', { class: 'row' },
        h('input', { name: 'domain', type: 'text', placeholder: 'ads.example.com', required: true, 'aria-label': 'Domain', spellcheck: 'false' }),
        h('button', { type: 'submit', value: 'check' }, 'Check'),
        edit ? [h('button', { type: 'submit', value: 'block' }, 'Block'),
          h('button', { type: 'submit', value: 'allow' }, 'Allow'),
          h('button', { type: 'submit', value: 'clear' }, 'Remove rule')] : null),
      edit ? h('p', { class: 'muted small' }, 'Block and Allow cover the domain and all its subdomains. Allow always wins over blocklists. Remove rule undoes either.') : null,
    ], async (f, btn) => {
      const action = btn ? btn.value : 'check';
      const d = val(f, 'domain').trim();
      if (action !== 'check') {
        await api('POST', '/domains', { domain: d, action });
        return { block: 'Blocked ', allow: 'Allowed ', clear: 'Removed your rule for ' }[action] + d + '.';
      }
      const r = await api('GET', '/domains/check?name=' + encodeURIComponent(d));
      const why = r.rule ? [' by ', h('code', {}, r.rule), ' from ', r.custom ? 'your custom rules' : r.list] : [];
      const out = msg(r.blocked && !r.allowed ? 'warn' : 'ok', '');
      fill(out, h('b', {}, r.name), r.allowed ? [' is allowed', why, '.'] : r.blocked ? [' is blocked', why, '.'] : ' is not blocked.');
      return out;
    }));
}

// ---------- devices ----------

// deviceLabel is the friendliest name we have for a device.
function deviceLabel(d) { return d.name || d.hostname || d.addrs[0]; }

function deviceTable(list, opts) {
  opts = opts || {};
  const manage = !opts.compact && can('devices.manage');
  return h('div', { class: 'scroll' }, h('table', {},
    h('thead', {}, h('tr', {}, h('th', {}, 'Device'), h('th', {}, 'Last seen'), h('th', {}, 'Queries'), h('th', {}, 'Blocked'), opts.compact ? null : h('th', {}))),
    h('tbody', {}, list.map(d => h('tr', {},
      h('td', {}, h('div', {}, can('querylog.view') ? h('a', { href: '#/queries?client=' + encodeURIComponent(d.id || d.addrs[0]) }, deviceLabel(d)) : deviceLabel(d)),
        deviceLabel(d) !== d.addrs.join(', ') ? h('div', { class: 'muted small' }, d.name && d.hostname ? d.hostname + ' · ' : '', d.addrs.join(', ')) : null),
      h('td', { class: 'nowrap' }, d.last_seen ? ago(d.last_seen) : 'not yet'),
      h('td', {}, fmtNum(d.queries)),
      h('td', {}, d.queries ? fmtNum(d.blocked) + ' (' + (100 * d.blocked / d.queries).toFixed(0) + '%)' : '—'),
      opts.compact ? null : h('td', { class: 'nowrap' },
        manage ? h('button', { class: 'link', onclick: () => editDevice(d) }, d.id ? 'Rename' : 'Name it') : null,
        manage && d.id ? h('button', { class: 'link danger', onclick: async () => {
          if (!confirm('Forget the name "' + d.name + '"? The device keeps working.')) return;
          try { await api('DELETE', '/devices/' + d.id); route(); } catch (e) { alert(e.message); }
        } }, 'Forget name') : null))))));
}

function editDevice(d) {
  const dlg = dialog(d.id ? 'Rename device' : 'Name this device', form({}, [
    h('label', { for: 'dname' }, 'Name'),
    h('input', { id: 'dname', name: 'name', type: 'text', value: d.name || d.hostname || '', required: true, maxlength: 64, autofocus: true }),
    h('label', { for: 'daddrs' }, 'Addresses (one per line)'),
    h('textarea', { id: 'daddrs', name: 'addrs', spellcheck: 'false', class: 'short' }, d.addrs.join('\n')),
    h('p', { class: 'muted small' }, 'Give the device a fixed address in your router (a DHCP reservation) so the name stays right.'),
    h('div', { class: 'actions' },
      h('button', { class: 'primary', type: 'submit' }, 'Save'),
      h('button', { type: 'button', onclick: () => dlg.close() }, 'Cancel')),
  ], async (f) => {
    const body = { name: val(f, 'name').trim(), addrs: lines(val(f, 'addrs')) };
    if (d.id) await api('PUT', '/devices/' + d.id, body);
    else await api('POST', '/devices', body);
    dlg.close();
    route();
  }));
  const first = dlg.querySelector('#dname');
  if (first) { first.focus(); first.select(); }
}

async function devices(main) {
  page(main, 'Devices', h('p', { class: 'muted' }, 'Loading…'));
  let list, settingsHint = null;
  try { list = await api('GET', '/devices'); } catch (e) { return page(main, 'Devices', msg('err', e.message)); }
  if (!list.length) {
    return page(main, 'Devices', h('div', { class: 'card highlight' }, h('h2', {}, 'No devices yet'), routerHelp()));
  }
  if (!list.some(d => d.hostname) && can('network.manage')) {
    settingsHint = msg('warn', '');
    fill(settingsHint, 'Devices show as numbers because DNServe doesn\u2019t know your router. Add your router\u2019s address under ', h('a', { href: '#/settings' }, 'Settings \u2192 Device names'), ' to see their names.');
  }
  page(main, 'Devices',
    h('p', { class: 'muted' }, 'Every device that has used DNServe since it started, most recent first.'),
    settingsHint,
    h('div', { class: 'card' }, deviceTable(list)));
}

// ---------- recent queries ----------

const RESULTS = {
  answered: ['Answered', 'ok'], cached: ['From cache', 'ok'], stale: ['From cache (stale)', 'ok'],
  blocked: ['Blocked', 'bad'], local: ['Local name', 'ok'], failed: ['Failed', 'bad'],
};

async function queries(main) {
  const params = hashParams();
  const filter = { client: params.get('client') || '', search: params.get('search') || '', result: params.get('result') || '' };
  const body = h('tbody');
  const more = h('button', { type: 'button', hidden: true }, 'Show older');
  const info = h('p', { class: 'muted small' });
  let devs = [];
  try { devs = await api('GET', '/devices'); } catch (_) { /* filter still works by IP */ }
  const names = {};
  devs.forEach(d => d.addrs.forEach(a => { names[a] = deviceLabel(d); }));

  const setHash = () => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(filter)) if (v) q.set(k, v);
    const s = q.toString();
    history.replaceState(null, '', '#/queries' + (s ? '?' + s : ''));
  };
  let oldest = 0, live = true;
  const row = (e) => {
    const [label, kind] = RESULTS[e.result] || [e.result, ''];
    const why = e.rule ? e.rule + (e.list ? ' (' + e.list + ')' : '') : '';
    const blocked = e.result === 'blocked';
    return h('tr', {},
      h('td', { class: 'nowrap small', title: fmtTime(e.time) }, new Date(e.time).toLocaleTimeString()),
      h('td', { class: 'small' }, names[e.client] || e.client),
      h('td', {}, h('span', { class: 'mono' }, e.name), ' ', h('span', { class: 'muted small' }, e.type)),
      h('td', {}, h('span', { class: 'badge ' + kind, title: why || null }, label, e.allowed ? ' · allowed' : ''),
        why ? h('div', { class: 'muted small' }, why) : null),
      can('domains.allowblock') ? h('td', { class: 'nowrap' }, h('button', { class: 'link', onclick: async (ev) => {
        const action = blocked ? 'allow' : 'block';
        try { await api('POST', '/domains', { domain: e.name, action }); ev.target.replaceWith(h('span', { class: 'small muted' }, blocked ? 'Allowed' : 'Blocked')); }
        catch (err) { alert(err.message); }
      } }, blocked ? 'Allow' : 'Block')) : null);
  };
  const q = (extra) => {
    const u = new URLSearchParams({ limit: '100' });
    for (const [k, v] of Object.entries(filter)) if (v) u.set(k, v);
    for (const [k, v] of Object.entries(extra || {})) u.set(k, v);
    return api('GET', '/queries?' + u);
  };
  const load = async () => {
    let r;
    try { r = await q(); } catch (e) { info.replaceChildren(msg('err', e.message)); return; }
    body.replaceChildren(...r.queries.map(row));
    oldest = r.queries.length ? r.queries[r.queries.length - 1].id : 0;
    more.hidden = r.queries.length < 100;
    info.textContent = r.queries.length ? 'Newest first. DNServe remembers the most recent ' + fmtNum(r.capacity) + ' queries until it restarts; longer history comes with analytics.' : '';
    if (!r.queries.length) body.append(h('tr', {}, h('td', { colspan: 5, class: 'muted' }, Object.values(filter).some(Boolean) ? 'Nothing matches.' : 'No queries yet.')));
  };
  more.addEventListener('click', async () => {
    live = false;
    try {
      const r = await q({ before: String(oldest) });
      r.queries.forEach(e => body.append(row(e)));
      if (r.queries.length) oldest = r.queries[r.queries.length - 1].id;
      more.hidden = r.queries.length < 100;
      pause.checked = false;
    } catch (e) { alert(e.message); }
  });
  const pause = h('input', { type: 'checkbox', checked: true, onchange: (ev) => { live = ev.target.checked; if (live) load(); } });

  const devSel = h('select', { name: 'client', 'aria-label': 'Device', onchange: (ev) => { filter.client = ev.target.value; setHash(); load(); } },
    h('option', { value: '' }, 'All devices'),
    devs.map(d => h('option', { value: d.id || d.addrs[0], selected: filter.client === (d.id || d.addrs[0]) }, deviceLabel(d))));
  if (filter.client && !devs.some(d => (d.id || d.addrs[0]) === filter.client)) devSel.append(h('option', { value: filter.client, selected: true }, filter.client));
  let debounce = null;
  const search = h('input', { type: 'text', name: 'search', placeholder: 'Search domains', value: filter.search, 'aria-label': 'Search domains', spellcheck: 'false', oninput: (ev) => {
    clearTimeout(debounce);
    debounce = setTimeout(() => { filter.search = ev.target.value.trim(); setHash(); load(); }, 250);
  } });
  const resSel = h('select', { name: 'result', 'aria-label': 'Result', onchange: (ev) => { filter.result = ev.target.value; setHash(); load(); } },
    h('option', { value: '' }, 'All results'),
    h('option', { value: 'blocked', selected: filter.result === 'blocked' }, 'Blocked'),
    h('option', { value: 'allowed', selected: filter.result === 'allowed' }, 'Allowed by a rule'),
    h('option', { value: 'failed', selected: filter.result === 'failed' }, 'Failed'));

  page(main, 'Recent queries',
    h('div', { class: 'row' }, devSel, search, resSel, h('label', { class: 'inline' }, pause, 'Live')),
    info,
    h('div', { class: 'card' }, h('div', { class: 'scroll' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'Time'), h('th', {}, 'Device'), h('th', {}, 'Domain'), h('th', {}, 'Result'), can('domains.allowblock') ? h('th', {}) : null)),
      body)), h('div', { class: 'actions' }, more)));
  await load();
  timer = setInterval(() => { if (live && !document.hidden) load(); }, 3000);
}

// ---------- settings ----------

async function settings(main) {
  page(main, 'Settings', h('p', { class: 'muted' }, 'Loading…'));
  let s;
  try { s = await api('GET', '/settings'); } catch (e) { return page(main, 'Settings', msg('err', e.message)); }
  const eff = s.effective, saved = s.saved || {};
  const sections = [];

  // Fields changed in the dashboard get a "changed" badge and, for admins,
  // a way back to the default.
  const origin = (...fields) => {
    const set = fields.filter(f => saved[f] !== undefined && saved[f] !== null);
    if (!set.length) return null;
    return h('span', {}, h('span', { class: 'badge' }, 'changed'),
      isAdmin() ? h('button', { class: 'link small', type: 'button', onclick: async () => {
        if (!confirm('Go back to the default for this section?')) return;
        try { await api('POST', '/settings/reset', { fields: set }); route(); } catch (e) { alert(e.message); }
      } }, 'reset to default') : null);
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
    let tunnelOK = true;
    try { const st = await api('GET', '/status'); tunnelOK = st.tunnel_interface_present !== false || u.Mode === 'tunnel'; } catch (_) { /* keep enabled */ }
    const prov = providerFor(u.Servers);
    const servers = h('textarea', { id: 'servers', name: 'servers', spellcheck: 'false', class: 'short' }, (u.Servers || []).join('\n'));
    const custom = h('div', { hidden: prov !== 'custom' },
      h('label', { for: 'servers' }, 'Your servers, one per line'), servers,
      h('p', { class: 'muted small' }, 'https://\u2026/dns-query for DNS over HTTPS, tls://name for DNS over TLS.'));
    const picker = h('select', { id: 'provider', name: 'provider', onchange: (ev) => {
      custom.hidden = ev.target.value !== 'custom';
      if (PROVIDERS[ev.target.value]) servers.value = PROVIDERS[ev.target.value].servers.join('\n');
    } }, Object.entries(PROVIDERS).map(([k, p]) => h('option', { value: k, selected: prov === k }, p.name + ' \u2014 ' + p.note)),
      h('option', { value: 'custom', selected: prov === 'custom' }, 'Custom servers\u2026'));
    const fwd = h('div', { class: 'indent', hidden: u.Mode === 'recursive' },
      h('label', { for: 'provider' }, u.Mode === 'tunnel' ? 'Resolver (used only while the VPN is down)' : 'Resolver'), picker, custom);
    const tunnelOpts = h('details', { class: 'indent', open: u.Mode === 'tunnel', hidden: u.Mode !== 'tunnel' }, h('summary', {}, 'VPN options'),
      h('label', { for: 'tif' }, 'VPN network interface'),
      h('input', { id: 'tif', name: 'tif', type: 'text', value: u.Tunnel.Interface || '' }),
      h('label', { for: 'egress' }, 'Expected VPN exit addresses (optional, one per line)'),
      h('textarea', { id: 'egress', name: 'egress', spellcheck: 'false', class: 'short' }, (u.Tunnel.ExpectedEgress || []).join('\n')),
      h('label', { for: 'ondown' }, 'If the VPN goes down'),
      h('select', { id: 'ondown', name: 'ondown' },
        h('option', { value: 'forward', selected: u.Tunnel.OnDown === 'forward' }, 'Keep working with encrypted forwarding until it is back'),
        h('option', { value: 'block', selected: u.Tunnel.OnDown === 'block' }, 'Stop answering (never send a lookup outside the VPN)')));
    const modeChoice = (m) => {
      const disabled = m === 'tunnel' && !tunnelOK;
      return h('label', { class: 'choice' + (disabled ? ' disabled' : '') },
        h('input', { type: 'radio', name: 'mode', value: m, checked: u.Mode === m, disabled, onchange: () => {
          fwd.hidden = m === 'recursive'; tunnelOpts.hidden = m !== 'tunnel';
        } }),
        h('span', {}, h('b', {}, MODES[m].title.replace(' (recommended)', '')), h('span', { class: 'muted small' }, ' ' + MODES[m].note),
          disabled ? h('span', { class: 'small warn-text' }, ' Needs the VPN setup in deploy/docker-compose.tunnel.yml; no VPN connection was found.') : null));
    };
    sections.push(h('div', { class: 'card' },
      h('h2', {}, 'Privacy ', origin('upstream_mode', 'upstream_servers', 'tunnel_interface', 'tunnel_expected_egress', 'tunnel_on_down')),
      h('p', { class: 'muted' }, 'How DNServe looks up the domains it doesn\u2019t block.'),
      form({}, [
        h('div', { class: 'choices' }, ['forward', 'recursive', 'tunnel'].map(modeChoice)),
        fwd, tunnelOpts,
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save')),
      ], (f) => save({
        upstream_mode: f.querySelector('input[name=mode]:checked').value, upstream_servers: lines(servers.value),
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
        h('label', { class: 'inline' }, h('input', { type: 'checkbox', name: 'bypass', checked: fl.BlockBypass }), "Don't let devices skip DNServe (blocks apps' own encrypted DNS and iCloud Private Relay)"),
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
      h('h2', {}, 'Device names ', origin('local_dns')),
      form({}, [
        h('p', { class: 'muted' }, 'DNServe can ask your router what each device is called, and sends lookups for local names (like printer.lan) to it.'),
        h('label', { for: 'localdns' }, 'Your router\u2019s address'),
        h('input', { id: 'localdns', name: 'localdns', type: 'text', value: eff.DNS.LocalDNS || '', placeholder: '192.168.1.1', spellcheck: 'false' }),
        h('p', { class: 'muted small' }, 'Usually the address you type to open your router\u2019s settings. Leave empty to turn this off.'),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save')),
      ], (f) => save({ local_dns: val(f, 'localdns').trim() }, { local_dns: eff.DNS.LocalDNS || '' }))));
    sections.push(h('div', { class: 'card' },
      h('h2', {}, 'Allowed networks ', origin('allowed_nets')),
      form({}, [
        h('p', { class: 'muted' }, 'Only devices in these networks may use this DNS server. Leave empty to allow private networks only (the safe default).'),
        h('textarea', { name: 'nets', spellcheck: 'false', 'aria-label': 'Allowed networks', class: 'short', placeholder: 'Private networks (default):\n192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12 and others' }, (eff.DNS.AllowedNets || []).join('\n')),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save')),
      ], (f) => save({ allowed_nets: lines(val(f, 'nets')) }, { allowed_nets: norm(eff.DNS.AllowedNets) }))));
  }

  page(main, 'Settings', sections);
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
