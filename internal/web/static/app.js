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
        delete f.dataset.dirty;
        if (note) out.replaceChildren(note instanceof Node ? note : msg('ok', note));
      } catch (e) {
        out.replaceChildren(msg('err', e.message));
      } finally {
        btns.forEach(b => (b.disabled = false));
      }
    },
  }), kids, out);
  if (f.hasAttribute('data-track')) {
    const mark = () => { f.dataset.dirty = '1'; };
    f.addEventListener('input', mark);
    f.addEventListener('change', mark);
  }
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

// tempPass makes a random temporary password that's easy to read out
// (no 0/O or 1/l/I): four groups of four, about 80 bits.
function tempPass() {
  const abc = 'abcdefghjkmnpqrstuvwxyz23456789';
  const r = new Uint32Array(16);
  crypto.getRandomValues(r);
  return [...r].map((x, i) => (i && i % 4 === 0 ? '-' : '') + abc[x % abc.length]).join('');
}

// inviteText is a message an admin can send to a new user.
function inviteText(username, password) {
  return 'You have an account on DNServe, our home network\u2019s DNS filter.\n\n' +
    '1. Open ' + location.origin + '/\n' +
    '2. Sign in as ' + username + ' with the temporary password ' + password + '\n' +
    '3. Set up an authenticator app when asked (for example Google Authenticator, Microsoft Authenticator or 1Password)\n' +
    '4. Then choose your own password under Your account.\n';
}

// deviceName turns a browser's user agent into "Chrome on macOS".
function deviceName(ua) {
  if (!ua) return 'Unknown device';
  const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Firefox\//.test(ua) ? 'Firefox'
    : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : /curl|python|Go-http/i.test(ua) ? 'Script' : 'Browser';
  const os = /iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad' : /Android/.test(ua) ? 'Android'
    : /Mac OS X|Macintosh/.test(ua) ? 'macOS' : /Windows/.test(ua) ? 'Windows' : /CrOS/.test(ua) ? 'ChromeOS' : /Linux/.test(ua) ? 'Linux' : '';
  return os ? browser + ' on ' + os : browser;
}

function inviteBox(note, username, password) {
  const text = inviteText(username, password);
  return h('div', {},
    msg('ok', note),
    h('p', { class: 'small' }, 'Send them this (it is not shown again):'),
    h('textarea', { class: 'tall', readonly: true, 'aria-label': 'Invite message' }, text),
    h('div', { class: 'actions' }, h('button', { type: 'button', onclick: (ev) => navigator.clipboard.writeText(text).then(() => { ev.target.textContent = 'Copied'; }) }, 'Copy message')));
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
    if (ME.setup_needed) {
      let su = {};
      try { su = await api('GET', '/setup'); } catch (_) { /* show setup */ }
      return su.joining ? joinWaiting() : setupAccount();
    }
    if (ME.stage === 'enroll') return enroll();
    if (ME.stage === 'mfa') return mfa();
    return login();
  }
  if (store.get('wizard') && can('upstream.manage')) return setupBasics();
  route();
}

// Moving away from a settings form with unsaved changes asks first.
let shownHash = location.hash, goingBack = false;
const unsaved = () => !!document.querySelector('form[data-dirty]');
window.addEventListener('hashchange', async () => {
  if (!(ME && ME.signed_in)) return;
  if (goingBack) { goingBack = false; return; }
  if (unsaved() && !(await ask('Leave without saving your changes?', 'Leave', false))) {
    goingBack = true;
    location.hash = shownHash;
    return;
  }
  route();
});
window.addEventListener('beforeunload', (ev) => { if (unsaved()) { ev.preventDefault(); ev.returnValue = ''; } });
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
      setupChoice(code);
    }),
  ));
}

// setupChoice: a new DNServe, or another node for an existing one.
function setupChoice(code) {
  render(centered(
    wizardSteps(1),
    h('h1', {}, 'Is this your first DNServe?'),
    h('div', { class: 'choices' },
      h('button', { class: 'choice', type: 'button', autofocus: true, onclick: () => setupAdmin(code) },
        h('b', {}, 'Yes, set up a new DNServe'), h('span', { class: 'muted small' }, 'Create an admin account and choose your settings.')),
      h('button', { class: 'choice', type: 'button', onclick: () => setupJoin(code) },
        h('b', {}, 'No, add this server to my DNServe'), h('span', { class: 'muted small' }, 'It copies the accounts, settings and blocklists from your other node and stays in sync with it.'))),
    h('div', { class: 'actions' }, h('button', { class: 'link', type: 'button', onclick: setupAccount }, 'Back')),
  ));
}

function setupJoin(code) {
  render(centered(
    h('h1', {}, 'Add this server to your DNServe'),
    h('ol', { class: 'steps-list' },
      h('li', {}, 'On your other DNServe, open ', h('b', {}, 'Cluster'), ' and choose ', h('b', {}, 'Add a node'), '.'),
      h('li', {}, 'Copy the join code it shows and paste it here.')),
    form({}, [
      h('label', { for: 'join' }, 'Join code'),
      h('textarea', { id: 'join', name: 'join', class: 'code', rows: 3, autocomplete: 'off', spellcheck: 'false', placeholder: 'DNSJ1-…', required: true, autofocus: true }),
      h('p', { class: 'muted small' }, 'The two servers talk to each other on port 8081. If one is behind a firewall, open that port between them.'),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Join'), h('button', { class: 'link', type: 'button', onclick: () => setupChoice(code) }, 'Back')),
    ], async (f) => {
      await api('POST', '/setup/join', { code, join_code: val(f, 'join'), host: location.hostname });
      joinWaiting();
    }),
  ));
}

// joinWaiting shows progress while the other node sends its settings.
function joinWaiting() {
  const note = h('p', { class: 'muted' }, 'Copying accounts and settings from your other node…');
  render(centered(h('h1', {}, 'Joining your DNServe'), note, h('div', { class: 'spinner', 'aria-hidden': 'true' })));
  const started = Date.now();
  timer = setInterval(async () => {
    let su;
    try { su = await api('GET', '/setup'); } catch (_) { return; }
    if (!su.needed) {
      clearInterval(timer); timer = null;
      render(centered(
        h('h1', {}, 'This server is now part of your DNServe'),
        msg('ok', 'It has the same accounts, settings and blocklists as your other node, and keeps in sync with it.'),
        h('p', {}, 'Sign in with your usual DNServe account. To use it for DNS, add its address to your router as a second DNS server.'),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'button', autofocus: true, onclick: boot }, 'Sign in'))));
    } else if (Date.now() - started > 30000) {
      note.replaceChildren('Still waiting for the other node. Check that both servers can reach each other on port 8081. This page carries on as soon as the settings arrive.');
    }
  }, 1500);
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
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Create account'), h('button', { class: 'link', type: 'button', onclick: () => setupChoice(code) }, 'Back')),
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
  { path: 'cluster', title: 'Cluster', page: clusterPage, show: () => can('cluster.manage') },
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
  const menu = h('button', { type: 'button', class: 'menu', 'aria-expanded': 'false', 'aria-controls': 'navlinks', onclick: () => {
    const open = nav.classList.toggle('open');
    menu.setAttribute('aria-expanded', String(open));
  } }, r.title + ' \u25be');
  const nav = h('nav', { class: 'side', 'aria-label': 'Main' },
    h('div', { class: 'brand' }, 'DNServe', menu),
    h('div', { id: 'navlinks', class: 'links' },
      ROUTES.filter(x => x.show()).map(x => h('a', { href: '#/' + x.path, class: x === r ? 'active' : '', 'aria-current': x === r ? 'page' : null }, x.title))),
    h('div', { class: 'spacer' }),
    h('div', { class: 'who' }, ME.user.username, ' · ', ME.user.role),
    h('button', { class: 'link', onclick: async () => { try { await api('POST', '/auth/logout'); } catch (_) { /* ignore */ } csrf = ''; ME = null; boot(); } }, 'Sign out'));
  const main = h('main', {});
  shownHash = location.hash;
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
    if (s.cluster && s.cluster.nodes > 1) {
      health.push(h('p', {}, h('span', { class: 'dot ' + (s.cluster.healthy ? 'ok' : 'bad') }), 'Cluster: ', s.cluster.nodes + ' nodes, ',
        s.cluster.healthy ? s.cluster.leader + ' leading' : 'no leader, changes paused', ' ',
        can('cluster.manage') ? h('a', { href: '#/cluster' }, 'Details') : null));
    }
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
      (s.filter && s.filter.lists && s.filter.lists.length) ? h('div', { class: 'card' }, h('div', { class: 'row spread' }, h('h2', {}, 'Lists'), updateListsButton()), h('div', { class: 'scroll' }, h('table', {},
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

// updateListsButton downloads every list again now, instead of waiting
// for the daily refresh.
function updateListsButton() {
  if (!can('lists.manage')) return null;
  const b = h('button', { type: 'button', class: 'small', onclick: async () => {
    b.disabled = true;
    try {
      await api('POST', '/lists/update');
      toast('Downloading the lists again. The new rules apply as soon as they are in, usually within a minute.');
    } catch (e) { toast(e.message, 'err'); }
    setTimeout(() => { b.disabled = false; }, 10000);
  } }, 'Update lists now');
  return b;
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
    h('thead', {}, h('tr', {}, h('th', {}, 'Device'), opts.groups ? h('th', {}, 'Group') : null, h('th', {}, 'Last seen'), h('th', {}, 'Queries'), h('th', {}, 'Blocked'), opts.compact ? null : h('th', {}))),
    h('tbody', {}, list.map(d => h('tr', {},
      h('td', {}, h('div', {}, can('querylog.view') ? h('a', { href: '#/queries?client=' + encodeURIComponent(d.id || d.addrs[0]) }, deviceLabel(d)) : deviceLabel(d)),
        deviceLabel(d) !== d.addrs.join(', ') ? h('div', { class: 'muted small' }, d.name && d.hostname ? d.hostname + ' · ' : '', d.addrs.join(', ')) : null),
      opts.groups ? h('td', {}, d.group && opts.groups[d.group] ? opts.groups[d.group] : h('span', { class: 'muted' }, 'Everyone')) : null,
      h('td', { class: 'nowrap' }, d.last_seen ? ago(d.last_seen) : 'not yet'),
      h('td', {}, fmtNum(d.queries)),
      h('td', {}, d.queries ? fmtNum(d.blocked) + ' (' + (100 * d.blocked / d.queries).toFixed(0) + '%)' : '—'),
      opts.compact ? null : h('td', { class: 'nowrap' },
        manage ? h('button', { class: 'link', onclick: () => editDevice(d, opts.groupList || []) }, d.id ? 'Rename' : 'Name it') : null,
        manage && d.id ? h('button', { class: 'link danger', onclick: async () => {
          if (!(await ask('Forget the name "' + d.name + '"?', 'Forget name'))) return;
          try { await api('DELETE', '/devices/' + d.id); route(); } catch (e) { toast(e.message, 'err'); }
        } }, 'Forget name') : null))))));
}

function editDevice(d, groups) {
  const dlg = dialog(d.id ? 'Edit device' : 'Name this device', form({}, [
    h('label', { for: 'dname' }, 'Name'),
    h('input', { id: 'dname', name: 'name', type: 'text', value: d.name || d.hostname || '', required: true, maxlength: 64, autofocus: true }),
    h('label', { for: 'daddrs' }, 'Addresses (one per line)'),
    h('textarea', { id: 'daddrs', name: 'addrs', spellcheck: 'false', class: 'short' }, d.addrs.join('\n')),
    h('p', { class: 'muted small' }, 'Give the device a fixed address in your router (a DHCP reservation) so the name stays right.'),
    groups.length ? [h('label', { for: 'dgroup' }, 'Group'),
      h('select', { id: 'dgroup', name: 'group' }, h('option', { value: '' }, 'Everyone (household settings)'),
        groups.map(g => h('option', { value: g.id, selected: d.group === g.id }, g.name)))] : null,
    h('div', { class: 'actions' },
      h('button', { class: 'primary', type: 'submit' }, 'Save'),
      h('button', { type: 'button', onclick: () => dlg.close() }, 'Cancel')),
  ], async (f) => {
    const body = { name: val(f, 'name').trim(), addrs: lines(val(f, 'addrs')) };
    if (f.elements.group) body.group = val(f, 'group');
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
  let list, gs, settingsHint = null;
  try { [list, gs] = await Promise.all([api('GET', '/devices'), api('GET', '/groups')]); } catch (e) { return page(main, 'Devices', msg('err', e.message)); }
  const groups = gs.groups;
  if (!list.length && !groups.length) {
    return page(main, 'Devices', h('div', { class: 'card highlight' }, h('h2', {}, 'No devices yet'), routerHelp()));
  }
  if (list.length && !list.some(d => d.hostname) && can('network.manage')) {
    settingsHint = msg('warn', '');
    fill(settingsHint, 'Devices show as numbers because DNServe doesn’t know your router. Add your router’s address under ', h('a', { href: '#/settings' }, 'Settings → Device names'), ' to see their names.');
  }
  const gnames = {};
  groups.forEach(g => { gnames[g.id] = g.name; });
  page(main, 'Devices',
    h('p', { class: 'muted' }, 'Every device that has used DNServe since it started, most recent first.'),
    settingsHint,
    h('div', { class: 'card' }, deviceTable(list, { groups: groups.length ? gnames : null, groupList: groups })),
    groupsCard(groups, list, gs));
}

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
function daysText(days) {
  const k = days.join(',');
  if (k === '0,1,2,3,4,5,6') return 'every day';
  if (k === '1,2,3,4,5') return 'weekdays';
  if (k === '0,6') return 'weekends';
  if (k === '0,1,2,3,4') return 'school nights (Sun–Thu)';
  return days.map(d => DAYS[d]).join(', ');
}

function groupsCard(groups, devs, gs) {
  const manage = can('devices.manage');
  const named = devs.filter(d => d.id);
  return h('div', { class: 'card' },
    h('h2', {}, 'Groups'),
    h('p', { class: 'muted' }, 'Give some devices their own rules, such as a bedtime for the kids’ tablets. Devices not in a group use the household settings.'),
    groups.length ? h('div', { class: 'scroll' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'Group'), h('th', {}, 'Devices'), h('th', {}, 'Rules'), h('th', {}, 'Schedules'), manage ? h('th', {}) : null)),
      h('tbody', {}, groups.map(g => h('tr', {},
        h('td', {}, h('b', {}, g.name), g.active.length ? h('div', {}, h('span', { class: 'badge bad nowrap' }, g.active.join(', ') + ' on now')) : null),
        h('td', { class: 'small' }, g.devices.length ? g.devices.map(id => (named.find(d => d.id === id) || { name: id }).name).join(', ') : h('span', { class: 'muted' }, 'none yet')),
        h('td', { class: 'small' }, g.skip_blocklists ? 'Skips the household blocklists' : 'Household blocklists', g.rules.length ? ', plus ' + g.rules.length + ' rule' + (g.rules.length > 1 ? 's' : '') : ''),
        h('td', { class: 'small' }, g.schedules.length ? g.schedules.map(sc => h('div', {}, sc.name, ': ', sc.block_all ? 'no internet' : 'blocks ' + sc.rules.length + ' domain' + (sc.rules.length > 1 ? 's' : ''), ', ', sc.start, '–', sc.end, ' ', daysText(sc.days))) : h('span', { class: 'muted' }, 'none')),
        manage ? h('td', { class: 'nowrap' },
          h('button', { class: 'link', onclick: () => editGroup(g, named, gs) }, 'Edit'),
          h('button', { class: 'link danger', onclick: async () => {
            if (!(await ask('Delete the group "' + g.name + '"? Its devices go back to the household settings.', 'Delete group'))) return;
            try { await api('DELETE', '/groups/' + g.id); route(); } catch (e) { toast(e.message, 'err'); }
          } }, 'Delete')) : null))))) : null,
    h('p', { class: 'muted small' }, 'Schedules follow ', h('b', {}, gs.time_zone), ' time (now ', gs.now, ').', can('network.manage') ? [' ', h('a', { href: '#/settings' }, 'Change')] : null),
    manage ? h('div', { class: 'actions' },
      named.length ? h('button', { onclick: () => editGroup(null, named, gs) }, 'Add a group')
        : h('p', { class: 'muted small' }, 'Name a device first (Name it, above), then you can put it in a group.')) : null);
}

function scheduleEditor(sc) {
  const rules = h('textarea', { 'data-f': 'rules', spellcheck: 'false', class: 'short', placeholder: 'youtube.com\ntiktok.com', 'aria-label': 'Domains to block' }, (sc.rules || []).join('\n'));
  const rulesBox = h('div', { hidden: sc.block_all }, h('p', { class: 'muted small' }, 'Domains to block during this time (subdomains included):'), rules);
  const box = h('fieldset', { class: 'sched' },
    h('div', { class: 'row' },
      h('input', { type: 'text', 'data-f': 'name', value: sc.name || '', placeholder: 'Name', 'aria-label': 'Schedule name', maxlength: 64 }),
      h('button', { type: 'button', class: 'link danger', onclick: () => box.remove() }, 'Remove')),
    h('div', { class: 'row mt-s days' }, DAYS.map((d, i) => h('label', { class: 'inline' }, h('input', { type: 'checkbox', 'data-day': i, checked: (sc.days || []).includes(i) }), d))),
    h('div', { class: 'row mt-s' },
      h('label', { class: 'inline' }, 'From ', h('input', { type: 'time', 'data-f': 'start', value: sc.start || '21:00', required: true })),
      h('label', { class: 'inline' }, 'until ', h('input', { type: 'time', 'data-f': 'end', value: sc.end || '07:00', required: true }))),
    h('div', { class: 'row mt-s' },
      h('label', { class: 'inline' }, h('input', { type: 'radio', name: 'mode-' + Math.random().toString(36).slice(2), value: 'all', checked: !!sc.block_all, onchange: () => { rulesBox.hidden = true; } }), 'Pause the internet'),
      h('label', { class: 'inline' }, h('input', { type: 'radio', name: '', value: 'some', checked: !sc.block_all, onchange: () => { rulesBox.hidden = false; } }), 'Block some domains')),
    rulesBox);
  // Both radios share one random name so each schedule is its own choice.
  const radios = box.querySelectorAll('input[type=radio]');
  radios[1].name = radios[0].name;
  box.read = () => ({
    name: box.querySelector('[data-f=name]').value.trim(),
    days: [...box.querySelectorAll('[data-day]')].filter(c => c.checked).map(c => +c.dataset.day),
    start: box.querySelector('[data-f=start]').value, end: box.querySelector('[data-f=end]').value,
    block_all: radios[0].checked, rules: radios[0].checked ? [] : lines(rules.value),
  });
  return box;
}

function editGroup(g, named, gs) {
  g = g || { name: '', devices: [], rules: [], schedules: [], skip_blocklists: false };
  const scheds = h('div', {}, g.schedules.map(scheduleEditor));
  const preset = (sc) => scheds.append(scheduleEditor(sc));
  const dlg = dialog(g.id ? 'Edit group' : 'Add a group', form({}, [
    h('label', { for: 'gname' }, 'Name'),
    h('input', { id: 'gname', name: 'name', type: 'text', value: g.name, required: true, maxlength: 64, placeholder: 'Kids', autofocus: true }),
    h('label', {}, 'Devices'),
    h('div', { class: 'perms' }, named.map(d => h('label', { class: 'inline' },
      h('input', { type: 'checkbox', name: 'dev', value: d.id, checked: g.devices.includes(d.id) }), d.name))),
    h('label', { class: 'inline mt' }, h('input', { type: 'checkbox', name: 'skip', checked: g.skip_blocklists }), 'Skip the household blocklists and custom rules (for example a work laptop)'),
    h('label', { for: 'grules' }, 'Extra rules for this group'),
    h('textarea', { id: 'grules', name: 'rules', spellcheck: 'false', class: 'short', placeholder: '||games.example^\n@@||school.example^' }, g.rules.join('\n')),
    h('p', { class: 'muted small' }, 'Same syntax as custom rules. Allow rules here (', h('code', {}, '@@||site^'), ') beat everything, even schedules.'),
    h('h3', {}, 'Schedules'),
    h('p', { class: 'muted small' }, 'In ', gs.time_zone, ' time. A schedule that ends before it starts runs overnight.'),
    scheds,
    h('div', { class: 'row mt-s' },
      h('button', { type: 'button', onclick: () => preset({ name: 'Bedtime', days: [0, 1, 2, 3, 4], start: '21:00', end: '07:00', block_all: true }) }, 'Add bedtime'),
      h('button', { type: 'button', onclick: () => preset({ name: 'Homework', days: [1, 2, 3, 4, 5], start: '16:00', end: '18:00', block_all: false, rules: [] }) }, 'Add homework time'),
      h('button', { type: 'button', onclick: () => preset({ name: '', days: [0, 1, 2, 3, 4, 5, 6], start: '12:00', end: '13:00', block_all: true }) }, 'Add other')),
    h('div', { class: 'actions' },
      h('button', { class: 'primary', type: 'submit' }, 'Save'),
      h('button', { type: 'button', onclick: () => dlg.close() }, 'Cancel')),
  ], async (f) => {
    const body = {
      name: val(f, 'name').trim(), skip_blocklists: f.elements.skip.checked, rules: lines(val(f, 'rules')),
      schedules: [...scheds.children].map(x => x.read()),
      devices: [...f.querySelectorAll('input[name=dev]:checked')].map(i => i.value),
    };
    if (g.id) await api('PUT', '/groups/' + g.id, body);
    else await api('POST', '/groups', body);
    dlg.close();
    route();
  }));
  dlg.classList.add('wide');
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
        catch (err) { toast(err.message, 'err'); }
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
    } catch (e) { toast(e.message, 'err'); }
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
        if (!(await ask('Go back to the default for this section?', 'Reset', false))) return;
        try { await api('POST', '/settings/reset', { fields: set }); route(); } catch (e) { toast(e.message, 'err'); }
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
      form({ 'data-track': true }, [
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
      form({ 'data-track': true }, [
        h('label', { class: 'inline' }, h('input', { type: 'checkbox', name: 'enabled', checked: fl.Enabled }), 'Filtering on'),
        h('label', { class: 'inline' }, h('input', { type: 'checkbox', name: 'bypass', checked: fl.BlockBypass }), "Don't let devices skip DNServe (blocks apps' own encrypted DNS and iCloud Private Relay)"),
        h('label', { for: 'bmode' }, 'Blocked domains answer with'),
        h('select', { id: 'bmode', name: 'bmode' },
          h('option', { value: 'null_ip', selected: fl.BlockMode === 'null_ip' }, '0.0.0.0 / :: (fastest for apps)'),
          h('option', { value: 'nxdomain', selected: fl.BlockMode === 'nxdomain' }, 'Domain does not exist (NXDOMAIN)'),
          h('option', { value: 'refused', selected: fl.BlockMode === 'refused' }, 'Refused')),
        h('div', { class: 'row spread mt' }, h('h3', {}, 'Blocklists'), updateListsButton()), block,
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
      form({ 'data-track': true }, [
        h('textarea', { name: 'rules', spellcheck: 'false', 'aria-label': 'Custom rules', class: 'tall' }, (eff.Filtering.Rules || []).join('\n')),
        h('p', { class: 'muted small' }, h('code', {}, '||ads.example.com^'), ' blocks a domain and its subdomains · ', h('code', {}, '@@||cdn.example.com^'), ' always allows · ',
          h('code', {}, '*.tracker.example'), ' subdomains only · ', h('code', {}, 'exact.example.com'), ' just that name. Custom rules beat every list.'),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save')),
      ], (f) => save({ rules: lines(val(f, 'rules')).filter(l => !l.startsWith('#') && !l.startsWith('!')) }, { rules: norm(eff.Filtering.Rules) }))));
  }

  if (can('network.manage')) {
    sections.push(h('div', { class: 'card' },
      h('h2', {}, 'Device names ', origin('local_dns')),
      form({ 'data-track': true }, [
        h('p', { class: 'muted' }, 'DNServe can ask your router what each device is called, and sends lookups for local names (like printer.lan) to it.'),
        h('label', { for: 'localdns' }, 'Your router\u2019s address'),
        h('input', { id: 'localdns', name: 'localdns', type: 'text', value: eff.DNS.LocalDNS || '', placeholder: '192.168.1.1', spellcheck: 'false' }),
        h('p', { class: 'muted small' }, 'Usually the address you type to open your router\u2019s settings. Leave empty to turn this off.'),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save')),
      ], (f) => save({ local_dns: val(f, 'localdns').trim() }, { local_dns: eff.DNS.LocalDNS || '' }))));
    let browserTZ = '';
    try { browserTZ = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (_) { /* old browser */ }
    let zones = [];
    try { zones = Intl.supportedValuesOf('timeZone'); } catch (_) { /* old browser */ }
    const tz = h('input', { id: 'tz', name: 'tz', type: 'text', value: eff.TimeZone || '', placeholder: 'Container time zone (UTC unless TZ is set)', list: 'tzlist', spellcheck: 'false' });
    sections.push(h('div', { class: 'card' },
      h('h2', {}, 'Time zone ', origin('time_zone')),
      form({ 'data-track': true }, [
        h('p', { class: 'muted' }, 'Group schedules, such as bedtimes, follow this time zone.'),
        h('label', { for: 'tz' }, 'Time zone'), tz,
        h('datalist', { id: 'tzlist' }, zones.map(z => h('option', { value: z }))),
        browserTZ && browserTZ !== eff.TimeZone ? h('p', { class: 'small' }, h('button', { type: 'button', class: 'link', onclick: () => { tz.value = browserTZ; } }, 'Use ' + browserTZ + ' (this browser’s)')) : null,
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save')),
      ], (f) => save({ time_zone: val(f, 'tz').trim() }, { time_zone: eff.TimeZone || '' }))));
    sections.push(h('div', { class: 'card' },
      h('h2', {}, 'Allowed networks ', origin('allowed_nets')),
      form({ 'data-track': true }, [
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

// ask replaces the browser's confirm box: it resolves true if the person agrees.
function ask(question, okLabel, danger) {
  return new Promise((resolve) => {
    let answer = false;
    const ok = h('button', { class: danger === false ? 'primary' : 'primary danger-fill', type: 'button', onclick: () => { answer = true; d.close(); } }, okLabel || 'OK');
    const d = dialog(question, h('div', { class: 'actions' }, ok, h('button', { type: 'button', autofocus: true, onclick: () => d.close() }, 'Cancel')));
    d.addEventListener('close', () => resolve(answer));
  });
}

// toast shows a short message at the bottom of the page.
function toast(text, kind) {
  let box = document.getElementById('toasts');
  if (!box) { box = h('div', { id: 'toasts', 'aria-live': 'polite' }); document.body.append(box); }
  const t = msg(kind || 'ok', text);
  box.append(t);
  setTimeout(() => t.remove(), kind === 'err' ? 8000 : 4000);
}

async function users(main) {
  page(main, 'Users', h('p', { class: 'muted' }, 'Loading…'));
  let list;
  try { list = await api('GET', '/users'); } catch (e) { return page(main, 'Users', msg('err', e.message)); }

  const act = async (fn) => { try { const note = await fn(); if (note) toast(note); route(); } catch (e) { toast(e.message, 'err'); } };
  const rows = list.map(u => h('tr', {},
    h('td', {}, h('b', {}, u.username), u.id === ME.user.id ? ' (you)' : '', u.disabled ? ' ' : null, u.disabled ? h('span', { class: 'badge bad' }, 'disabled') : null),
    h('td', {}, u.role),
    h('td', {}, u.mfa_enrolled ? h('span', { class: 'badge ok' }, 'on · ' + u.recovery_codes_left + ' recovery codes') : h('span', { class: 'badge' }, 'set up at next sign-in')),
    h('td', {}, fmtTime(u.created_at)),
    h('td', {}, h('div', { class: 'row' },
      h('button', { class: 'link', onclick: () => editUser(u) }, 'Edit'),
      h('button', { class: 'link', onclick: () => act(() => api('PATCH', '/users/' + u.id, { disabled: !u.disabled })) }, u.disabled ? 'Enable' : 'Disable'),
      h('button', { class: 'link', onclick: () => tempPassword(u) }, 'Set password'),
      u.mfa_enrolled ? h('button', { class: 'link', onclick: async () => (await ask('Reset two-factor sign-in for ' + u.username + '? They set it up again at their next sign-in.', 'Reset 2FA')) && act(() => api('POST', '/users/' + u.id + '/reset-mfa')) }, 'Reset 2FA') : null,
      u.id !== ME.user.id ? h('button', { class: 'link danger', onclick: async () => (await ask('Delete ' + u.username + '? Their API tokens stop working.', 'Delete user')) && act(() => api('DELETE', '/users/' + u.id)) }, 'Delete') : null))));

  const picker = permPicker('viewer', []);
  page(main, 'Users',
    h('div', { class: 'card scroll' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'User'), h('th', {}, 'Role'), h('th', {}, 'Two-factor'), h('th', {}, 'Created'), h('th', {}))),
      h('tbody', {}, rows))),
    h('div', { class: 'card' }, h('h2', {}, 'Add a user'),
      form({}, [
        h('div', { class: 'row' },
          h('input', { name: 'username', type: 'text', placeholder: 'Username', required: true, autocomplete: 'off', 'aria-label': 'Username' }),
          h('input', { name: 'password', type: 'text', placeholder: 'Temporary password (12+ characters)', required: true, autocomplete: 'off', spellcheck: 'false', minlength: 12, 'aria-label': 'Temporary password', value: tempPass() }),
          h('button', { type: 'button', onclick: (ev) => { ev.target.closest('form').elements.password.value = tempPass(); } }, 'New password')),
        h('label', {}, 'Role'), roleSelect('viewer', picker),
        h('label', {}, 'Permissions'), picker,
        h('p', { class: 'muted small' }, 'They sign in with this password and must set up an authenticator app before doing anything else.'),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Add user')),
      ], async (f) => {
        const name = val(f, 'username').trim(), pass = val(f, 'password');
        await api('POST', '/users', { username: name, password: pass, role: val(f, 'role'), perms: picker.read() });
        const d = dialog('Added ' + name, [inviteBox(name + ' can sign in now.', name, pass),
          h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'button', onclick: () => d.close() }, 'Done'))]);
        d.addEventListener('close', () => route());
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
      h('div', { class: 'row' },
        h('input', { name: 'password', type: 'text', autocomplete: 'off', spellcheck: 'false', minlength: 12, required: true, autofocus: true, 'aria-label': 'New password', value: tempPass() }),
        h('button', { type: 'button', onclick: (ev) => { ev.target.closest('form').elements.password.value = tempPass(); } }, 'New password')),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Set password'), h('button', { type: 'button', onclick: () => d.close() }, 'Cancel')),
    ], async (f) => {
      const pass = val(f, 'password');
      await api('POST', '/users/' + u.id + '/password', { password: pass });
      d.close();
      const d2 = dialog('New password for ' + u.username, [inviteBox('Password set.', u.username, pass),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'button', onclick: () => d2.close() }, 'Done'))]);
    }));
  }
}

// ---------- cluster ----------

const ROLES = {
  leader: ['Leader', 'ok', 'Takes changes and sends them to the other nodes.'],
  follower: ['Follower', 'ok', 'Has every change and can take over as leader.'],
  joining: ['Catching up', '', 'Getting a copy of the settings. It starts voting once it has caught up.'],
  standby: ['Never leads', '', 'Keeps a full copy and answers DNS, but never leads or votes.'],
  witness: ['Witness', 'ok', 'Votes so the cluster keeps a majority. It doesn\u2019t answer DNS.'],
  adding: ['Adding', '', 'Being added to the cluster.'],
};

async function clusterPage(main) {
  page(main, 'Cluster', h('p', { class: 'muted' }, 'Loading…'));
  let data;
  try { data = await api('GET', '/cluster'); } catch (e) { return page(main, 'Cluster', msg('err', e.message)); }
  const c = data.cluster;
  const nodes = c.nodes || [];
  const self = nodes.find(n => n.self) || {};
  const others = nodes.filter(n => !n.self);
  const act = async (fn, note) => { try { await fn(); if (note) toast(note); } catch (e) { toast(e.message, 'err'); } route(); };

  const status = [];
  if (c.left_out) {
    status.push(msg('err', 'This node is no longer part of its cluster (it was removed, or the cluster was recovered without it). It still answers DNS with the settings it last had. To bring it back, make a join code on a working node and use "Join another DNServe" below.'));
  } else if (!c.healthy) {
    status.push(msg('err', 'No leader: this node can’t reach enough of the cluster, so changes are paused. DNS keeps working everywhere with the current settings. Bring the missing node back, or if it’s gone for good, recover below.'));
  } else if (nodes.length === 1) {
    status.push(h('p', { class: 'muted' }, 'This DNServe runs on one server. Add a second so DNS keeps working if one goes down. Settings, accounts and blocklists stay the same on both.'));
  } else {
    status.push(msg('ok', 'All changes are shared between ' + nodes.length + ' nodes. ' + (nodes.find(n => n.leader) || {}).name + ' is leading.'));
  }
  const hasWitness = nodes.some(n => n.witness);
  if (c.healthy && nodes.length > 1) {
    status.push(h('p', {}, c.tolerates > 0
      ? 'Changes keep working with ' + c.tolerates + (c.tolerates === 1 ? ' voting node' : ' voting nodes') + ' down.'
      : 'Changes pause while any voting node is down. DNS keeps working on every node either way.'));
  }
  if (c.healthy && c.voters === 2) {
    status.push(h('p', { class: 'muted small' }, 'To keep taking changes with either node down, add a ', h('b', {}, 'witness'),
      ' on a third machine (see below). Or, if one server is more reliable, set the other to ', h('b', {}, 'Never lead'), '.'));
  } else if (c.healthy && c.voters >= 4 && c.voters % 2 === 0 && !hasWitness) {
    status.push(h('p', { class: 'muted small' }, 'With an even number of voting nodes, adding a witness lets the cluster lose one more node and keep taking changes.'));
  }

  const roleBadge = (n) => {
    const r = ROLES[n.role] || [n.role, '', ''];
    return h('span', { class: 'badge ' + r[1], title: r[2] }, r[0]);
  };
  const preferredSet = nodes.some(n => n.preferred);
  const rows = nodes.map(n => h('tr', {},
    h('td', {}, h('b', {}, n.name), n.self ? ' (this node)' : '', n.preferred ? h('span', { class: 'badge', title: 'Leads whenever it is up' }, '★ preferred') : null),
    h('td', {}, roleBadge(n)),
    h('td', {}, h('span', { class: 'dot ' + (n.reachable ? 'ok' : 'bad') }), n.reachable ? (n.behind > 20 ? n.behind + ' changes behind' : 'Up') : 'Unreachable'),
    h('td', { class: 'small' }, h('code', {}, n.addr || '—')),
    h('td', { class: 'small muted' }, n.version || ''),
    h('td', {}, c.healthy && !c.left_out ? h('div', { class: 'row' },
      h('button', { class: 'link', onclick: () => renameNode(n) }, 'Rename'),
      !n.leader && !n.never_leader && !n.witness && n.voter && (!preferredSet || n.preferred) ? h('button', { class: 'link', onclick: () => act(() => api('POST', '/cluster/transfer', { to: n.id }), n.name + ' is leading now') }, 'Make leader') : null,
      !n.never_leader && !n.witness ? h('button', { class: 'link', onclick: () => act(() => api('POST', '/cluster/preferred', { id: n.preferred ? '' : n.id }), n.preferred ? 'No preferred leader' : n.name + ' leads whenever it’s up') }, n.preferred ? 'Stop preferring' : 'Prefer as leader') : null,
      !n.witness ? h('button', { class: 'link', onclick: () => neverLead(n) }, n.never_leader ? 'Allow to lead' : 'Never lead') : null,
      !n.self && !n.leader ? h('button', { class: 'link danger', onclick: async () => (await ask('Remove ' + n.name + ' from the cluster? It stops getting changes. To add it again it needs a new join code.', 'Remove node')) && act(() => api('DELETE', '/cluster/nodes/' + n.id), n.name + ' removed') }, 'Remove') : null) : null)));

  const addCard = c.healthy && !c.left_out ? h('div', { class: 'card' }, h('h2', {}, 'Add a node'),
    h('ol', { class: 'steps-list' },
      h('li', {}, 'On the new server, start DNServe the same way as this one (the same ', h('code', {}, 'docker compose'), ' file works). Make sure port ', h('b', {}, '8081'), ' is published and open between the servers.'),
      h('li', {}, 'Open its dashboard, enter its setup code, and choose ', h('b', {}, 'No, add this server to my DNServe'), '.'),
      h('li', {}, 'Paste the join code from here. It works once, for an hour.')),
    h('p', { class: 'muted small' }, 'Adding a ', h('b', {}, 'witness'), ' instead? It\u2019s the same image on a third machine; it only votes, so it needs very little. Make a join code and the next screen shows the command to start it.'),
    form({}, [
      h('label', { for: 'host' }, 'Other nodes reach this one at'),
      h('div', { class: 'row' }, h('input', { id: 'host', name: 'host', type: 'text', value: c.advertise_learned ? (c.advertise || '').replace(/:\d+$/, '').replace(/^\[|\]$/g, '') : location.hostname, required: true, spellcheck: 'false' }), h('span', { class: 'muted' }, ':' + ((c.advertise || '').match(/:(\d+)$/) || [, '8081'])[1])),
      h('p', { class: 'muted small' }, 'This server’s address on your network. Usually the one in your browser’s address bar.'),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Make a join code')),
    ], async (f) => {
      const r = await api('POST', '/cluster/join-codes', { host: val(f, 'host').trim() });
      const cmd = 'docker run -d --name dnserve-witness --restart unless-stopped \\\n  -p 8081:8081 -v dnserve-witness:/data \\\n  -e DNSERVE_ROLE=witness -e DNSERVE_JOIN=' + r.code + ' \\\n  ghcr.io/prezmc/dnserve:latest';
      const copy = (text) => (ev) => navigator.clipboard.writeText(text).then(() => { ev.target.textContent = 'Copied'; });
      const d = dialog('Join code', [
        h('p', {}, 'For a full node, paste this into the new server’s setup page. It works once and expires at ' + fmtTime(r.expires_at) + '.'),
        h('textarea', { class: 'code', readonly: true, 'aria-label': 'Join code' }, r.code),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'button', onclick: copy(r.code) }, 'Copy code')),
        h('details', {}, h('summary', {}, 'Starting a witness instead'),
          h('p', { class: 'small' }, 'On the third machine, run:'),
          h('textarea', { class: 'tall code', readonly: true, 'aria-label': 'Witness command' }, cmd),
          h('div', { class: 'actions' }, h('button', { type: 'button', onclick: copy(cmd) }, 'Copy command'))),
        h('div', { class: 'actions' }, h('button', { type: 'button', onclick: () => d.close() }, 'Done'))]);
      d.classList.add('wide');
      d.addEventListener('close', () => route());
    })) : null;

  const recoverCard = !c.healthy && !c.left_out && others.length ? h('div', { class: 'card' }, h('h2', {}, 'Recover with this node only'),
    h('p', {}, 'If ', others.map(n => n.name).join(' and '), ' is gone for good (broken, wiped or replaced), make this node the whole cluster. It keeps its accounts and settings and starts taking changes again.'),
    h('p', { class: 'muted small' }, 'DNServe checks first that no other node answers, so two clusters never run at once. The nodes left out are locked out; to use one again, wipe it and join it with a new code.'),
    form({}, [
      h('label', { for: 'rpw' }, 'Your password'),
      h('input', { id: 'rpw', name: 'password', type: 'password', autocomplete: 'current-password', required: true }),
      h('div', { class: 'actions' }, h('button', { class: 'primary danger-fill', type: 'submit' }, 'Recover with ' + self.name)),
    ], async (f) => {
      const password = val(f, 'password');
      try {
        await api('POST', '/cluster/recover', { password });
      } catch (e) {
        if (!/could still be running/.test(e.message)) throw e;
        if (!(await ask(e.message + '. Recover anyway?', 'Recover anyway'))) return;
        await api('POST', '/cluster/recover', { password, accept_risk: true });
      }
      toast(self.name + ' is now the whole cluster');
      route();
    })) : null;

  const joinCard = data.can_join ? h('details', { class: 'card' }, h('summary', {}, 'Join another DNServe instead'),
    msg('warn', 'This replaces everything on this node (accounts, settings, devices and groups) with the other DNServe’s. You’ll sign in again with an account from there.'),
    form({}, [
      h('label', { for: 'jc' }, 'Join code from the other DNServe'),
      h('textarea', { id: 'jc', name: 'join', class: 'code', rows: 3, required: true, spellcheck: 'false', placeholder: 'DNSJ1-…' }),
      h('label', { for: 'jpw' }, 'Your password'),
      h('input', { id: 'jpw', name: 'password', type: 'password', autocomplete: 'current-password', required: true }),
      h('div', { class: 'actions' }, h('button', { class: 'primary danger-fill', type: 'submit' }, 'Replace and join')),
    ], async (f) => {
      if (!(await ask('Replace this node’s accounts and settings with the other DNServe’s?', 'Replace and join'))) return;
      await api('POST', '/cluster/join', { join_code: val(f, 'join'), password: val(f, 'password'), host: location.hostname });
      csrf = ''; ME = null;
      joinWaiting();
    })) : null;

  page(main, 'Cluster',
    h('div', { class: 'card' }, status),
    h('div', { class: 'card scroll' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'Node'), h('th', {}, 'Role'), h('th', {}, 'Status'), h('th', {}, 'Address'), h('th', {}, 'Version'), h('th', {}))),
      h('tbody', {}, rows))),
    addCard, recoverCard, joinCard);

  timer = setInterval(async () => {
    if (document.hidden || document.querySelector('dialog') || unsaved()) return;
    try {
      const fresh = await api('GET', '/cluster');
      if (JSON.stringify(strip(fresh)) !== JSON.stringify(strip(data))) route();
    } catch (_) { /* keep showing */ }
  }, 5000);
  function strip(d) { return (d.cluster.nodes || []).map(n => [n.id, n.role, n.reachable, n.leader, n.preferred, n.never_leader, n.name, n.behind > 20]).concat([d.cluster.healthy, d.cluster.left_out]); }

  function renameNode(n) {
    const d = dialog('Rename ' + n.name, form({}, [
      h('input', { name: 'name', type: 'text', value: n.name, maxlength: 64, required: true, autofocus: true, 'aria-label': 'Node name' }),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save'), h('button', { type: 'button', onclick: () => d.close() }, 'Cancel')),
    ], async (f) => {
      await api('PUT', '/cluster/nodes/' + n.id, { name: val(f, 'name').trim() });
      d.close();
      route();
    }));
  }

  async function neverLead(n) {
    if (!n.never_leader && !(await ask(n.name + ' will keep a full copy and answer DNS, but never lead or vote. ' +
      (c.voters === 2 ? 'The other node can then take changes on its own, even while ' + n.name + ' is down.' : ''), 'Never lead', false))) return;
    act(() => api('PUT', '/cluster/nodes/' + n.id, { never_leader: !n.never_leader }));
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

// showCodes puts fresh recovery codes in a dialog.
function showCodes(title, codes) {
  const text = 'DNServe recovery codes for ' + ME.user.username + ' on ' + location.hostname + '\n' +
    'Each code works once. Keep them somewhere safe.\n\n' + codes.join('\n') + '\n';
  const done = h('button', { class: 'primary', type: 'button', disabled: true, onclick: () => d.close() }, 'Done');
  const d = dialog(title, [
    h('p', { class: 'muted' }, 'Your old recovery codes no longer work. Each of these lets you sign in once if you lose your phone.'),
    h('div', { class: 'codes mono' }, codes.map(c => h('div', {}, c))),
    h('div', { class: 'actions' },
      h('button', { type: 'button', onclick: () => download('dnserve-recovery-codes.txt', text) }, 'Download'),
      h('button', { type: 'button', onclick: (ev) => navigator.clipboard.writeText(text).then(() => { ev.target.textContent = 'Copied'; }) }, 'Copy')),
    h('label', { class: 'inline' }, h('input', { type: 'checkbox', onchange: (ev) => { done.disabled = !ev.target.checked; } }), "I've saved these codes"),
    h('div', { class: 'actions' }, done)]);
  d.addEventListener('cancel', (ev) => { if (done.disabled) ev.preventDefault(); });
  d.addEventListener('close', async () => { try { ME = await api('GET', '/auth/me'); } catch (_) { /* keep */ } route(); });
}

function newRecovery() {
  const d = dialog('Make new recovery codes', form({}, [
    h('p', { class: 'muted' }, 'Your current recovery codes stop working.'),
    h('label', { for: 'rpw' }, 'Your password'),
    h('input', { id: 'rpw', name: 'password', type: 'password', autocomplete: 'current-password', required: true, autofocus: true }),
    h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Make new codes'), h('button', { type: 'button', onclick: () => d.close() }, 'Cancel')),
  ], async (f) => {
    const r = await api('POST', '/auth/recovery-codes', { password: val(f, 'password') });
    d.close();
    showCodes('Your new recovery codes', r.recovery_codes);
  }));
}

function newAuthenticator() {
  const body = h('div');
  const d = dialog('Move to a new phone or app', body);
  fill(body, form({}, [
    h('p', { class: 'muted' }, 'Your current app keeps working until the new one is confirmed.'),
    h('label', { for: 'apw' }, 'Your password'),
    h('input', { id: 'apw', name: 'password', type: 'password', autocomplete: 'current-password', required: true, autofocus: true }),
    h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Continue'), h('button', { type: 'button', onclick: () => d.close() }, 'Cancel')),
  ], async (f) => {
    const t = await api('POST', '/auth/authenticator/begin', { password: val(f, 'password') });
    fill(body,
      h('p', { class: 'muted' }, 'Scan this with the new app:'),
      t.qr_png ? h('img', { class: 'qr', src: t.qr_png, alt: 'QR code for your authenticator app' }) : null,
      h('details', {}, h('summary', { class: 'small' }, "Can't scan? Enter the key by hand"),
        h('p', { class: 'small' }, 'Account: ', h('b', {}, ME.user.username), ', key: ', h('code', {}, t.secret.match(/.{1,4}/g).join(' ')), ' (time-based, 6 digits).')),
      form({}, [
        h('label', { for: 'ncode' }, 'Code from the new app'),
        h('input', { id: 'ncode', name: 'code', class: 'code', type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 7, required: true }),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Switch to this app'), h('button', { type: 'button', onclick: () => d.close() }, 'Cancel')),
      ], async (f2) => {
        const r = await api('POST', '/auth/authenticator/confirm', { code: val(f2, 'code') });
        d.close();
        showCodes('New app is on. Save your new recovery codes', r.recovery_codes);
      }));
    const c = body.querySelector('#ncode');
    if (c) c.focus();
  }));
}

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

    h('div', { class: 'card' }, h('h2', {}, 'Two-factor sign-in'),
      h('p', { class: 'muted' }, 'You have ', h('b', {}, String(ME.user.recovery_codes_left !== undefined ? ME.user.recovery_codes_left : '?')), ' unused recovery codes.'),
      h('div', { class: 'actions' },
        h('button', { type: 'button', onclick: () => newAuthenticator() }, 'Move to a new phone or app'),
        h('button', { type: 'button', onclick: () => newRecovery() }, 'Make new recovery codes'))),

    h('div', { class: 'card' }, h('h2', {}, 'Signed-in sessions'),
      h('div', { class: 'scroll' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Device'), h('th', {}, 'IP'), h('th', {}, 'Signed in'), h('th', {}, 'Last used'), h('th', {}))),
        h('tbody', {}, sessions.filter(x => x.stage === 'full').map(x => h('tr', {},
          h('td', { title: x.user_agent || '' }, deviceName(x.user_agent)), h('td', {}, x.ip), h('td', {}, fmtTime(x.created)), h('td', {}, fmtTime(x.last_seen)),
          h('td', {}, x.id === ME.session_id ? h('span', { class: 'badge' }, 'this one')
            : h('button', { class: 'link danger', onclick: async () => { try { await api('DELETE', '/auth/sessions/' + x.id); route(); } catch (e) { toast(e.message, 'err'); } } }, 'Sign out')))))))),

    h('div', { class: 'card' }, h('h2', {}, 'API tokens'),
      h('p', { class: 'muted' }, 'For scripts and home automation. Send as ', h('code', {}, 'Authorization: Bearer <token>'), '. A token can do only what you pick, and never more than your own account.'),
      tokens.length ? h('div', { class: 'scroll' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Name'), h('th', {}, 'Can'), h('th', {}, 'Created'), h('th', {}, 'Expires'), h('th', {}))),
        h('tbody', {}, tokens.map(t => h('tr', {}, h('td', {}, t.name), h('td', { class: 'small' }, (t.perms || []).map(p => PERMS[p] || p).join(', ')), h('td', {}, fmtTime(t.created_at)), h('td', {}, t.expires_at ? fmtTime(t.expires_at) : 'never'),
          h('td', {}, h('button', { class: 'link danger', onclick: async () => { if (!(await ask('Revoke the token "' + t.name + '"? Anything using it stops working.', 'Revoke'))) return; try { await api('DELETE', '/tokens/' + t.id); route(); } catch (e) { toast(e.message, 'err'); } } }, 'Revoke'))))))) : null,
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
