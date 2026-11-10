// DNServ dashboard. Plain JavaScript, no build step, no external assets.
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

// fuzzyScore says how well q matches text: higher is better, -1 is no
// match. Every letter of q must appear in order; a plain substring, a match
// at the start of a word and letters close together score higher.
function fuzzyScore(q, text) {
  q = q.toLowerCase().replace(/\s+/g, '');
  text = text.toLowerCase();
  if (!q) return 0;
  const sub = text.indexOf(q);
  if (sub >= 0) return 1000 - sub - (sub === 0 || /[\s.\-_(]/.test(text[sub - 1]) ? 0 : 50);
  let score = 0, last = -1;
  for (const c of q) {
    const i = text.indexOf(c, last + 1);
    if (i < 0) return -1;
    score += i === last + 1 ? 10 : (/[\s.\-_(]/.test(text[i - 1] || ' ') ? 5 : 1);
    last = i;
  }
  return score;
}

// combo is a select box you can type into: typing narrows the choices with
// fuzzy matching (letters in order, so "lvrm" finds "Living room TV").
// opts.options is [{value, label, detail}]; detail (an IP, say) is shown
// and searched too. With opts.free, any text is a value and the options
// are only suggestions. onchange gets the chosen value.
function combo(opts) {
  let options = opts.options || [];
  let value = opts.value || '';
  let shown = [], active = -1;
  const labelOf = (v) => { const o = options.find(o => o.value === v); return o ? o.label + (o.detail && o.detail !== o.label ? ' · ' + o.detail : '') : v; };
  const input = h('input', { type: 'text', role: 'combobox', 'aria-autocomplete': 'list', 'aria-expanded': 'false', 'aria-label': opts.label,
    placeholder: opts.placeholder || '', spellcheck: 'false', autocomplete: 'off', value: opts.free ? value : (value ? labelOf(value) : '') });
  const list = h('ul', { class: 'combo-list', role: 'listbox', hidden: true });
  const wrap = h('div', { class: 'combo' + (opts.class ? ' ' + opts.class : '') }, input, list);
  const close = () => { list.hidden = true; input.setAttribute('aria-expanded', 'false'); active = -1; };
  const pick = (o) => {
    value = o ? o.value : '';
    input.value = opts.free ? value : (o && o.value ? labelOf(o.value) : '');
    close();
    opts.onchange && opts.onchange(value);
  };
  const draw = () => {
    const q = input.value.trim();
    const typed = !opts.free && value && q === labelOf(value) ? '' : q;
    shown = options.map(o => ({ o, s: fuzzyScore(typed, o.label + ' ' + (o.detail || '') + ' ' + o.value) }))
      .filter(x => x.s >= 0).sort((a, b) => typed ? b.s - a.s : 0).slice(0, 50).map(x => x.o);
    active = shown.length && typed ? 0 : -1;
    list.replaceChildren(...(shown.length ? shown.map((o, i) => h('li', { role: 'option', class: i === active ? 'on' : null, 'aria-selected': String(o.value === value),
      onmousedown: (ev) => { ev.preventDefault(); pick(o); } }, o.label, o.detail && o.detail !== o.label ? h('span', { class: 'muted small' }, ' ', o.detail) : null))
      : [h('li', { class: 'muted small empty' }, opts.free ? 'No suggestions' : 'Nothing matches')]));
    list.hidden = opts.free && !shown.length;
    input.setAttribute('aria-expanded', String(!list.hidden));
  };
  const move = (d) => {
    if (list.hidden) draw();
    if (!shown.length) return;
    active = (active + d + shown.length) % shown.length;
    list.querySelectorAll('li').forEach((li, i) => li.classList.toggle('on', i === active));
    const li = list.children[active];
    li && li.scrollIntoView({ block: 'nearest' });
  };
  input.addEventListener('focus', () => { if (!opts.free) input.select(); draw(); });
  input.addEventListener('input', () => { draw(); if (opts.free) { value = input.value.trim(); opts.oninput && opts.oninput(value); } });
  input.addEventListener('blur', () => {
    close();
    if (!opts.free) input.value = value ? labelOf(value) : ''; // typed text that wasn't picked is dropped
  });
  input.addEventListener('keydown', (ev) => {
    if (ev.key === 'ArrowDown') { ev.preventDefault(); move(1); }
    else if (ev.key === 'ArrowUp') { ev.preventDefault(); move(-1); }
    else if (ev.key === 'Enter') {
      if (!list.hidden && active >= 0) { ev.preventDefault(); pick(shown[active]); }
      else if (opts.free) { close(); opts.onchange && opts.onchange(value); }
    } else if (ev.key === 'Escape' && !list.hidden) { ev.preventDefault(); ev.stopPropagation(); close(); }
  });
  wrap.setOptions = (o) => { options = o; if (!list.hidden) draw(); };
  Object.defineProperty(wrap, 'value', { get: () => value });
  return wrap;
}

// deviceOptions lists devices for a combo, each with its addresses, since
// a device's name is only as good as what the router or DHCP reported.
function deviceOptions(devs, all) {
  const out = all ? [{ value: '', label: all }] : [];
  devs.forEach(d => out.push({ value: d.id || d.addrs[0], label: deviceLabel(d), detail: (d.addrs || []).join(', ') }));
  return out;
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
  get(k) { try { return sessionStorage.getItem('dnserv.' + k); } catch (_) { return null; } },
  set(k, v) { try { v === null ? sessionStorage.removeItem('dnserv.' + k) : sessionStorage.setItem('dnserv.' + k, v); } catch (_) { /* ignore */ } },
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
  return 'You have an account on DNServ, our home network\u2019s DNS filter.\n\n' +
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
  'filtering.pause': 'Pause filtering',
  'devices.manage': 'Manage devices and groups',
  'upstream.manage': 'Change how DNS is resolved',
  'network.manage': 'Change allowed networks',
  'users.manage': 'Manage users (admin)',
  'cluster.manage': 'Manage the cluster (admin)',
  'backups.manage': 'Manage backups (admin)',
  'audit.view': 'View the audit log (admin)',
};
const POWER_PERMS = ['dashboard.view', 'querylog.view', 'data.export', 'domains.allowblock', 'rules.edit', 'lists.manage', 'filtering.pause', 'devices.manage', 'upstream.manage', 'network.manage'];
const VIEWER_PERMS = ['dashboard.view', 'querylog.view', 'filtering.pause'];

const PROVIDERS = {
  cloudflare: { name: 'Cloudflare (1.1.1.1)', note: 'Fast, no filtering of its own.', servers: ['https://cloudflare-dns.com/dns-query', 'tls://one.one.one.one'] },
  quad9: { name: 'Quad9 (9.9.9.9)', note: 'Non-profit; also blocks known malware domains.', servers: ['https://dns.quad9.net/dns-query', 'tls://dns.quad9.net'] },
  mullvad: { name: 'Mullvad', note: 'Privacy-focused, keeps no logs.', servers: ['https://dns.mullvad.net/dns-query', 'tls://dns.mullvad.net'] },
};
const providerFor = (servers) => Object.keys(PROVIDERS).find(k => JSON.stringify(PROVIDERS[k].servers) === JSON.stringify(servers || [])) || 'custom';

const MODES = {
  forward: { title: 'Encrypted forwarding (recommended)', note: "Lookups go encrypted to a public resolver you pick, so your ISP can't see or change them." },
  recursive: { title: 'Full recursion', note: 'DNServ asks the domain servers itself and checks DNSSEC. No single company sees all your lookups, but your ISP can see them.' },
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
    h('p', { class: 'muted small' }, "Leave the secondary DNS empty or point it at a second DNServ node. A public one such as 8.8.8.8 lets devices skip filtering. Devices switch over when they reconnect to Wi-Fi."),
  ];
}

// ---------- boot ----------

async function boot() {
  try {
    ME = await api('GET', '/auth/me');
  } catch (e) {
    return render(h('div', { class: 'center' }, h('div', { class: 'card' }, h('h1', {}, 'DNServ'), msg('err', 'Could not reach the node: ' + e.message), h('button', { onclick: boot }, 'Try again'))));
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
    h('h1', {}, 'Welcome to DNServ'),
    h('p', { class: 'muted' }, "First, prove this is your server. DNServ printed a setup code in its container log when it started. It's in a box headed \u201cDNServ first-run setup\u201d. From a terminal:"),
    h('p', {}, h('code', {}, 'docker logs dnserv')),
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

// setupChoice: a new DNServ, or another node for an existing one.
function setupChoice(code) {
  render(centered(
    wizardSteps(1),
    h('h1', {}, 'Is this your first DNServ?'),
    h('div', { class: 'choices' },
      h('button', { class: 'choice', type: 'button', autofocus: true, onclick: () => setupAdmin(code) },
        h('b', {}, 'Yes, set up a new DNServ'), h('span', { class: 'muted small' }, 'Create an admin account and choose your settings.')),
      h('button', { class: 'choice', type: 'button', onclick: () => setupJoin(code) },
        h('b', {}, 'No, add this server to my DNServ'), h('span', { class: 'muted small' }, 'It copies the accounts, settings and blocklists from your other node and stays in sync with it.')),
      h('button', { class: 'choice', type: 'button', onclick: () => setupRestore(code) },
        h('b', {}, 'Restore from a backup'), h('span', { class: 'muted small' }, 'Bring back the accounts and settings from a DNServ backup file.'))),
    h('div', { class: 'actions' }, h('button', { class: 'link', type: 'button', onclick: setupAccount }, 'Back')),
  ));
}

function setupJoin(code) {
  render(centered(
    h('h1', {}, 'Add this server to your DNServ'),
    h('ol', { class: 'steps-list' },
      h('li', {}, 'On your other DNServ, open ', h('b', {}, 'Cluster'), ' and choose ', h('b', {}, 'Add a node'), '.'),
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
  render(centered(h('h1', {}, 'Joining your DNServ'), note, h('div', { class: 'spinner', 'aria-hidden': 'true' })));
  const started = Date.now();
  timer = setInterval(async () => {
    let su;
    try { su = await api('GET', '/setup'); } catch (_) { return; }
    if (!su.needed) {
      clearInterval(timer); timer = null;
      render(centered(
        h('h1', {}, 'This server is now part of your DNServ'),
        msg('ok', 'It has the same accounts, settings and blocklists as your other node, and keeps in sync with it.'),
        h('p', {}, 'Sign in with your usual DNServ account. To use it for DNS, add its address to your router as a second DNS server.'),
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
    h('p', { class: 'muted' }, 'DNServ on ' + location.hostname),
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
    h('p', { class: 'muted' }, 'Every DNServ account needs an authenticator app, such as 1Password, Bitwarden, Google Authenticator, Microsoft Authenticator or Authy. Scan this code with it:'),
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
  const text = 'DNServ recovery codes for ' + (ME.user ? ME.user.username : '') + ' on ' + location.hostname + '\n' +
    'Each code works once. Keep them somewhere safe.\n\n' + codes.join('\n') + '\n';
  const cont = h('button', { class: 'primary', disabled: true, onclick: () => (wizard && can('upstream.manage') ? setupBasics() : boot()) }, 'Continue');
  render(h('div', { class: 'center' }, h('div', { class: 'card' },
    wizard ? wizardSteps(3) : null,
    h('h1', {}, 'Save your recovery codes'),
    h('p', { class: 'muted' }, "If you lose your phone, each of these codes lets you sign in once. They won't be shown again."),
    h('div', { class: 'codes mono' }, codes.map(c => h('div', {}, c))),
    h('div', { class: 'actions' },
      h('button', { type: 'button', onclick: () => download('dnserv-recovery-codes.txt', text) }, 'Download'),
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
    h('h1', {}, 'Choose how DNServ protects you'),
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
        h('span', {}, h('b', {}, "Don't let devices skip DNServ"), ' ', h('span', { class: 'muted small' }, 'Blocks browsers and apps from using their own encrypted DNS (and iCloud Private Relay). Good for families. A few apps may then fail to connect.'))),
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
    h('p', {}, 'Last step: send your devices to DNServ.'),
    routerHelp(),
    seen,
    h('div', { class: 'actions' }, h('button', { class: 'primary', onclick: () => { location.hash = '#/'; boot(); } }, 'Open the dashboard'),
      isAdmin() ? h('button', { onclick: () => { location.hash = '#/import'; boot(); } }, 'Import from AdGuard Home') : null),
  ));
  // Show devices as they arrive, so it's clear the router change worked.
  const poll = async () => {
    let ds;
    try { ds = await api('GET', '/devices'); } catch (_) { return; }
    ds = ds.filter(d => d.queries > 0);
    fill(seen, h('h3', {}, 'Devices using DNServ'),
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
  { path: 'analytics', title: 'Analytics', page: analyticsPage, show: () => can('dashboard.view') },
  { path: 'performance', title: 'Performance', page: performancePage, show: () => can('dashboard.view') },
  { path: 'queries', title: 'Query log', page: queries, show: () => can('querylog.view') },
  { path: 'names', title: 'Local names', page: localNames, show: () => can('network.manage') },
  { path: 'settings', title: 'Settings', page: settings, show: () => ['upstream.manage', 'network.manage', 'lists.manage', 'rules.edit'].some(can) },
  { path: 'users', title: 'Users', page: users, show: () => can('users.manage') },
  { path: 'cluster', title: 'Cluster', page: clusterPage, show: () => can('cluster.manage') },
  { path: 'backups', title: 'Backups & history', page: backupsPage, show: () => can('backups.manage') },
  { path: 'import', title: 'Import from AdGuard Home', page: importPage, show: isAdmin, hidden: true },
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
    h('div', { class: 'brand' }, h('a', { href: '#/', class: 'logo' }, h('img', { src: 'logo.svg', alt: '', width: 26, height: 26 }), h('span', {}, 'DN', h('b', {}, 'Serv'))), menu),
    h('div', { id: 'navlinks', class: 'links' },
      ROUTES.filter(x => x.show() && !x.hidden).map(x => h('a', { href: '#/' + x.path, class: x === r ? 'active' : '', 'aria-current': x === r ? 'page' : null }, navIcon(x.path), x.title))),
    h('div', { class: 'spacer' }),
    h('div', { class: 'who' }, h('span', { class: 'avatar', 'aria-hidden': 'true' }, (ME.user.username || '?').slice(0, 1).toUpperCase()), h('span', {}, ME.user.username, h('span', { class: 'role' }, ME.user.role))),
    h('button', { class: 'link', onclick: async () => { try { await api('POST', '/auth/logout'); } catch (_) { /* ignore */ } csrf = ''; ME = null; boot(); } }, 'Sign out'));
  const main = h('main', {});
  shownHash = location.hash;
  render(h('div', { class: 'shell' }, nav, main));
  document.title = r.title + ' · DNServ';
  r.page(main);
}

// navIcon is a small line icon for a menu entry (24px grid, drawn in
// the text colour so it follows the theme).
const NAV_ICONS = {
  '': 'M4 13h6V4H4zM14 20h6v-9h-6zM14 8h6V4h-6zM4 20h6v-3H4z',
  devices: 'M3 5h18v11H3zM8 20h8M12 16v4',
  analytics: 'M4 20V10M10 20V4M16 20v-7M22 20H2',
  performance: 'M13 3 4 14h7l-1 7 9-11h-7z',
  queries: 'M4 6h16M4 12h16M4 18h10',
  names: 'M4 4h10l6 6v10H4zM14 4v6h6M8 14h8M8 17h5',
  settings: 'M4 7h10M18 7h2M4 17h4M12 17h8M14 4v6M8 14v6',
  users: 'M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM2 21c0-4 3-6 7-6s7 2 7 6M17 4a4 4 0 0 1 0 7M22 21c0-3-1.5-5-4-5.6',
  cluster: 'M10 5a2 2 0 1 0 4 0 2 2 0 1 0-4 0M3 19a2 2 0 1 0 4 0 2 2 0 1 0-4 0M17 19a2 2 0 1 0 4 0 2 2 0 1 0-4 0M12 7v4M12 11l-6 6M12 11l6 6',
  backups: 'M4 7c0-2 16-2 16 0v10c0 2-16 2-16 0zM4 7c0 2 16 2 16 0M4 12c0 2 16 2 16 0',
  audit: 'M9 4h6v3H9zM6 6H5v15h14V6h-1M9 12h6M9 16h4',
  account: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21c0-4 4-6 8-6s8 2 8 6',
};
function navIcon(path) {
  const d = NAV_ICONS[path];
  return d ? svg('svg', { viewBox: '0 0 24 24', class: 'ico', 'aria-hidden': 'true' }, svg('path', { d })) : null;
}

function fill(el, ...kids) { el.replaceChildren(...kids.flat(Infinity).filter(k => k !== null && k !== undefined && k !== false)); }
function page(main, title, ...kids) { fill(main, h('h1', {}, title), kids); }

// ---------- dashboard ----------

const DASH_RANGES = ['24h', '7d', '30d'];

// sparkline is a tiny trend line for a dashboard tile.
function sparkline(values) {
  const max = Math.max(...values), n = values.length;
  if (!(max > 0)) return null;
  const pts = values.map((v, i) => (100 * i / (n - 1)).toFixed(1) + ',' + (30 - 27 * v / max).toFixed(1));
  return svg('svg', { viewBox: '0 0 100 32', preserveAspectRatio: 'none', class: 'spark', 'aria-hidden': 'true' },
    svg('path', { d: 'M0,32L' + pts.join('L') + 'L100,32Z', class: 'area' }),
    svg('path', { d: 'M' + pts.join('L'), class: 'stroke' }));
}

// serversCard shows which server answered what: each one's share of the
// queries, blocks, cache answers and response time, so a cluster's split
// of the work (and a server that has gone quiet) is easy to see.
function serversCard(sum, s) {
  const nodes = (sum.nodes || []).filter(n => n.name);
  if (!nodes.length) return null;
  const total = nodes.reduce((a, n) => a + (n.counts ? n.counts.total : 0), 0);
  const leader = s.cluster && s.cluster.nodes > 1 ? s.cluster.leader : '';
  const self = s.cluster && s.cluster.name;
  const pct = (a, b) => (b ? fmtPct(a / b) : '—');
  return h('div', { class: 'card d-servers' },
    h('div', { class: 'row spread' }, h('h2', {}, nodes.length > 1 ? 'Servers' : 'Server'), can('cluster.manage') ? h('a', { href: '#/cluster', class: 'small' }, 'Cluster') : null),
    // One block per server (name, then its numbers), so it fits the
    // narrow dashboard column at any width.
    h('div', { class: 'servers' }, nodes.map(n => {
      const c = n.counts || { total: 0, blocked: 0, cached: 0, ms_sum: 0 };
      const stat = (label, v, sub) => h('div', { class: 'stat' }, h('div', { class: 'muted small' }, label), h('div', { class: 'num' }, v), sub ? h('div', { class: 'muted small' }, sub) : null);
      return h('div', { class: 'server' },
        h('div', { class: 'row' }, h('span', { class: 'nowrap' }, h('span', { class: 'dot ' + (n.ok ? 'ok' : 'bad') }), h('b', {}, n.name)),
          n.name === leader ? h('span', { class: 'badge accent' }, 'leader') : null,
          n.name === self && nodes.length > 1 ? h('span', { class: 'muted small' }, 'this one') : null),
        n.ok ? bar(c.total, Math.max(...nodes.map(x => (x.counts ? x.counts.total : 0)))) : h('div', { class: 'small bad-text' }, n.error || 'not answering'),
        n.ok ? h('div', { class: 'stats' },
          stat('Queries', fmtNum(c.total), nodes.length > 1 ? pct(c.total, total) + ' of all' : null),
          stat('Blocked', pct(c.blocked, c.total)),
          stat('Cache', pct(c.cached, c.total)),
          stat('Avg', c.total ? fmtMs(c.ms_sum / c.total) : '—')) : null);
    })),
    h('p', { class: 'muted small' }, 'Answers each server gave its devices. Devices pick a server themselves, so an even split is not expected.'));
}

async function dashboard(main) {
  const body = h('div', {}, h('p', { class: 'muted' }, 'Loading…'));
  const devBox = h('div');
  const chartBox = h('div');
  const extraBox = h('div');
  const ver = h('p', { class: 'muted small d-ver' });
  // The period applies to the tiles, chart and top lists, like the time
  // picker at the top of a cloud DNS console.
  const range = DASH_RANGES.includes(hashParams().get('range')) ? hashParams().get('range') : '24h';
  const status = h('span', { class: 'pill' }, h('span', { class: 'dot' }), 'Checking…');
  const pauseBtn = h('span');
  const pauseBox = h('div');
  const head = h('div', { class: 'page-head' }, h('h1', {}, 'Dashboard'), status, pauseBtn, h('span', { class: 'grow' }),
    can('dashboard.view') ? h('div', { class: 'seg', role: 'group', 'aria-label': 'Period' }, DASH_RANGES.map(k =>
      h('button', { type: 'button', 'aria-pressed': String(k === range), onclick: () => {
        history.replaceState(null, '', '#/' + (k === '24h' ? '' : '?range=' + k));
        shownHash = location.hash;
        route();
      } }, k))) : null);
  fill(main, head, h('div', { class: 'dash' }, pauseBox, body, chartBox, extraBox, devBox, checkDomainCard(), ver));
  const pause = pauseControl(pauseBtn, pauseBox, () => load());

  // The tiles and upstream counts come from the saved query history (the
  // chosen period, every node) so they survive restarts and updates; the
  // counters since start are only used when history is off.
  const hist = { sum: null, perf: null, at: 0 };
  const loadHist = async () => {
    if (!can('dashboard.view')) return;
    const [sum, perf] = await Promise.all([api('GET', '/analytics/summary?range=' + range).catch(() => null), api('GET', '/analytics/performance?range=' + range).catch(() => null)]);
    hist.sum = sum && (sum.stats || sum.detail) ? sum : null;
    hist.perf = perf && (perf.stats || perf.detail) ? perf : null;
    hist.at = Date.now();
  };
  const load = async () => {
    let s;
    if (Date.now() - hist.at > 60000) await loadHist();
    let pz;
    try { [s, pz] = await Promise.all([api('GET', '/status'), api('GET', '/pause').catch(() => null)]); } catch (e) { body.replaceChildren(msg('err', e.message)); return; }
    pause.show(pz, s);
    const q = s.queries || {};
    let total = ['upstream', 'cached', 'stale', 'blocked', 'local', 'error'].reduce((a, k) => a + (q[k] || 0), 0);
    let blocked = q.blocked || 0, cached = (q.cached || 0) + (q.stale || 0);
    const fromHist = !!hist.sum;
    if (fromHist) {
      const c = hist.sum.counts;
      total = c.total; blocked = c.blocked; cached = c.cached;
    }
    const pct = (n) => (total ? (100 * n / total).toFixed(1) + '%' : '—');
    // Upstream tries and failures over the same 24 hours, on this server.
    const upHist = new Map();
    if (hist.perf) {
      const self = s.cluster && s.cluster.name;
      for (const u of hist.perf.view.upstreams) if (!self || u.node === self || hist.perf.view.upstreams.every(x => x.node !== self)) {
        const cur = upHist.get(u.server) || { tries: 0, failed: 0 };
        cur.tries += u.tries; cur.failed += u.errors + u.timeouts;
        upHist.set(u.server, cur);
      }
    }
    // Each tile opens the page with the detail behind it, and shows its
    // trend over the period when history is on.
    const series = fromHist ? hist.sum.series || [] : [];
    const rq = range === '24h' ? '' : 'range=' + range;
    const tile = (label, value, sub, href, values) => h(href ? 'a' : 'div', { class: 'tile', href },
      h('div', { class: 'label' }, label), h('div', { class: 'value' }, value), sub ? h('div', { class: 'sub muted' }, sub) : null,
      values && values.length > 1 ? sparkline(values) : null);
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
    const upName = upstreamLabel;
    const bad = (s.cluster && s.cluster.nodes > 1 && !s.cluster.healthy) || (s.unbound && !s.unbound.ready) || (s.tunnel && !s.tunnel.up);
    const loading = s.filter && !s.filter.ready;
    const off = pz && pz.filtering_enabled === false;
    const paused = pz && pz.paused ? (pz.pauses.some(p => p.node === '*') ? 'Filtering paused' : 'Paused on ' + pz.pauses.map(p => p.node_name).join(', ')) : '';
    status.className = 'pill ' + (bad ? 'bad' : loading || paused || off ? 'warn' : 'ok');
    fill(status, h('span', { class: 'dot' }), bad ? 'Needs attention' : paused || (off ? 'Filtering is off' : loading ? 'Loading lists' : 'Protecting your network'));
    fill(body,
      total === 0 ? h('div', { class: 'card highlight d-wait' }, h('h2', {}, 'Waiting for your first device'), routerHelp()) : null,
      h('p', { class: 'muted small d-note' }, fromHist ? [RANGES[range], hist.sum.nodes && hist.sum.nodes.length > 1 ? ', all servers' : '', '. DNServ started ', (s.uptime_seconds || 0) < 60 ? 'just now' : fmtDur(s.uptime_seconds) + ' ago', '.']
        : ['Counting since DNServ started ', (s.uptime_seconds || 0) < 60 ? 'just now' : fmtDur(s.uptime_seconds) + ' ago', '. Turn on query history to keep counts across restarts.']),
      h('div', { class: 'grid d-tiles' },
        tile('Queries', fmtNum(total), fromHist ? fmtNum(hist.sum.devices || 0) + ' devices' : null,
          can('querylog.view') ? '#/queries' + (rq ? '?' + rq : '') : null, series.map(p => p.total)),
        tile('Blocked', total ? fmtNum(blocked) : '0', total ? pct(blocked) + ' of queries' : null,
          can('querylog.view') ? '#/queries?result=blocked' + (rq ? '&' + rq : '') : null, series.map(p => p.blocked)),
        tile('Answered from cache', pct(cached), total ? fmtNum(cached) + ' answers' : null,
          can('dashboard.view') ? '#/performance' + (rq ? '?' + rq : '') : null, series.map(p => (p.total ? p.cached / p.total : 0))),
        tile('Blocking rules', fmtNum(s.filter ? s.filter.rules : 0), s.filter && s.filter.lists ? s.filter.lists.filter(l => !l.allowlist).length + ' lists' : null,
          ['lists.manage', 'rules.edit'].some(can) ? '#/settings' : null)),
      fromHist ? serversCard(hist.sum, s) : null,
      h('div', { class: 'card d-health' }, h('h2', {}, 'Health'), health,
        (s.upstreams && s.upstreams.length) ? h('div', { class: 'scroll' }, h('table', {},
          h('thead', {}, h('tr', {}, h('th', {}, 'Resolver'), h('th', {}, 'Latency'), h('th', {}, 'Queries'), h('th', {}, 'Failures'))),
          h('tbody', {}, s.upstreams.map(u => {
            const hu = hist.perf ? (upHist.get(u.server) || { tries: 0, failed: 0 }) : null;
            return h('tr', {}, h('td', { title: u.server }, upName(u.server)), h('td', {}, u.latency_ms ? u.latency_ms.toFixed(1) + ' ms' : '—'),
              h('td', {}, fmtNum(hu ? hu.tries : u.queries)), h('td', {}, fmtNum(hu ? hu.failed : u.failures)));
          })))) : null),
      (s.filter && s.filter.lists && s.filter.lists.length) ? h('div', { class: 'card d-lists' }, h('div', { class: 'row spread' }, h('h2', {}, 'Lists'), h('div', { class: 'row' }, clearCacheButton(), updateListsButton())), h('div', { class: 'scroll' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'List'), h('th', {}, 'Rules'), h('th', {}, 'Updated'), h('th', {}, 'Status'))),
        h('tbody', {}, s.filter.lists.map(l => h('tr', {}, h('td', {}, l.name, l.allowlist ? ' (allow)' : ''), h('td', {}, fmtNum(l.rules)), h('td', {}, ago(l.updated)),
          h('td', {}, l.error ? h('span', { class: 'badge bad', title: l.error }, l.rules ? 'update failed, using saved copy' : 'download failed') : h('span', { class: 'badge ok' }, 'ok')))))))) : null,
    );
    ver.textContent = 'DNServ ' + s.version;
  };
  const loadDevices = async () => {
    let ds;
    try { ds = await api('GET', '/devices'); } catch (_) { return; }
    const seen = ds.filter(d => d.queries > 0);
    if (!seen.length) { devBox.replaceChildren(); return; }
    devBox.replaceChildren(h('div', { class: 'card d-devices' },
      h('h2', {}, 'Devices ', h('span', { class: 'muted small' }, seen.length + ' seen')),
      deviceTable(seen.slice(0, 5), { compact: true }),
      seen.length > 5 || can('devices.manage') ? h('p', { class: 'small mt-s' }, h('a', { href: '#/devices' }, seen.length > 5 ? 'All ' + seen.length + ' devices' : 'Name your devices')) : null));
  };
  const extras = () => (can('dashboard.view') ? dashboardExtras(extraBox, range) : null);
  await Promise.all([load(), loadDevices(), dashboardChart(chartBox, range), extras()]);
  let tick = 0;
  timer = setInterval(() => {
    if (document.hidden) return;
    load();
    if (++tick % 3 === 0) loadDevices();
    if (tick % 12 === 0) { dashboardChart(chartBox, range); extras(); }
  }, 5000);
}

// ---------- pause filtering ----------

const PAUSE_LABELS = { 1: '1 minute', 5: '5 minutes', 15: '15 minutes', 30: '30 minutes', 60: '1 hour', 0: 'Until I turn it back on' };

// fmtLeft is a countdown: 4:05, or 1:02:05 past an hour.
function fmtLeft(sec) {
  sec = Math.max(0, Math.ceil(sec));
  const hr = Math.floor(sec / 3600), m = Math.floor(sec / 60) % 60, s = sec % 60;
  const pad = (n) => String(n).padStart(2, '0');
  return hr ? hr + ':' + pad(m) + ':' + pad(s) : m + ':' + pad(s);
}

// pauseControl puts the Pause filtering button in the page head and a
// banner for each pause in force, with a live countdown and a button to
// turn filtering back on. reload refreshes the dashboard after a change.
function pauseControl(btnSlot, box, reload) {
  let state = null;
  // Countdowns run off the server's remaining time, so a wrong clock on
  // this computer doesn't matter.
  let ends = [];
  let tick = null;
  const stop = () => { if (tick) { clearInterval(tick); tick = null; } };

  const change = async (method, path, body, note) => {
    try {
      const v = await api(method, path, body);
      show(v);
      toast(note);
      reload();
    } catch (e) { toast(e.message, 'err'); }
  };

  const openMenu = () => {
    const nodes = state.nodes || [];
    let where = '*';
    const whereSeg = nodes.length > 1 ? h('div', { class: 'seg wrap', role: 'group', 'aria-label': 'Which servers' },
      [{ id: '*', name: 'All servers' }].concat(nodes).map(n => h('button', { type: 'button', 'aria-pressed': String(n.id === where), onclick: (ev) => {
        where = n.id;
        whereSeg.querySelectorAll('button').forEach(b => b.setAttribute('aria-pressed', String(b === ev.currentTarget)));
      } }, n.name, n.self ? h('span', { class: 'muted small' }, ' (this one)') : null))) : null;
    const d = dialog('Pause filtering', [
      h('p', { class: 'muted' }, 'Devices get real answers for everything, ads and trackers included, until the pause ends. Local names keep working.'),
      whereSeg ? [h('p', { class: 'small b' }, 'Where'), whereSeg,
        h('p', { class: 'muted small' }, 'Pausing one server only helps devices that use it. Most devices switch between your two DNS servers on their own.')] : null,
      h('p', { class: 'small b' }, 'For how long'),
      h('div', { class: 'pause-opts' }, (state.options || [1, 5, 15, 30, 60, 0]).map(m => h('button', { type: 'button', class: m === 0 ? 'wide' : null, onclick: async () => {
        d.close();
        const name = where === '*' ? '' : nodes.find(n => n.id === where).name;
        await change('POST', '/pause', { minutes: m, node: where }, 'Filtering paused' + (name ? ' on ' + name : nodes.length > 1 ? ' on all servers' : '') + (m ? ' for ' + PAUSE_LABELS[m] : ' until you turn it back on') + '.');
      } }, PAUSE_LABELS[m] || m + ' minutes'))),
      h('div', { class: 'actions' }, h('button', { type: 'button', onclick: () => d.close() }, 'Cancel')),
    ]);
  };

  const render = () => {
    const now = Date.now();
    for (const e of ends) {
      if (!e.at) continue;
      const left = (e.at - now) / 1000;
      if (left <= 0) { stop(); reload(); return; }
      e.el.textContent = fmtLeft(left);
    }
  };

  function show(v) {
    state = v;
    stop();
    ends = [];
    if (!v) { fill(btnSlot); fill(box); return; }
    const many = (v.nodes || []).length > 1;
    const allPaused = v.pauses.some(p => p.node === '*');
    fill(btnSlot, v.can_pause && v.filtering_enabled && !allPaused
      ? h('button', { type: 'button', class: 'small pause-btn', onclick: openMenu }, h('span', { class: 'pause-ico', 'aria-hidden': 'true' }), v.paused ? 'Pause more' : 'Pause filtering')
      : null);
    if (!v.paused) { fill(box); return; }
    fill(box, h('div', { class: 'card d-pause', role: 'status' }, v.pauses.map(p => {
      const left = h('b', { class: 'count' });
      if (!p.indefinite) ends.push({ el: left, at: Date.now() + p.remaining_seconds * 1000 });
      const where = p.node === '*' ? (many ? ' on all servers' : '') : ' on ' + p.node_name;
      return h('div', { class: 'pause-row' },
        h('span', { class: 'pause-ico big', 'aria-hidden': 'true' }),
        h('div', { class: 'grow' },
          h('div', { class: 'b' }, 'Filtering is paused' + where),
          h('div', { class: 'muted small' }, p.indefinite ? 'Until someone turns it back on' : ['Back on in ', left, ' at ', new Date(Date.now() + p.remaining_seconds * 1000).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })],
            ' · paused by ', p.by, ' ', ago(p.since))),
        v.can_pause ? h('button', { type: 'button', class: 'primary', onclick: () => change('DELETE', '/pause' + (p.node === '*' ? '' : '?node=' + encodeURIComponent(p.node)), undefined, 'Filtering is back on' + (p.node === '*' ? '' : ' on ' + p.node_name) + '.') },
          v.pauses.length > 1 && p.node === '*' ? 'Turn back on everywhere' : 'Turn filtering back on') : null);
    })));
    render();
    if (ends.length) {
      tick = setInterval(() => { if (!box.isConnected) { stop(); return; } render(); }, 1000);
    }
  }
  return { show };
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

// clearCacheButton empties the answer cache on every server, so the next
// question for each name goes upstream again.
function clearCacheButton() {
  if (!can('lists.manage')) return null;
  const b = h('button', { type: 'button', class: 'small', onclick: async () => {
    b.disabled = true;
    try {
      const r = await api('POST', '/cache/clear');
      const ok = r.servers.filter(x => !x.error), bad = r.servers.filter(x => x.error);
      toast('Cache cleared: ' + ok.map(x => x.server + ' (' + x.entries.toLocaleString() + ' answers)').join(', ') +
        (bad.length ? '. Couldn\'t reach ' + bad.map(x => x.server).join(', ') + '.' : '.'), bad.length ? 'err' : undefined);
    } catch (e) { toast(e.message, 'err'); }
    setTimeout(() => { b.disabled = false; }, 3000);
  } }, 'Clear cache');
  return b;
}

// clearHistoryButton deletes performance stats ("performance") or all
// query history ("history") on every server, after asking. Admins only.
function clearHistoryButton(what, label, question, after) {
  if (!isAdmin()) return null;
  const b = h('button', { type: 'button', class: 'small', onclick: async () => {
    if (!await ask(question, label)) return;
    b.disabled = true;
    try {
      const r = await api('POST', '/analytics/clear', { what });
      const ok = r.servers.filter(x => !x.error), bad = r.servers.filter(x => x.error);
      toast((ok.length ? 'Cleared on ' + ok.map(x => x.server).join(', ') + '.' : 'Nothing was cleared.') +
        (bad.length ? ' Couldn\'t clear ' + bad.map(x => x.server + ' (' + x.error + ')').join(', ') + '.' : ''), bad.length ? 'err' : undefined);
      if (after) after();
    } catch (e) { toast(e.message, 'err'); }
    b.disabled = false;
  } }, label);
  return b;
}

// ---------- check a domain ----------

function checkDomainCard() {
  const edit = can('domains.allowblock');
  return h('div', { class: 'card d-check' },
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
  if (list.some(d => !d.name) && !list.some(d => d.hostname) && can('network.manage')) {
    settingsHint = msg('warn', '');
    fill(settingsHint, 'Devices show as numbers because DNServ doesn’t know your router. Add your router’s address under ', h('a', { href: '#/settings' }, 'Settings → Device names'), ' to see their names.');
  }
  const gnames = {};
  groups.forEach(g => { gnames[g.id] = g.name; });
  page(main, 'Devices',
    h('p', { class: 'muted' }, 'Every device that has used DNServ since it started, most recent first.'),
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

// ---------- blocked services ----------

let servicesCache = null;
const loadServices = () => (servicesCache = servicesCache || api('GET', '/services').then(r => r.services).catch((e) => { servicesCache = null; throw e; }));

// servicePicker shows the service catalog as ticks grouped by category.
// read() returns the ticked ids (or the starting ones until it has loaded).
function servicePicker(selected, label, collapsed) {
  selected = selected || [];
  const box = h('div', { class: 'services', 'aria-label': label || 'Blocked services' }, h('p', { class: 'muted small' }, 'Loading services…'));
  let loaded = false;
  loadServices().then((all) => {
    const cats = [];
    all.forEach(sv => { if (!cats.includes(sv.category)) cats.push(sv.category); });
    box.replaceChildren(...cats.map(c => h('div', { class: 'mt-s' },
      h('div', { class: 'muted small' }, c),
      h('div', { class: 'perms' }, all.filter(sv => sv.category === c).map(sv => h('label', { class: 'inline', title: sv.domains.join(', ') },
        h('input', { type: 'checkbox', 'data-service': sv.id, checked: selected.includes(sv.id) }), sv.name))))));
    loaded = true;
  }).catch(e => fill(box, h('p', { class: 'muted small' }, "Couldn't load the services: " + e.message)));
  box.read = () => loaded ? [...box.querySelectorAll('[data-service]')].filter(c => c.checked).map(c => c.dataset.service) : selected.slice();
  if (!collapsed) return box;
  // In dialogs: folded away, with a summary of what's ticked.
  const sum = h('summary', {});
  const names = () => {
    const ids = box.read();
    if (!ids.length) return 'None. Choose services';
    const byId = {}; (servicesCache && loaded ? [...box.querySelectorAll('[data-service]')] : []).forEach(c => { byId[c.dataset.service] = c.parentNode.textContent; });
    return ids.map(id => byId[id] || id).join(', ');
  };
  const det = h('details', { class: 'services-pick' }, sum, box);
  const upd = () => { sum.textContent = names(); };
  box.addEventListener('change', upd);
  loadServices().then(() => setTimeout(upd)).catch(() => {});
  upd();
  det.read = box.read;
  return det;
}

function scheduleEditor(sc) {
  const rules = h('textarea', { 'data-f': 'rules', spellcheck: 'false', class: 'short', placeholder: 'youtube.com\ntiktok.com', 'aria-label': 'Domains to block' }, (sc.rules || []).join('\n'));
  const svc = servicePicker(sc.services, 'Services to block during this time', true);
  const rulesBox = h('div', { hidden: sc.block_all }, h('p', { class: 'muted small' }, 'Services to block during this time:'), svc,
    h('p', { class: 'muted small mt-s' }, 'And other domains (subdomains included):'), rules);
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
    services: radios[0].checked ? [] : svc.read(),
  });
  return box;
}

function editGroup(g, named, gs) {
  g = g || { name: '', devices: [], rules: [], schedules: [], skip_blocklists: false };
  const gsvc = servicePicker(g.services, 'Services blocked for this group', true);
  const scheds = h('div', {}, g.schedules.map(scheduleEditor));
  const preset = (sc) => scheds.append(scheduleEditor(sc));
  const dlg = dialog(g.id ? 'Edit group' : 'Add a group', form({}, [
    h('label', { for: 'gname' }, 'Name'),
    h('input', { id: 'gname', name: 'name', type: 'text', value: g.name, required: true, maxlength: 64, placeholder: 'Kids', autofocus: true }),
    h('label', {}, 'Devices'),
    named.length > 8 ? h('input', { type: 'search', placeholder: 'Find a device', 'aria-label': 'Find a device', spellcheck: 'false', oninput: (ev) => {
      ev.target.nextElementSibling.querySelectorAll('label').forEach(l => { l.hidden = fuzzyScore(ev.target.value, l.dataset.k) < 0; });
    } }) : null,
    h('div', { class: 'perms' }, named.map(d => h('label', { class: 'inline', 'data-k': d.name + ' ' + (d.addrs || []).join(' '), title: (d.addrs || []).join(', ') || null },
      h('input', { type: 'checkbox', name: 'dev', value: d.id, checked: g.devices.includes(d.id) }), d.name))),
    h('label', { class: 'inline mt' }, h('input', { type: 'checkbox', name: 'skip', checked: g.skip_blocklists }), 'Skip the household blocklists and custom rules (for example a work laptop)'),
    h('label', { for: 'grules' }, 'Extra rules for this group'),
    h('textarea', { id: 'grules', name: 'rules', spellcheck: 'false', class: 'short', placeholder: '||games.example^\n@@||school.example^' }, g.rules.join('\n')),
    h('p', { class: 'muted small' }, 'Same syntax as custom rules. Allow rules here (', h('code', {}, '@@||site^'), ') beat everything, even schedules.'),
    h('h3', {}, 'Blocked services'),
    h('p', { class: 'muted small' }, 'Blocked all the time for this group, on top of the ones blocked for everyone. Use a schedule below to block them only at some times.'),
    gsvc,
    h('label', { for: 'gsafe' }, 'Safe search'),
    h('select', { id: 'gsafe', name: 'safe' },
      h('option', { value: '', selected: !g.safe_search }, 'Same as the household'),
      h('option', { value: 'on', selected: g.safe_search === 'on' }, 'On for this group'),
      h('option', { value: 'off', selected: g.safe_search === 'off' }, 'Off for this group')),
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
      services: gsvc.read(), safe_search: val(f, 'safe'),
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
  const filter = { client: params.get('client') || '', search: params.get('search') || '', result: params.get('result') || '', range: RANGES[params.get('range')] ? params.get('range') : '24h' };
  const body = h('tbody');
  const more = h('button', { type: 'button', hidden: true }, 'Show older');
  const info = h('p', { class: 'muted small' });
  const nodesNote = h('div');
  let devs = [];
  try { devs = await api('GET', '/devices'); } catch (_) { /* filter still works by IP */ }
  const names = {};
  devs.forEach(d => d.addrs.forEach(a => { names[a] = deviceLabel(d); }));

  const setHash = () => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(filter)) if (v && !(k === 'range' && v === '24h')) q.set(k, v);
    const s = q.toString();
    history.replaceState(null, '', '#/queries' + (s ? '?' + s : ''));
  };
  // useHistory: search each server's saved history (merged), or, when
  // history is off, the recent queries this server holds in memory.
  let oldest = 0, live = true, useHistory = true, multi = false, risk = {};
  const row = (e) => {
    const [label, kind] = RESULTS[e.result] || [e.result, ''];
    const why = e.rule ? e.rule + (e.list ? ' (' + e.list + ')' : '') : '';
    const blocked = e.result === 'blocked';
    return h('tr', {},
      h('td', { class: 'nowrap small', title: fmtTime(e.time) }, new Date(e.time).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })),
      h('td', { class: 'small' }, names[e.client] ? [names[e.client], h('div', { class: 'muted mono' }, e.client)] : h('span', { class: 'mono' }, e.client),
        multi && e.node ? h('div', { class: 'muted' }, 'via ', e.node) : null),
      h('td', {}, can('dashboard.view') && useHistory ? h('button', { class: 'link mono', type: 'button', onclick: () => domainDialog(e.name, filter.range === '1h' ? '24h' : filter.range) }, e.name) : h('span', { class: 'mono' }, e.name),
        ' ', h('span', { class: 'muted small' }, e.type), ' ', riskBadge(risk[e.name]),
        (e.ips || []).length || (e.cnames || []).length ? h('div', { class: 'muted small mono', title: (e.cnames || []).concat(e.ips || []).join('\n') },
          (e.cnames || []).length ? '\u2192 ' + e.cnames[e.cnames.length - 1] + ' ' : '', (e.ips || []).slice(0, 2).join(', '), (e.ips || []).length > 2 ? ' +' + ((e.ips.length) - 2) : '') : null),
      h('td', {}, h('span', { class: 'badge ' + kind, title: why || null }, label, e.allowed ? ' · allowed' : ''),
        why ? h('div', { class: 'muted small' }, why) : null),
      can('domains.allowblock') ? h('td', { class: 'nowrap' }, h('button', { class: 'link', onclick: async (ev) => {
        const action = blocked ? 'allow' : 'block';
        try { await api('POST', '/domains', { domain: e.name, action }); ev.target.replaceWith(h('span', { class: 'small muted' }, blocked ? 'Allowed' : 'Blocked')); }
        catch (err) { toast(err.message, 'err'); }
      } }, blocked ? 'Allow' : 'Block')) : null);
  };
  const qs = (extra) => {
    const u = new URLSearchParams({ limit: '100' });
    for (const [k, v] of Object.entries(filter)) if (v && (useHistory || k !== 'range')) u.set(k, v);
    for (const [k, v] of Object.entries(extra || {})) u.set(k, v);
    return u;
  };
  const q = async (extra) => {
    if (useHistory) {
      const r = await api('GET', '/analytics/queries?' + qs(extra));
      if (r.detail) {
        multi = (r.nodes || []).length > 1;
        r.device_names && Object.entries(r.device_names).forEach(([k, v]) => { if (v && !names[k]) names[k] = v; });
        fill(nodesNote, coverage(r.nodes));
        Object.assign(risk, r.risk || {});
        return r;
      }
      useHistory = false;
      rangeSel.hidden = true;
      if (exportBtn) exportBtn.hidden = true;
    }
    return api('GET', '/queries?' + qs(extra));
  };
  const cursor = (e) => (useHistory ? e.t : e.id);
  const load = async () => {
    let r;
    try { r = await q(); } catch (e) { info.replaceChildren(msg('err', e.message)); return; }
    body.replaceChildren(...r.queries.map(row));
    oldest = r.queries.length ? cursor(r.queries[r.queries.length - 1]) : 0;
    more.hidden = r.queries.length < 100;
    info.textContent = !r.queries.length ? '' : useHistory
      ? 'Newest first, from every server’s saved history.'
      : 'Newest first. Query history is off, so this shows the most recent ' + fmtNum(r.capacity) + ' queries this server has seen since it started.';
    if (!r.queries.length) body.append(h('tr', {}, h('td', { colspan: 5, class: 'muted' }, ['client', 'search', 'result'].some(k => filter[k]) ? 'Nothing matches.' : 'No queries yet.')));
  };
  more.addEventListener('click', async () => {
    live = false;
    try {
      const r = await q({ before: String(oldest) });
      r.queries.forEach(e => body.append(row(e)));
      if (r.queries.length) oldest = cursor(r.queries[r.queries.length - 1]);
      more.hidden = r.queries.length < 100;
      pause.checked = false;
    } catch (e) { toast(e.message, 'err'); }
  });
  const pause = h('input', { type: 'checkbox', checked: true, onchange: (ev) => { live = ev.target.checked; if (live) load(); } });

  const devOpts = deviceOptions(devs, 'All devices');
  if (filter.client && !devOpts.some(o => o.value === filter.client)) devOpts.push({ value: filter.client, label: filter.client });
  const devSel = combo({ label: 'Device', placeholder: 'All devices', options: devOpts, value: filter.client, class: 'dev',
    onchange: (v) => { filter.client = v; setHash(); load(); } });
  let debounce = null;
  const runSearch = (v) => { clearTimeout(debounce); debounce = setTimeout(() => { if (filter.search === v) return; filter.search = v; setHash(); load(); }, 250); };
  const search = combo({ label: 'Search domains', placeholder: 'Search domains', free: true, value: filter.search, options: [], oninput: runSearch, onchange: runSearch });
  // Suggest the domains seen most in the period, so part of a name, or its
  // letters in order, finds them.
  if (can('dashboard.view')) Promise.all(['domains', 'blocked'].map(by => api('GET', '/analytics/top?by=' + by + '&range=' + (filter.range === '1h' ? '24h' : filter.range) + '&limit=200').catch(() => null)))
    .then(rs => {
      const seen = new Set(), opts = [];
      rs.forEach((r, i) => ((r && r.rows) || []).forEach(x => { if (!seen.has(x.key)) { seen.add(x.key); opts.push({ value: x.key, label: x.key, detail: i ? 'blocked' : '' }); } }));
      search.setOptions(opts);
    });
  const resSel = h('select', { name: 'result', 'aria-label': 'Result', onchange: (ev) => { filter.result = ev.target.value; setHash(); load(); } },
    h('option', { value: '' }, 'All results'),
    h('option', { value: 'blocked', selected: filter.result === 'blocked' }, 'Blocked'),
    h('option', { value: 'allowed', selected: filter.result === 'allowed' }, 'Allowed by a rule'),
    h('option', { value: 'cached', selected: filter.result === 'cached' }, 'From cache'),
    h('option', { value: 'failed', selected: filter.result === 'failed' }, 'Failed'));
  const rangeSel = h('select', { name: 'range', 'aria-label': 'Period', onchange: (ev) => { filter.range = ev.target.value; setHash(); load(); } },
    Object.entries(RANGES).map(([k, v]) => h('option', { value: k, selected: filter.range === k }, v)));
  const exportBtn = can('data.export') ? h('button', { type: 'button', onclick: async () => {
    try { await fetchFile('GET', '/analytics/export?' + qs({ limit: '50000' })); } catch (e) { toast(e.message, 'err'); }
  } }, 'Export CSV') : null;

  page(main, 'Query log',
    h('div', { class: 'row' }, devSel, search, resSel, rangeSel, h('label', { class: 'inline' }, pause, 'Live'), exportBtn),
    nodesNote, info,
    h('div', { class: 'card' }, h('div', { class: 'scroll' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'Time'), h('th', {}, 'Device'), h('th', {}, 'Domain'), h('th', {}, 'Result'), can('domains.allowblock') ? h('th', {}) : null)),
      body)), h('div', { class: 'actions' }, more)));
  await load();
  timer = setInterval(() => { if (live && !document.hidden && !document.querySelector('dialog[open]')) load(); }, 3000);
}

// ---------- analytics ----------

const RANGES = { '1h': 'Last hour', '24h': 'Last 24 hours', '7d': 'Last 7 days', '30d': 'Last 30 days', '90d': 'Last 90 days' };

function svg(tag, attrs, ...kids) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v !== null && v !== undefined) el.setAttribute(k, v);
  kids.flat().forEach(k => k && el.append(k));
  return el;
}

// bucketLabel formats a bucket start for the chart's axis and tooltip.
function bucketLabel(t, step, long) {
  const d = new Date(t * 1000);
  if (step >= 86400) return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  if (step >= 3600 && (long || step > 3600)) return d.toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' });
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// queryChart draws allowed and blocked queries per bucket as stacked
// bars, with a tooltip per bar and a table for screen readers.
function queryChart(sum) {
  const step = sum.step;
  const from = Math.floor(new Date(sum.from).getTime() / 1000), to = Math.floor(new Date(sum.to).getTime() / 1000);
  const byT = new Map(sum.series.map(p => [p.t, p]));
  // Fill empty buckets so gaps show as gaps.
  const first = sum.series.length ? Math.min(sum.series[0].t, from - ((from % step) + step) % step) : from;
  const pts = [];
  for (let t = first; t < to; t += step) pts.push(byT.get(t) || { t, total: 0, blocked: 0 });
  if (!pts.length) return null;
  const W = 720, H = 180, padL = 44, padB = 22, padT = 8;
  const maxV = Math.max(1, ...pts.map(p => p.total));
  const nice = (() => { const m = Math.pow(10, Math.floor(Math.log10(maxV))); return Math.ceil(maxV / m) * m; })();
  const y = (v) => padT + (H - padT - padB) * (1 - v / nice);
  const bw = (W - padL) / pts.length;
  const barW = Math.max(1, Math.min(28, bw - 2));
  const tip = h('div', { class: 'chart-tip', hidden: true });
  const g = [];
  [0, 0.5, 1].forEach(f => {
    const v = Math.round(nice * f);
    g.push(svg('line', { x1: padL, x2: W, y1: y(v), y2: y(v), class: 'grid-line' }));
    g.push(svg('text', { x: padL - 6, y: y(v) + 4, 'text-anchor': 'end', class: 'axis' }, document.createTextNode(fmtNum(v))));
  });
  const every = Math.ceil(pts.length / 6);
  pts.forEach((p, i) => {
    const x = padL + i * bw + (bw - barW) / 2;
    const allowed = p.total - p.blocked;
    const r = Math.min(3, barW / 2);
    const yA = y(allowed), yB = y(p.total);
    if (allowed > 0) g.push(svg('rect', { x, y: yA, width: barW, height: Math.max(1, y(0) - yA), rx: r, class: 'bar-allowed' }));
    if (p.blocked > 0) g.push(svg('rect', { x, y: yB, width: barW, height: Math.max(1, yA - yB - (allowed > 0 ? 2 : 0)), rx: r, class: 'bar-blocked' }));
    if (i % every === 0) g.push(svg('text', { x: x + barW / 2, y: H - 6, 'text-anchor': 'middle', class: 'axis' }, document.createTextNode(bucketLabel(p.t, step))));
    const hit = svg('rect', { x: padL + i * bw, y: 0, width: bw, height: H - padB, class: 'hit' });
    const show = () => {
      fill(tip, h('b', {}, bucketLabel(p.t, step, true)), h('div', {}, fmtNum(p.total), ' queries'),
        h('div', {}, h('span', { class: 'key blocked' }), fmtNum(p.blocked), ' blocked', p.total ? ' (' + (100 * p.blocked / p.total).toFixed(1) + '%)' : ''),
        p.total ? h('div', { class: 'muted' }, (p.ms_sum / p.total).toFixed(1), ' ms average') : null);
      tip.hidden = false;
      const left = ((padL + i * bw + bw / 2) / W) * 100;
      tip.style.left = Math.min(80, Math.max(5, left)) + '%';
    };
    hit.addEventListener('mouseenter', show);
    hit.addEventListener('focus', show);
    hit.addEventListener('mouseleave', () => { tip.hidden = true; });
    g.push(hit);
  });
  const chart = svg('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart', role: 'img', 'aria-label': 'Queries over time: allowed and blocked' }, g);
  const table = h('details', { class: 'small' }, h('summary', { class: 'muted' }, 'Show as a table'),
    h('div', { class: 'scroll' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Time'), h('th', {}, 'Queries'), h('th', {}, 'Blocked'))),
      h('tbody', {}, pts.filter(p => p.total).map(p => h('tr', {}, h('td', {}, bucketLabel(p.t, step, true)), h('td', {}, fmtNum(p.total)), h('td', {}, fmtNum(p.blocked))))))));
  return h('div', {},
    h('div', { class: 'legend small' }, h('span', {}, h('span', { class: 'key allowed' }), 'Allowed'), h('span', {}, h('span', { class: 'key blocked' }), 'Blocked')),
    h('div', { class: 'chart-wrap' }, chart, tip), table);
}

// coverage says which servers' history is included.
function coverage(nodes) {
  if (!nodes || nodes.length < 2 && nodes.every(n => n.ok)) return null;
  const missing = nodes.filter(n => !n.ok);
  if (!missing.length) return h('p', { class: 'muted small' }, 'Includes history from ', nodes.map(n => n.name).join(', '), '.');
  return msg('warn', 'Not included: ' + missing.map(n => n.name + ' (' + (n.error || 'no answer') + ')').join(', ') +
    '. Each server keeps its own history, so its queries are missing until it is back.');
}

// domainButton blocks or allows a domain in one click, based on how it is
// treated now, and offers Undo for the owner's own rule.
function domainButton(name, now) {
  if (!can('domains.allowblock')) return null;
  const action = now && now.custom ? 'clear' : (now && now.blocked ? 'allow' : 'block');
  const label = { clear: now && now.blocked ? 'Unblock' : 'Undo allow', allow: 'Allow', block: 'Block' }[action];
  return h('button', { class: 'link', type: 'button', onclick: async (ev) => {
    ev.stopPropagation();
    try {
      await api('POST', '/domains', { domain: name, action });
      ev.target.replaceWith(h('span', { class: 'small muted' }, { clear: 'Rule removed', allow: 'Allowed', block: 'Blocked' }[action]));
    } catch (e) { toast(e.message, 'err'); }
  } }, label);
}

function caughtBy(r) {
  if (!r.list && !r.rule) return null;
  return h('div', { class: 'muted small' }, 'Caught by ', r.rule ? h('code', {}, r.rule) : null, r.list ? [' on ', r.list === 'Custom rules' ? 'your custom rules' : r.list] : null);
}

// bar is a thin meter under a top-list row, scaled to the list's first row.
// riskBadge marks a medium or high risk domain; its title says why.
function riskBadge(r) {
  if (!r || r.score < 40) return null;
  return h('span', { class: 'badge risk-' + r.level, title: (r.reasons || []).join('; ') }, r.level === 'high' ? 'High risk' : 'Risky', ' ', r.score);
}

function typeLine(t) {
  if (!t) return null;
  const other = t.category === 'Other';
  return h('div', { class: 'muted small' }, other && t.company ? t.company : [t.category, t.company ? ' \u00b7 ' + t.company : '']);
}

function bar(part, top, blocked) {
  const s = h('span');
  s.style.width = (top ? Math.max(1, 100 * part / top) : 0) + '%';
  return h('div', { class: 'meter' + (blocked ? ' blocked' : ''), 'aria-hidden': 'true' }, s);
}

async function domainDialog(name, range) {
  const body = h('div', {}, h('p', { class: 'muted' }, 'Loading…'));
  const d = dialog(name, [body, h('div', { class: 'actions' }, h('button', { type: 'button', onclick: () => d.close() }, 'Close'))]);
  d.classList.add('wide');
  let r;
  try { r = await api('GET', '/analytics/domain?' + new URLSearchParams({ name, range })); } catch (e) { fill(body, msg('err', e.message)); return; }
  const c = r.counts || { total: 0, blocked: 0 };
  const now = r.now || {};
  const alsoOn = h('div', {}, h('h3', {}, 'On your lists'), h('p', { class: 'muted small' }, 'Checking your lists\u2026'));
  api('GET', '/analytics/alsoon?' + new URLSearchParams({ name })).then(x => {
    fill(alsoOn, h('h3', {}, 'On your lists'), !x.lists.length ? h('p', { class: 'muted small' }, 'No enabled list has a rule for this domain.')
      : h('ul', { class: 'plain small' }, x.lists.map(l => h('li', {}, l.allowlist ? h('span', { class: 'badge ok' }, 'allow') : h('span', { class: 'badge bad' }, 'block'), ' ', l.list === 'Custom rules' ? 'Your custom rules' : l.list, ' ', h('code', {}, l.rule)))),
      x.partial ? h('p', { class: 'muted small' }, 'Some lists took too long to check.') : null);
  }).catch(e => fill(alsoOn, h('h3', {}, 'On your lists'), msg('err', e.message)));
  const vtBox = h('div', {});
  api('GET', '/virustotal').then(x => {
    if (!x.configured) return;
    const btn = h('button', { type: 'button', onclick: async () => {
      btn.disabled = true;
      try {
        const v = (await api('POST', '/analytics/virustotal?' + new URLSearchParams({ name }))).report;
        const bad = v.malicious + v.suspicious;
        fill(vtBox, h('h3', {}, 'VirusTotal'), !v.found ? h('p', { class: 'muted small' }, 'VirusTotal has no report for this domain.')
          : h('div', { class: 'msg ' + (v.malicious >= 3 ? 'err' : bad ? 'warn' : 'ok') },
            h('b', {}, bad ? fmtNum(v.malicious) + ' engines say malicious' + (v.suspicious ? ', ' + fmtNum(v.suspicious) + ' suspicious' : '') : 'No engine flags this domain'),
            ' (of ', fmtNum(v.malicious + v.suspicious + v.harmless + v.undetected), '). ',
            v.analyzed ? 'Analyzed ' + ago(v.analyzed) + '. ' : '', h('a', { href: v.link, target: '_blank', rel: 'noopener noreferrer' }, 'Full report')));
      } catch (e) { btn.disabled = false; toast(e.message, 'err'); }
    } }, 'Check on VirusTotal');
    fill(vtBox, h('div', { class: 'actions left' }, btn, h('span', { class: 'muted small' }, 'Sends only this domain name to VirusTotal.')));
  }).catch(() => {});
  fill(body,
    h('p', {}, now.allowed ? ['Allowed now', now.rule ? [' by ', h('code', {}, now.rule)] : null, now.list ? [' (', now.custom ? 'your custom rules' : now.list, ')'] : null]
      : now.blocked ? ['Blocked now by ', h('code', {}, now.rule), ' on ', now.custom ? 'your custom rules' : now.list] : 'Not blocked now.', ' ', domainButton(name, now)),
    r.type ? h('p', {}, r.type.category !== 'Other' ? h('span', { class: 'badge' }, r.type.category) : 'Run by', r.type.company ? [r.type.category !== 'Other' ? ' run by ' : ' ', r.type.url ? h('a', { href: r.type.url, target: '_blank', rel: 'noopener noreferrer' }, r.type.company) : r.type.company] : null) : null,
    r.risk && r.risk.score > 0 ? h('div', { class: 'msg ' + (r.risk.score >= 70 ? 'err' : r.risk.score >= 40 ? 'warn' : 'ok') },
      h('b', {}, 'Risk ' + r.risk.score + ' of 100. '), (r.risk.reasons || []).join(' \u00b7 '), ' ',
      can('lists.manage') ? h('button', { class: 'link', type: 'button', onclick: async (ev) => {
        try {
          const cur = (await api('GET', '/settings')).effective.Analytics.TrustedDomains || [];
          await api('PATCH', '/settings', { trusted_domains: cur.concat([name]) });
          ev.target.replaceWith(h('span', { class: 'small' }, 'Trusted. It won\u2019t be marked risky again.'));
        } catch (e) { toast(e.message, 'err'); }
      } }, 'I trust this domain') : null) : null,
    r.caught_by && !now.blocked ? h('p', { class: 'muted small' }, 'Was last blocked by ', h('code', {}, r.caught_by.rule), ' on ', r.caught_by.list, '.') : null,
    h('div', { class: 'grid' },
      h('div', { class: 'tile' }, h('div', { class: 'label' }, RANGES[range]), h('div', { class: 'value' }, fmtNum(c.total))),
      h('div', { class: 'tile' }, h('div', { class: 'label' }, 'Blocked'), h('div', { class: 'value' }, fmtNum(c.blocked)))),
    r.last_seen ? h('p', { class: 'muted small' }, 'First seen ', fmtTime(r.first_seen), ' · last seen ', fmtTime(r.last_seen)) : null,
    c.total ? queryChart(r) : h('p', { class: 'muted' }, 'No queries for this domain in this period.'),
    r.answers && r.answers.length ? [h('h3', {}, 'Recent answers'), h('ul', { class: 'plain small' }, r.answers.map(a => h('li', { class: 'mono' },
      (a.cnames || []).length ? [(a.cnames || []).join(' \u2192 '), ' \u2192 '] : null, (a.ips || []).join(', ') || h('span', { class: 'muted' }, 'no addresses'))))] : null,
    alsoOn,
    vtBox,
    r.devices && r.devices.length ? [h('h3', {}, 'Devices that asked'), h('div', { class: 'scroll' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'Device'), h('th', {}, 'Queries'), h('th', {}, 'Blocked'))),
      h('tbody', {}, r.devices.map(x => h('tr', {},
        h('td', {}, h('a', { href: '#/queries?' + new URLSearchParams({ client: x.device || x.key, search: name }), onclick: () => d.close() }, x.label || x.key)),
        h('td', {}, fmtNum(x.total)), h('td', {}, fmtNum(x.blocked)))))))] : null,
    coverage(r.nodes));
}

async function analyticsPage(main) {
  const params = hashParams();
  const st = { range: RANGES[params.get('range')] ? params.get('range') : '24h', client: params.get('client') || '' };
  const perDevice = can('querylog.view');
  const body = h('div', {}, h('p', { class: 'muted' }, 'Loading…'));
  let devs = [];
  if (perDevice) { try { devs = await api('GET', '/devices'); } catch (_) { /* filter still works by IP */ } }
  const setHash = () => {
    const q = new URLSearchParams();
    if (st.range !== '24h') q.set('range', st.range);
    if (st.client) q.set('client', st.client);
    history.replaceState(null, '', '#/analytics' + (q.toString() ? '?' + q : ''));
  };
  const rangeBtns = h('div', { class: 'seg', role: 'group', 'aria-label': 'Period' }, Object.keys(RANGES).map(k =>
    h('button', { type: 'button', 'aria-pressed': String(k === st.range), onclick: (ev) => {
      st.range = k; rangeBtns.querySelectorAll('button').forEach(b => b.setAttribute('aria-pressed', String(b === ev.target)));
      setHash(); load();
    } }, k)));
  const devSel = perDevice ? combo({ label: 'Device', placeholder: 'All devices', options: deviceOptions(devs, 'All devices'), value: st.client, class: 'dev',
    onchange: (v) => { st.client = v; setHash(); load(); } }) : null;
  page(main, 'Analytics', h('div', { class: 'row' }, rangeBtns, devSel), body);

  const q = (path, extra) => {
    const u = new URLSearchParams({ range: st.range, ...extra });
    if (st.client) u.set('client', st.client);
    return api('GET', '/analytics/' + path + '?' + u);
  };
  const topList = (title, rows, kind) => { const total = rows.length ? rows[0].total : 0; return h('div', { class: 'card' }, h('h2', {}, title),
    !rows.length ? h('p', { class: 'muted' }, 'Nothing yet.') : h('table', { class: 'top' }, h('tbody', {}, rows.map(r => {
      if (kind === 'clients') {
        return h('tr', {}, h('td', {}, h('a', { href: '#/analytics?' + new URLSearchParams({ client: r.device || r.key, range: st.range }) }, r.label || r.addrs[0]),
          r.label ? h('div', { class: 'muted small' }, r.addrs.join(', ')) : null, bar(r.total, total)),
        h('td', { class: 'num' }, fmtNum(r.total), r.blocked ? h('div', { class: 'muted small' }, fmtNum(r.blocked), ' blocked') : null));
      }
      return h('tr', {},
        h('td', {}, h('button', { class: 'link mono', type: 'button', onclick: () => domainDialog(r.key, st.range) }, r.key), ' ', riskBadge(r.risk),
          kind === 'risky' ? h('div', { class: 'small' }, (r.risk.reasons || []).join(' \u00b7 ')) : null,
          kind === 'blocked' ? caughtBy(r) : typeLine(r.type), bar(r.total, total)),
        h('td', { class: 'num' }, fmtNum(r.total)),
        h('td', { class: 'nowrap' }, domainButton(r.key, r.now)));
    })))); };

  const load = async () => {
    let sum, dom, blk, cli, risky, lists;
    try {
      [sum, dom, blk, cli, risky, lists] = await Promise.all([q('summary'), q('top', { by: 'domains', limit: '15' }), q('top', { by: 'blocked', limit: '15' }),
        perDevice && !st.client ? q('top', { by: 'clients', limit: '15' }) : Promise.resolve(null), q('risky', { limit: '10' }), q('top', { by: 'lists', limit: '10' })]);
    } catch (e) { fill(body, msg('err', e.message)); return; }
    const c = sum.counts;
    const pct = (n) => (c.total ? (100 * n / c.total).toFixed(1) + '%' : '—');
    const tile = (label, value, note) => h('div', { class: 'tile' }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, value), note ? h('div', { class: 'muted small' }, note) : null);
    fill(body,
      !sum.stats && !sum.detail ? msg('warn', 'Query history is turned off, so there is nothing to show. ' + (isAdmin() ? 'Turn it on under Settings → Query history.' : 'An admin can turn it on.')) : null,
      coverage(sum.nodes),
      h('div', { class: 'grid' },
        tile('Queries', fmtNum(c.total)),
        tile('Blocked', fmtNum(c.blocked), pct(c.blocked)),
        tile('Answered from cache', pct(c.cached)),
        tile('Average response', c.total ? (c.ms_sum / c.total).toFixed(1) + ' ms' : '—'),
        st.client ? null : tile('Devices', fmtNum(sum.devices)),
        risky.feeds || risky.domains ? tile('Risky domains', fmtNum(risky.domains), risky.domains ? fmtNum(risky.queries) + ' queries' : 'none seen') : null),
      risky.rows.length ? h('div', { class: 'risky' }, topList('Risky domains', risky.rows, 'risky'),
        h('p', { class: 'muted small' }, 'Scored from malware and phishing feeds and how the name looks. Scores never block anything; use Block, or add the feeds as blocklists. ',
          risky.domains > risky.rows.length ? 'Showing the ' + risky.rows.length + ' riskiest of ' + fmtNum(risky.domains) + '.' : '')) : null,
      h('div', { class: 'card' }, h('h2', {}, 'Queries over time'), c.total ? queryChart(sum) : h('p', { class: 'muted' }, 'No queries in this period.')),
      (sum.nodes || []).length > 1 ? serversCard(sum, {}) : null,
      h('div', { class: 'cols' }, topList('Top domains', dom.rows, 'domains'), topList('Top blocked', blk.rows, 'blocked')),
      h('div', { class: 'cols' }, cli ? topList('Busiest devices', cli.rows, 'clients') : null, topListsCard(lists.rows, st.range, false)),
      perDevice && st.client ? h('p', {}, h('a', { href: '#/queries?client=' + encodeURIComponent(st.client) }, 'See every query from this device')) : null);
  };
  await load();
  timer = setInterval(() => { if (!document.hidden && !document.querySelector('dialog[open]')) load(); }, 30000);
}

// dashboardChart is the dashboard's queries-over-time card.
async function dashboardChart(box, range) {
  range = range || '24h';
  let sum;
  try { sum = await api('GET', '/analytics/summary?range=' + range); } catch (_) { return; }
  if (!sum.counts || !sum.counts.total) { box.replaceChildren(); return; }
  box.replaceChildren(h('div', { class: 'card d-chart' },
    h('div', { class: 'row spread' }, h('h2', {}, RANGES[range]), h('a', { href: '#/analytics' + (range === '24h' ? '' : '?range=' + range), class: 'small' }, 'Analytics')),
    h('p', { class: 'muted small' }, fmtNum(sum.counts.total), ' queries, ', fmtNum(sum.counts.blocked), ' blocked, from ', fmtNum(sum.devices), sum.devices === 1 ? ' device.' : ' devices.'),
    queryChart(sum)));
}

// ---------- performance ----------

// upstreamLabel names an upstream server the way people know it.
function upstreamLabel(u) {
  return /^udp:\/\/127\.0\.0\.1:/.test(u) ? 'Unbound (built in)' : u.replace(/^https:\/\/([^/]+).*/, '$1 (HTTPS)').replace(/^tls:\/\/([^:]+).*/, '$1 (TLS)');
}

function fmtMs(ms) {
  if (ms === null || ms === undefined || !isFinite(ms)) return '—';
  if (ms >= 1000) return (ms / 1000).toFixed(1) + ' s';
  if (ms >= 10) return ms.toFixed(0) + ' ms';
  if (ms >= 1) return ms.toFixed(1) + ' ms';
  return ms.toFixed(2) + ' ms';
}

function fmtPct(f) { return f > 0 && f < 0.001 ? '<0.1%' : (100 * (f || 0)).toFixed(1) + '%'; }

// usualNote compares a value with what is usual: "usually 12 ms".
function usualNote(cur, usual, fmt, worseIfHigher) {
  if (usual === null || usual === undefined || !isFinite(usual)) return null;
  let cls = 'muted';
  if (usual > 0) {
    const r = cur / usual;
    if (worseIfHigher ? r > 1.5 : r < 0.67) cls = 'worse';
    else if (worseIfHigher ? r < 0.8 : r > 1.2) cls = 'better';
  }
  return h('span', { class: cls }, 'usually ', fmt(usual));
}

// niceMax rounds a chart's top value up to 1, 2 or 5 × 10ⁿ steps and
// returns the top and the step between grid lines.
function niceMax(v, lines) {
  const raw = Math.max(v, 1e-6) / lines;
  const p = Math.pow(10, Math.floor(Math.log10(raw)));
  const step = [1, 2, 2.5, 5, 10].map(m => m * p).find(s => s >= raw);
  return { top: step * Math.ceil(v / step - 1e-9) || step, step };
}

// latencyChart draws response times over time in two panels that share a
// time axis, each on its own linear scale from zero: upstream lookups on
// top (milliseconds) and all answers below (mostly from cache, fractions
// of a millisecond). A shared log scale made 10 ms and 100 ms look close
// together, so each panel's height now means the same thing everywhere.
// The time axis starts where the history starts, not at an empty start
// of the period. Unusual buckets are shaded in both panels.
function latencyChart(view, step, from, to, anomalies) {
  const byT = new Map(view.series.map(p => [p.t, p]));
  const align = (t) => t - ((t % step) + step) % step;
  // Start at the first bucket with queries if that is later than the
  // period's start, so a new server doesn't show mostly empty space.
  const withData = view.series.filter(p => p.queries > 0);
  if (!withData.length) return null;
  const trimmed = withData[0].t > align(from);
  const pts = [];
  for (let t = withData[0].t; t < to; t += step) pts.push(byT.get(t) || { t, queries: 0, lookups: 0 });
  if (!pts.length) return null;

  const panels = [
    { title: 'Lookups (not in cache, asked upstream)', count: 'lookups', series: [
      { key: 'lookup_avg_ms', label: 'Average', cls: 's1' },
      { key: 'lookup_p95_ms', label: '95th percentile', cls: 's2' }] },
    { title: 'All answers (most come from cache)', count: 'queries', series: [
      { key: 'p50_ms', label: 'Median', cls: 's3' }] },
  ];
  const W = 720, padL = 56, padR = 8, axisH = 22, gap = 30, titleH = 18;
  const heights = [150, 70];
  let yOff = 0;
  const g = [];
  const idx = new Map(pts.map((p, i) => [p.t, i]));
  const bw = (W - padL - padR) / pts.length;
  const xc = (i) => padL + i * bw + bw / 2;
  panels.forEach((pn, pi) => {
    const top = yOff + titleH, ph = heights[pi], bottom = top + ph;
    pn.top = top; pn.bottom = bottom;
    const vals = [];
    pts.forEach(p => { if (p[pn.count] >= 1) pn.series.forEach(s => { if (p[s.key] > 0) vals.push(p[s.key]); }); });
    g.push(svg('text', { x: padL, y: yOff + 12, class: 'axis panel-title' }, document.createTextNode(pn.title)));
    if (!vals.length) {
      g.push(svg('text', { x: padL + (W - padL) / 2, y: top + ph / 2, 'text-anchor': 'middle', class: 'axis' }, document.createTextNode(pn.count === 'lookups' ? 'No lookups in this period' : 'No queries in this period')));
      yOff = bottom + gap;
      return;
    }
    const { top: max, step: tick } = niceMax(Math.max(...vals), pi === 0 ? 4 : 2);
    const y = (v) => bottom - ph * Math.min(v, max) / max;
    (anomalies || []).forEach(a => {
      const i0 = idx.get(a.t), i1 = idx.get(a.end);
      if (i0 === undefined) return;
      g.push(svg('rect', { x: padL + i0 * bw, y: top, width: ((i1 === undefined ? i0 : i1) - i0 + 1) * bw, height: ph, class: 'anom ' + a.severity }));
    });
    for (let v = 0; v <= max + tick / 1e6; v += tick) {
      g.push(svg('line', { x1: padL, x2: W - padR, y1: y(v), y2: y(v), class: 'grid-line' + (v === 0 ? ' base' : '') }));
      g.push(svg('text', { x: padL - 6, y: y(v) + 4, 'text-anchor': 'end', class: 'axis' }, document.createTextNode(v === 0 ? '0' : fmtMs(v))));
    }
    pn.series.forEach(s => {
      const ok = (p) => p[s.key] > 0 && p[pn.count] >= 1;
      let d = '', pen = false;
      pts.forEach((p, i) => {
        if (!ok(p)) { pen = false; return; }
        d += (pen ? 'L' : 'M') + xc(i).toFixed(1) + ' ' + y(p[s.key]).toFixed(1);
        pen = true;
      });
      if (d) g.push(svg('path', { d, class: 'line ' + s.cls }));
      // Lone points (gaps on both sides) as dots, so they show.
      pts.forEach((p, i) => {
        const has = (j) => j >= 0 && j < pts.length && ok(pts[j]);
        if (ok(p) && !has(i - 1) && !has(i + 1)) g.push(svg('circle', { cx: xc(i), cy: y(p[s.key]), r: 2.5, class: 'dot-' + s.cls }));
      });
    });
    yOff = bottom + gap;
  });
  const H = panels[1].bottom + axisH;
  const every = Math.ceil(pts.length / 6);
  const tip = h('div', { class: 'chart-tip', hidden: true });
  pts.forEach((p, i) => {
    if (i % every === 0) g.push(svg('text', { x: xc(i), y: H - 6, 'text-anchor': 'middle', class: 'axis' }, document.createTextNode(bucketLabel(p.t, step))));
    const hit = svg('rect', { x: padL + i * bw, y: 0, width: bw, height: H - axisH, class: 'hit' });
    const show = () => {
      fill(tip, h('b', {}, bucketLabel(p.t, step, true)),
        p.queries ? [h('div', {}, fmtNum(p.queries), ' queries, median ', fmtMs(p.p50_ms), ', 95% under ', fmtMs(p.p95_ms)),
          p.lookups ? h('div', {}, fmtNum(p.lookups), ' lookups: ', fmtMs(p.lookup_avg_ms), ' average, 95% under ', fmtMs(p.lookup_p95_ms)) : null,
          h('div', { class: 'muted' }, fmtPct(p.cache_hit), ' from cache', p.failed ? ', ' + fmtNum(p.failed) + ' failed' : '')]
          : h('div', { class: 'muted' }, 'No queries'));
      tip.hidden = false;
      tip.style.left = Math.min(80, Math.max(12, (xc(i) / W) * 100)) + '%';
    };
    hit.addEventListener('mouseenter', show);
    hit.addEventListener('mouseleave', () => { tip.hidden = true; });
    g.push(hit);
  });
  const chart = svg('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart', role: 'img', 'aria-label': 'Response times over time: lookups and all answers, each on its own scale' }, g);
  const table = h('details', { class: 'small' }, h('summary', { class: 'muted' }, 'Show as a table'),
    h('div', { class: 'scroll' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Time'), h('th', {}, 'Queries'), h('th', {}, 'Median'), h('th', {}, '95%'), h('th', {}, '99%'), h('th', {}, 'Lookups'), h('th', {}, 'Lookup avg'), h('th', {}, 'Lookup 95%'), h('th', {}, 'From cache'), h('th', {}, 'Failed'))),
      h('tbody', {}, pts.filter(p => p.queries).map(p => h('tr', {}, h('td', {}, bucketLabel(p.t, step, true)), h('td', {}, fmtNum(p.queries)), h('td', {}, fmtMs(p.p50_ms)), h('td', {}, fmtMs(p.p95_ms)), h('td', {}, fmtMs(p.p99_ms)),
        h('td', {}, fmtNum(p.lookups)), h('td', {}, p.lookups ? fmtMs(p.lookup_avg_ms) : '—'), h('td', {}, p.lookups ? fmtMs(p.lookup_p95_ms) : '—'), h('td', {}, fmtPct(p.cache_hit)), h('td', {}, fmtNum(p.failed))))))));
  // One plain sentence on the gap the two scales hide: how much longer a
  // lookup takes than a typical answer.
  const s = view.summary;
  const ratio = s.lookups && s.p50_ms > 0 ? s.lookup_avg_ms / s.p50_ms : 0;
  const story = s.lookups ? h('p', { class: 'small story' },
    h('b', {}, fmtPct(s.cache_hit)), ' answered from cache, typically in ', h('b', {}, fmtMs(s.p50_ms)), '. ',
    'The rest were looked up upstream, averaging ', h('b', {}, fmtMs(s.lookup_avg_ms)),
    ratio >= 2 ? [' (about ', h('b', {}, ratio >= 10 ? fmtNum(Math.round(ratio / 10) * 10) : Math.round(ratio), '×'), ' longer)'] : null,
    ', and 95% of them took under ', h('b', {}, fmtMs(s.lookup_p95_ms)), '.') : null;
  return h('div', {}, story,
    h('div', { class: 'legend small' }, panels.flatMap(pn => pn.series).map(s => h('span', {}, h('span', { class: 'key ' + s.cls }), s.label === 'Median' ? 'Median, all answers' : 'Lookups, ' + s.label.toLowerCase())),
      (anomalies || []).length ? h('span', {}, h('span', { class: 'key anom' }), 'Unusual') : null),
    h('div', { class: 'chart-wrap' }, chart, tip),
    trimmed ? h('p', { class: 'muted small' }, 'No queries recorded before ', bucketLabel(pts[0].t, step, true), ', so the chart starts there.') : null,
    table);
}

// distChart shows how many queries took how long.
function distChart(dist) {
  const rows = dist.map((d, i) => ({ ...d, lo: i ? dist[i - 1].le : 0 }));
  const total = rows.reduce((a, r) => a + r.all, 0);
  if (!total) return null;
  // Trim empty buckets at both ends.
  let a = 0, b = rows.length - 1;
  while (a < b && !rows[a].all) a++;
  while (b > a && !rows[b].all) b--;
  const shown = rows.slice(a, b + 1);
  const top = Math.max(...shown.map(r => r.all));
  const label = (r) => r.le ? (r.lo ? fmtMs(r.lo) + '–' : 'under ') + fmtMs(r.le) : 'over ' + fmtMs(r.lo);
  let cum = 0;
  shown.forEach(r => { cum += r.all; r.cum = cum; });
  return h('div', { class: 'scroll' }, h('table', { class: 'top dist' }, h('thead', {}, h('tr', {}, h('th', {}, 'Time'), h('th', { class: 'num' }, 'Queries'), h('th', { class: 'num' }, 'Of which lookups'), h('th', { class: 'num' }, 'Answered by now'))),
    h('tbody', {}, shown.filter(r => r.all).map(r => h('tr', {}, h('td', { class: 'nowrap' }, label(r), bar(r.all, top)), h('td', { class: 'num' }, fmtNum(r.all)), h('td', { class: 'num' }, fmtNum(r.lookups)), h('td', { class: 'num' }, fmtPct(r.cum / total)))))));
}

async function performancePage(main) {
  const params = hashParams();
  const st = { range: RANGES[params.get('range')] ? params.get('range') : '24h' };
  const body = h('div', {}, h('p', { class: 'muted' }, 'Loading…'));
  const rangeBtns = h('div', { class: 'seg', role: 'group', 'aria-label': 'Period' }, Object.keys(RANGES).map(k =>
    h('button', { type: 'button', 'aria-pressed': String(k === st.range), onclick: (ev) => {
      st.range = k; rangeBtns.querySelectorAll('button').forEach(b => b.setAttribute('aria-pressed', String(b === ev.target)));
      history.replaceState(null, '', '#/performance' + (k !== '24h' ? '?range=' + k : ''));
      load();
    } }, k)));
  const clearBtn = clearHistoryButton('performance', 'Clear performance stats',
    'Clear performance stats on every server? Response times, upstream timings and the warnings based on them start again from now. The query history is kept, and so are the slowest domains and device tables, which come from it.', () => load());
  page(main, 'Performance', h('p', { class: 'muted' }, 'How quickly DNServ answers, how your upstream servers are doing, and anything out of the ordinary.'), h('div', { class: 'row spread' }, rangeBtns, clearBtn), body);

  const load = async () => {
    let r;
    try { r = await api('GET', '/analytics/performance?' + new URLSearchParams({ range: st.range })); } catch (e) { fill(body, msg('err', e.message)); return; }
    // Only compare tiles with the week before, not with this period itself.
    const v = r.view, s = v.summary, u = v.usual_from === 'before' ? v.usual : null;
    const from = Math.floor(new Date(r.from).getTime() / 1000), to = Math.floor(new Date(r.to).getTime() / 1000);
    const tile = (label, value, note, title) => h('div', { class: 'tile', title }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, value), note ? h('div', { class: 'small' }, note) : null);
    const multiNode = (r.nodes || []).length > 1;
    const usualWhat = v.usual_from === 'before' ? 'Compared with the 7 days before.' : v.usual_from === 'period' ? 'Compared with a typical ' + (r.step >= 86400 ? 'day' : r.step >= 3600 ? (r.step > 3600 ? r.step / 3600 + ' hours' : 'hour') : (r.step / 60) + ' minutes') + ' in this period.' : 'Not enough history yet to say what is usual.';
    fill(body,
      !r.stats && !r.detail ? msg('warn', 'Query history is turned off, so there is nothing to show. ' + (isAdmin() ? 'Turn it on under Settings → Query history.' : 'An admin can turn it on.')) : null,
      coverage(r.nodes),
      v.anomalies.length ? h('div', { class: 'card' }, h('h2', {}, 'Unusual ', h('span', { class: 'muted small' }, v.anomalies.length === 1 ? '1 thing' : v.anomalies.length + ' things')),
        h('ul', { class: 'plain anomalies' }, v.anomalies.slice(0, 20).map(a => h('li', {},
          h('span', { class: 'badge ' + (a.severity === 'bad' ? 'bad' : 'warn') }, a.title), ' ',
          h('span', { class: 'muted small' }, bucketLabel(a.t, r.step, true), a.end !== a.t ? ' – ' + bucketLabel(a.end + r.step, r.step, true) : ''),
          a.server ? h('span', { class: 'small' }, ' · ', upstreamLabel(a.server)) : null,
          multiNode && a.node ? h('span', { class: 'muted small' }, ' · from ', a.node) : null,
          h('div', { class: 'small' }, a.detail)))),
        v.anomalies.length > 20 ? h('p', { class: 'muted small' }, 'And ', v.anomalies.length - 20, ' more.') : null)
        : s.queries ? msg('ok', 'Nothing unusual in this period. ' + usualWhat) : null,
      h('div', { class: 'grid' },
        tile('Median response', fmtMs(s.p50_ms), u ? usualNote(s.p50_ms, u.p50_ms, fmtMs, true) : null, 'Half of all queries were answered faster than this.'),
        tile('95% answered within', fmtMs(s.p95_ms), u ? usualNote(s.p95_ms, u.p95_ms, fmtMs, true) : null, '1 in 20 queries took longer than this.'),
        tile('Average response', fmtMs(s.avg_ms), [fmtNum(s.queries), ' queries'], 'Includes cached and blocked answers.'),
        tile('Lookups (not cached)', s.lookups ? fmtMs(s.lookup_avg_ms) : '—', s.lookups ? ['95% within ', fmtMs(s.lookup_p95_ms), u && u.lookups ? [' · ', usualNote(s.lookup_p95_ms, u.lookup_p95_ms, fmtMs, true)] : null] : 'none', 'Queries DNServ had to ask an upstream server about.'),
        tile('Answered from cache', fmtPct(s.cache_hit), u ? usualNote(s.cache_hit, u.cache_hit, fmtPct, false) : null, 'Of the queries that weren’t blocked or local names.'),
        tile('Failed (SERVFAIL)', fmtNum(s.failed), [fmtPct(s.fail_rate), u ? [' · ', usualNote(s.fail_rate, u.fail_rate, fmtPct, true)] : null])),
      h('div', { class: 'card' }, h('h2', {}, 'Response times'), s.queries ? latencyChart(v, r.step, from, to, v.anomalies.filter(a => !a.server)) : h('p', { class: 'muted' }, 'No queries in this period.'),
        s.queries ? h('p', { class: 'muted small' }, 'Times are measured inside DNServ, from receiving a query to having the answer ready. ', usualWhat) : null),
      h('div', { class: 'card' }, h('h2', {}, 'Upstream servers'),
        !v.upstreams.length ? h('p', { class: 'muted' }, 'No upstream lookups in this period.') : h('div', { class: 'scroll' }, h('table', {},
          h('thead', {}, h('tr', {}, multiNode ? h('th', {}, 'Server') : null, h('th', {}, 'Upstream'), h('th', { class: 'num' }, 'Tries'), h('th', { class: 'num' }, 'Average'), h('th', { class: 'num' }, 'Median'), h('th', { class: 'num' }, '95%'), h('th', { class: 'num' }, 'Slowest'), h('th', { class: 'num' }, 'Timeouts'), h('th', { class: 'num' }, 'Errors'))),
          h('tbody', {}, v.upstreams.map(x => h('tr', {},
            multiNode ? h('td', {}, x.node) : null,
            h('td', { title: x.server }, upstreamLabel(x.server), x.servfail ? h('div', { class: 'muted small' }, fmtNum(x.servfail), ' SERVFAIL answers') : null),
            h('td', { class: 'num' }, fmtNum(x.tries)),
            h('td', { class: 'num' }, x.answered ? fmtMs(x.avg_ms) : '—', x.usual_avg_ms ? h('div', { class: 'small' }, usualNote(x.avg_ms, x.usual_avg_ms, fmtMs, true)) : null),
            h('td', { class: 'num' }, x.answered ? fmtMs(x.p50_ms) : '—'),
            h('td', { class: 'num' }, x.answered ? fmtMs(x.p95_ms) : '—'),
            h('td', { class: 'num' }, x.answered ? fmtMs(x.max_ms) : '—'),
            h('td', { class: 'num' + (x.timeouts ? ' worse' : '') }, fmtNum(x.timeouts)),
            h('td', { class: 'num' + (x.errors ? ' worse' : '') }, fmtNum(x.errors))))))),
        v.upstreams.length ? h('p', { class: 'muted small' }, 'Each server measures its own path to the upstream. Prefetches of popular names count here too.') : null),
      h('div', { class: 'cols' },
        h('div', { class: 'card' }, h('h2', {}, 'How long queries took'), distChart(v.dist) || h('p', { class: 'muted' }, 'No queries in this period.')),
        h('div', { class: 'card' }, h('h2', {}, 'By record type'), !v.types.length ? h('p', { class: 'muted' }, 'No queries in this period.') : h('table', { class: 'top' },
          h('thead', {}, h('tr', {}, h('th', {}, 'Type'), h('th', { class: 'num' }, 'Queries'), h('th', { class: 'num' }, 'Average'), h('th', { class: 'num' }, '95%'))),
          h('tbody', {}, v.types.slice(0, 12).map(t => h('tr', {}, h('td', { class: 'mono' }, t.type), h('td', { class: 'num' }, fmtNum(t.queries)), h('td', { class: 'num' }, fmtMs(t.avg_ms)), h('td', { class: 'num' }, fmtMs(t.p95_ms)))))))),
      h('div', { class: 'cols' },
        h('div', { class: 'card' }, h('h2', {}, 'Slowest domains to look up'), !r.domains.length ? h('p', { class: 'muted' }, r.stats ? 'Nothing yet.' : 'Needs hourly history (Settings → Query history).') : h('table', { class: 'top' },
          h('thead', {}, h('tr', {}, h('th', {}, 'Domain'), h('th', { class: 'num' }, 'Average'), h('th', { class: 'num' }, 'Lookups'))),
          h('tbody', {}, r.domains.map(d => h('tr', {}, h('td', {}, h('button', { class: 'link mono', type: 'button', onclick: () => domainDialog(d.key, st.range) }, d.key)),
            h('td', { class: 'num' }, fmtMs(d.lookup_avg_ms)), h('td', { class: 'num' }, fmtNum(d.lookups)))))),
          r.domains.length ? h('p', { class: 'muted small' }, 'Average time to look up each domain when it wasn’t cached (3 lookups or more). Slow ones are often far away or have slow name servers.') : null),
        r.devices ? h('div', { class: 'card' }, h('h2', {}, 'Devices'), !r.devices.length ? h('p', { class: 'muted' }, 'Nothing yet.') : h('div', { class: 'scroll' }, h('table', { class: 'top' },
          h('thead', {}, h('tr', {}, h('th', {}, 'Device'), h('th', { class: 'num' }, 'Queries'), h('th', { class: 'num' }, 'From cache'), h('th', { class: 'num' }, 'Lookup avg'), h('th', { class: 'num' }, 'Failed'))),
          h('tbody', {}, r.devices.slice(0, 20).map(d => h('tr', {},
            h('td', {}, h('a', { href: '#/analytics?' + new URLSearchParams({ client: d.device || d.addrs[0], range: st.range }) }, d.label || d.addrs[0]), d.label ? h('div', { class: 'muted small' }, d.addrs.join(', ')) : null),
            h('td', { class: 'num' }, fmtNum(d.queries)), h('td', { class: 'num' }, fmtPct(d.cache_hit)), h('td', { class: 'num' }, d.lookups ? fmtMs(d.lookup_avg_ms) : '—'),
            h('td', { class: 'num' + (d.failed ? ' worse' : '') }, fmtNum(d.failed))))))),
          h('p', { class: 'muted small' }, 'A device with few cache hits is asking for many different names, which makes its browsing feel slower.')) : null));
  };
  await load();
  timer = setInterval(() => { if (!document.hidden && !document.querySelector('dialog[open]')) load(); }, 30000);
}

// listLabel names where a block came from.
function listLabel(k) { return k === 'Custom rules' ? 'Your custom rules' : k || 'Other (device group rules)'; }

// topListsCard shows which lists blocked the most.
function topListsCard(rows, range, link) {
  if (!rows || !rows.length) return null;
  const total = rows.reduce((a, r) => a + r.total, 0);
  return h('div', { class: 'card d-top' },
    h('div', { class: 'row spread' }, h('h2', {}, 'Top blocking lists'), link ? h('a', { href: '#/analytics', class: 'small' }, 'Analytics') : null),
    h('table', { class: 'top' }, h('tbody', {}, rows.map(r => h('tr', {},
      h('td', {}, listLabel(r.key), bar(r.total, rows[0].total)),
      h('td', { class: 'num' }, fmtNum(r.total), h('div', { class: 'muted small' }, fmtPct(r.total / total))))))),
    h('p', { class: 'muted small' }, RANGES[range], '. Each block counts for the list whose rule matched first.'));
}

// dashboardExtras adds the last hour's response times and the top
// blocking lists to the dashboard.
async function dashboardExtras(box, range) {
  range = range || '24h';
  const [perf, lists, doms, blk] = await Promise.all([
    api('GET', '/analytics/performance?range=1h').catch(() => null),
    api('GET', '/analytics/top?by=lists&range=' + range + '&limit=6').catch(() => null),
    api('GET', '/analytics/top?by=domains&range=' + range + '&limit=6').catch(() => null),
    api('GET', '/analytics/top?by=blocked&range=' + range + '&limit=6').catch(() => null)]);
  const cards = [];
  // Top domains and top blocked side by side, as AdGuard Home and NextDNS
  // show them; a name opens the same domain details as on Analytics.
  const topCard = (cls, title, rows, blocked) => (rows && rows.length ? h('div', { class: 'card ' + cls },
    h('div', { class: 'row spread' }, h('h2', {}, title), h('a', { href: '#/analytics' + (range === '24h' ? '' : '?range=' + range), class: 'small' }, 'More')),
    h('table', { class: 'top' }, h('tbody', {}, rows.map(r => h('tr', {},
      h('td', {}, h('button', { class: 'link mono', type: 'button', onclick: () => domainDialog(r.key, range) }, r.key), ' ', riskBadge(r.risk),
        blocked && r.list ? h('div', { class: 'muted small' }, listLabel(r.list)) : null, bar(r.total, rows[0].total, blocked)),
      h('td', { class: 'num' }, fmtNum(r.total))))))) : null);
  const dc = topCard('d-domains', 'Top domains', doms && doms.rows, false);
  const bc = topCard('d-blocked', 'Top blocked', blk && blk.rows, true);
  if (dc) cards.push(dc);
  if (bc) cards.push(bc);
  if (perf && perf.view.summary.queries) {
    const s = perf.view.summary, an = perf.view.anomalies;
    const stat = (label, value) => h('div', {}, h('div', { class: 'muted small' }, label), h('div', { class: 'big' }, value));
    cards.push(h('div', { class: 'card d-perf' },
      h('div', { class: 'row spread' }, h('h2', {}, 'Response times, last hour'), h('a', { href: '#/performance', class: 'small' }, 'Performance')),
      h('div', { class: 'stats' }, stat('Median', fmtMs(s.p50_ms)), stat('95% within', fmtMs(s.p95_ms)), stat('Lookups, average', s.lookups ? fmtMs(s.lookup_avg_ms) : '—'), stat('From cache', fmtPct(s.cache_hit))),
      an.length ? h('div', { class: 'msg ' + (an.some(a => a.severity === 'bad') ? 'err' : 'warn') }, h('b', {}, an[0].title), ' ', an[0].detail, an.length > 1 ? [' ', h('a', { href: '#/performance?range=1h' }, '+', an.length - 1, ' more')] : null)
        : h('p', { class: 'muted small' }, 'Nothing unusual.')));
  }
  const lc = lists ? topListsCard(lists.rows, range, true) : null;
  if (lc) cards.push(lc);
  box.replaceChildren(cards.length > 1 ? h('div', { class: 'cols' }, cards) : cards);
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

  if (isAdmin()) {
    sections.push(h('div', { class: 'card' }, h('div', { class: 'row spread' },
      h('div', {}, h('h2', { class: 'm0' }, 'Moving from AdGuard Home?'),
        h('p', { class: 'muted small m0' }, 'Bring across its blocklists, rules, DNS rewrites, devices and upstream servers.')),
      h('a', { href: '#/import' }, 'Import from AdGuard Home'))));
  }

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
    const strategies = {
      fastest: 'Fastest: ask the quickest server, the others if it fails (recommended)',
      in_order: 'In order: the first server, the others only if it fails',
      round_robin: 'Round robin: take turns, spreading the load evenly',
      parallel: 'All at once: ask every server, use the first answer (more traffic)',
    };
    const strategy = h('select', { id: 'strategy', name: 'strategy' }, Object.entries(strategies).map(([k, t]) => h('option', { value: k, selected: (u.Strategy || 'fastest') === k }, t)));
    const fwd = h('div', { class: 'indent', hidden: u.Mode === 'recursive' },
      h('label', { for: 'provider' }, u.Mode === 'tunnel' ? 'Resolver (used only while the VPN is down)' : 'Resolver'), picker, custom,
      h('label', { for: 'strategy' }, 'With more than one server'), strategy,
      h('p', { class: 'muted small' }, 'A server that fails or times out is skipped for 30 seconds, whichever you pick.'));
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
      h('h2', {}, 'Privacy ', origin('upstream_mode', 'upstream_servers', 'upstream_strategy', 'tunnel_interface', 'tunnel_expected_egress', 'tunnel_on_down')),
      h('p', { class: 'muted' }, 'How DNServ looks up the domains it doesn\u2019t block.'),
      form({ 'data-track': true }, [
        h('div', { class: 'choices' }, ['forward', 'recursive', 'tunnel'].map(modeChoice)),
        fwd, tunnelOpts,
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save')),
      ], (f) => save({
        upstream_mode: f.querySelector('input[name=mode]:checked').value, upstream_servers: lines(servers.value), upstream_strategy: val(f, 'strategy'),
        tunnel_interface: val(f, 'tif').trim(), tunnel_expected_egress: lines(val(f, 'egress')), tunnel_on_down: val(f, 'ondown'),
      }, {
        upstream_mode: u.Mode, upstream_servers: norm(u.Servers), upstream_strategy: u.Strategy || 'fastest',
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
        h('label', { class: 'inline' }, h('input', { type: 'checkbox', name: 'bypass', checked: fl.BlockBypass }), "Don't let devices skip DNServ (blocks apps' own encrypted DNS and iCloud Private Relay)"),
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

  if (can('lists.manage')) {
    const fl = eff.Filtering;
    const svc = servicePicker(fl.BlockedServices);
    sections.push(h('div', { class: 'card' },
      h('h2', {}, 'Blocked services and safe search ', origin('blocked_services', 'safe_search')),
      form({ 'data-track': true }, [
        h('label', { class: 'inline' }, h('input', { type: 'checkbox', name: 'safe', checked: fl.SafeSearch }),
          'Safe search: Google, Bing and DuckDuckGo only show safe results, and YouTube uses Restricted Mode'),
        h('h3', {}, 'Blocked for everyone'),
        h('p', { class: 'muted small' }, 'Each one blocks the app and its website. To block a service for some devices only, or at some times, use a group on the Devices page. An allow rule of your own still wins.'),
        svc,
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save')),
      ], (f) => save({ safe_search: f.elements.safe.checked, blocked_services: svc.read() },
        { safe_search: fl.SafeSearch, blocked_services: norm(fl.BlockedServices) }))));
  }

  if (can('rules.edit')) {
    sections.push(h('div', { class: 'card' },
      h('h2', {}, 'Custom rules ', origin('rules')),
      form({ 'data-track': true }, [
        h('textarea', { name: 'rules', spellcheck: 'false', 'aria-label': 'Custom rules', class: 'tall' }, (eff.Filtering.Rules || []).join('\n')),
        h('p', { class: 'muted small' }, h('code', {}, '||ads.example.com^'), ' blocks a domain and its subdomains · ', h('code', {}, '@@||cdn.example.com^'), ' always allows · ',
          h('code', {}, '*.tracker.example'), ' subdomains only · ', h('code', {}, 'exact.example.com'), ' just that name · ',
          h('code', {}, '||ad-*.example.com^'), ' wildcards · ', h('code', {}, '/^ads[0-9]+\\./'), ' regex. Custom rules beat every list.'),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save')),
      ], (f) => save({ rules: lines(val(f, 'rules')).filter(l => !l.startsWith('#') && !l.startsWith('!')) }, { rules: norm(eff.Filtering.Rules) }))));
  }

  if (can('network.manage')) {
    sections.push(h('div', { class: 'card' },
      h('h2', {}, 'Device names ', origin('local_dns')),
      form({ 'data-track': true }, [
        h('p', { class: 'muted' }, 'DNServ can ask your router what each device is called, and sends lookups for local names (like printer.lan) to it.'),
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

  if (can('lists.manage')) {
    const ac = eff.Analytics;
    let intel = { sources: [] };
    try { intel = await api('GET', '/analytics/intel'); } catch (_) { /* status unknown */ }
    sections.push(h('div', { class: 'card' },
      h('h2', {}, 'Risk scoring ', origin('threat_feeds', 'trusted_domains')),
      form({ 'data-track': true }, [
        h('p', { class: 'muted' }, 'Analytics marks risky domains using public malware and phishing feeds and how a name looks. It never blocks on its own.'),
        h('label', { class: 'inline' }, h('input', { type: 'checkbox', name: 'feeds', checked: ac.ThreatFeeds }), 'Download threat feeds (about 30 MB of memory)'),
        h('label', { for: 'trusted' }, 'Trusted domains, never marked risky (one per line, covers subdomains)'),
        h('textarea', { id: 'trusted', name: 'trusted', spellcheck: 'false', class: 'short' }, (ac.TrustedDomains || []).join('\n')),
        intel.sources.length ? h('div', { class: 'scroll' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Source'), h('th', {}, 'Entries'), h('th', {}, 'Updated'), h('th', {}, 'Status'))),
          h('tbody', {}, intel.sources.map(x => h('tr', {}, h('td', {}, x.name), h('td', {}, fmtNum(x.entries)), h('td', {}, x.updated ? ago(x.updated) : '\u2014'),
            h('td', {}, x.error ? h('span', { class: 'badge bad', title: x.error }, x.entries ? 'update failed, using saved copy' : 'download failed') : h('span', { class: 'badge ok' }, 'ok'))))))) : null,
        h('p', { class: 'muted small' }, 'Domain types and owners come from AdGuard\u2019s companies database (CC BY-SA 4.0).'),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save')),
      ], (f) => save({ threat_feeds: f.elements.feeds.checked, trusted_domains: lines(val(f, 'trusted')) }, { threat_feeds: ac.ThreatFeeds, trusted_domains: norm(ac.TrustedDomains) }))));
  }

  if (can('lists.manage')) {
    let vt = { configured: false };
    try { vt = await api('GET', '/virustotal'); } catch (_) { /* unknown */ }
    const set = async (key) => {
      try { await api('PUT', '/virustotal', { key }); toast(key ? 'VirusTotal key saved.' : 'VirusTotal key removed.'); route(); } catch (e) { toast(e.message, 'err'); }
    };
    sections.push(h('div', { class: 'card' },
      h('h2', {}, 'VirusTotal'),
      form({}, [
        h('p', { class: 'muted' }, 'Optional. With your own free VirusTotal API key, a domain\u2019s details get a \u201cCheck on VirusTotal\u201d button. Only the domain you check is sent, only when you click, at most 4 a minute. Results are kept for a day.'),
        vt.configured ? h('p', {}, h('span', { class: 'badge ok' }, 'Key saved'), ' ', h('button', { class: 'link', type: 'button', onclick: () => set('') }, 'Remove key')) : null,
        h('label', { for: 'vtkey' }, vt.configured ? 'Replace the key' : 'API key'),
        h('input', { id: 'vtkey', name: 'vtkey', type: 'password', autocomplete: 'off', spellcheck: 'false' }),
        h('p', { class: 'muted small' }, 'The key is shared with your other servers and never shown again. It isn\u2019t part of backups.'),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save key')),
      ], (f) => { const k = val(f, 'vtkey').trim(); if (k) return set(k); })));
  }

  if (isAdmin()) {
    const hc = eff.History;
    let hs = null;
    try { hs = (await api('GET', '/status')).history; } catch (_) { /* size unknown */ }
    sections.push(h('div', { class: 'card' },
      h('h2', {}, 'Query history ', origin('history_days', 'stats_days')),
      form({ 'data-track': true }, [
        h('p', { class: 'muted' }, 'Each server keeps its own history for Analytics and the Query log. Nothing leaves your servers. Set a number to 0 to keep none.'),
        h('label', { for: 'hdays' }, 'Keep every query for (days)'),
        h('input', { id: 'hdays', name: 'hdays', type: 'number', min: 0, max: 365, value: hc.Days }),
        h('p', { class: 'muted small' }, 'Lets you search what each device looked up. Takes about 33 MB per day kept for every 100,000 queries a day; a typical home makes 10,000 to 50,000.'),
        h('label', { for: 'sdays' }, 'Keep hourly totals for (days)'),
        h('input', { id: 'sdays', name: 'sdays', type: 'number', min: 0, max: 730, value: hc.StatsDays }),
        h('p', { class: 'muted small' }, 'Charts and top lists. Much smaller than every query.'),
        hs ? h('p', { class: 'muted small' }, 'This server’s history uses ', fmtSize(hs.bytes), '.', hs.dropped ? ' ' + fmtNum(hs.dropped) + ' queries weren’t saved because the disk couldn’t keep up.' : '') : null,
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save')),
      ], (f) => save({ history_days: Number(val(f, 'hdays')), stats_days: Number(val(f, 'sdays')) }, { history_days: hc.Days, stats_days: hc.StatsDays })),
      h('h3', {}, 'Start over'),
      h('p', { class: 'muted small' }, 'Deletes history on every server. This can’t be undone, and backups don’t include history.'),
      h('div', { class: 'actions' },
        clearHistoryButton('performance', 'Clear performance stats', 'Clear performance stats on every server? Response times, upstream timings and their warnings start again from now. The query history, Analytics and the Query log are kept.'),
        clearHistoryButton('history', 'Delete all query history', 'Delete all query history on every server? Every saved query, the Analytics totals and the performance stats are deleted, and everything starts again from now.'))));
  }

  // A row of section chips at the top, so a long settings page is one
  // click from any section (buttons, not links, to keep the #/ routes).
  const secs = sections.flat(Infinity).filter(x => x instanceof Element);
  const jump = secs.length > 3 ? h('nav', { class: 'jump', 'aria-label': 'Sections' }, secs.map(sec => {
    const t = sec.querySelector('h2');
    return t ? h('button', { type: 'button', onclick: () => sec.scrollIntoView({ behavior: 'smooth', block: 'start' }) }, t.firstChild ? t.firstChild.textContent : t.textContent) : null;
  })) : null;
  page(main, 'Settings', jump, sections);
}

// ---------- import from AdGuard Home ----------

async function importPage(main) {
  const result = h('div');
  const connect = form({}, [
    h('p', { class: 'muted' }, 'DNServ reads your blocklists, custom rules, DNS rewrites, devices and upstream servers from AdGuard Home, shows you what it found, and adds what you choose. Nothing changes in AdGuard Home, and the password is used once and not saved.'),
    h('label', { for: 'agurl' }, 'AdGuard Home address'),
    h('input', { id: 'agurl', name: 'url', type: 'text', placeholder: 'http://192.168.1.2:3000', autofocus: true, autocomplete: 'off', spellcheck: 'false', required: true }),
    h('p', { class: 'muted small' }, 'The address you open AdGuard Home’s dashboard at.'),
    h('div', { class: 'row' },
      h('div', { class: 'grow' }, h('label', { for: 'aguser' }, 'Username'), h('input', { id: 'aguser', name: 'username', type: 'text', autocomplete: 'off' })),
      h('div', { class: 'grow' }, h('label', { for: 'agpass' }, 'Password'), h('input', { id: 'agpass', name: 'password', type: 'password', autocomplete: 'off' }))),
    h('label', { class: 'inline' }, h('input', { type: 'checkbox', name: 'insecure' }), h('span', {}, 'Accept a self-signed certificate (only for https:// addresses)')),
    h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Read settings')),
  ], async (f) => {
    fill(result, h('div', { class: 'card' }, h('div', { class: 'spinner' }), h('p', { class: 'muted small tc' }, 'Reading AdGuard Home…')));
    let res;
    try {
      res = await api('POST', '/import/adguard/preview', { url: val(f, 'url'), username: val(f, 'username'), password: val(f, 'password'), insecure: f.elements.insecure.checked });
    } catch (e) { fill(result); throw e; }
    f.elements.password.value = '';
    importPreview(result, res.id, res.plan);
  });
  page(main, 'Import from AdGuard Home', h('div', { class: 'import' }, h('div', { class: 'card' }, connect), result));
}

function importPreview(box, id, plan) {
  const pick = [];
  const exclude = new Set();
  const list = (items, title, open, withBoxes) => {
    if (!items || !items.length) return null;
    const shown = items.slice(0, 500);
    return h('details', { open: open || null }, h('summary', {}, title),
      h('ul', { class: 'plain small' }, shown.map(it => h('li', {},
        withBoxes && it.id ? h('label', { class: 'inline' },
          h('input', { type: 'checkbox', checked: true, onchange: (ev) => { if (ev.target.checked) exclude.delete(it.id); else exclude.add(it.id); } }),
          h('span', {}, h('span', { class: 'mono' }, it.text), it.detail ? h('span', { class: 'muted' }, ' · ' + it.detail) : null))
          : h('span', {}, h('span', { class: 'mono' }, it.text), it.detail ? h('span', { class: 'muted' }, ' — ' + it.detail) : null))),
        items.length > shown.length ? h('li', { class: 'muted' }, 'and ' + fmtNum(items.length - shown.length) + ' more') : null));
  };
  const cards = plan.sections.map(s => {
    if (s.info) {
      return h('div', { class: 'card' }, h('h2', {}, s.title),
        h('ul', { class: 'plain small' }, (s.skipped || []).map(it => h('li', {}, h('b', {}, it.text), h('span', { class: 'muted' }, ' — ' + it.detail)))));
    }
    const n = s.items.length, have = (s.have || []).length, skipped = (s.skipped || []).length;
    const counts = [n ? fmtNum(n) + ' to add' : 'Nothing new', have ? fmtNum(have) + ' already in DNServ' : null, skipped ? fmtNum(skipped) + ' can’t move' : null].filter(Boolean).join(' · ');
    let tick = null;
    if (n) {
      tick = h('input', { type: 'checkbox', checked: s.default });
      pick.push({ key: s.key, box: tick });
    }
    return h('div', { class: 'card' },
      n ? h('label', { class: 'inline m0' }, tick, h('h2', { class: 'm0' }, s.title)) : h('h2', { class: 'm0' }, s.title),
      h('p', { class: 'muted small mt-s' }, counts),
      s.note ? h('p', { class: 'small' + (s.default || !n ? '' : ' warn-text') }, s.note) : null,
      list(s.items, 'What will be added', n <= 12, true),
      list(s.have, 'Already in DNServ', false, false),
      list(s.skipped, 'Can’t be moved, and why', skipped <= 6, false));
  });
  const done = h('div');
  const go = h('button', { class: 'primary', type: 'button', onclick: async () => {
    const sections = pick.filter(p => p.box.checked).map(p => p.key);
    if (!sections.length) { fill(done, msg('err', 'Tick at least one section to import.')); return; }
    go.disabled = true;
    try {
      const r = await api('POST', '/import/adguard/apply', { id, sections, exclude: [...exclude] });
      fill(box, h('div', { class: 'card highlight' },
        h('h2', {}, 'Imported from AdGuard Home'),
        h('p', {}, r.summary ? 'Added ' + r.summary + '.' : 'Everything was already in DNServ.'),
        r.lists ? h('p', { class: 'muted small' }, 'New lists download in the background and start blocking within a minute.') : null,
        h('p', {}, 'Next: check ', h('a', { href: '#/settings' }, 'Settings'), ', ', h('a', { href: '#/names' }, 'Local names'), ' and ', h('a', { href: '#/devices' }, 'Devices'),
          ', then point your router’s DNS at DNServ. Keep AdGuard Home running until devices have moved across.')));
    } catch (e) {
      fill(done, msg('err', e.message));
      go.disabled = false;
    }
  } }, 'Import selected');
  fill(box,
    h('p', { class: 'muted' }, 'Found AdGuard Home ', plan.version || '', ' at ', h('code', {}, plan.source), '. Tick what to bring across; open a section to leave single items out.'),
    cards,
    pick.length ? h('div', { class: 'card' }, h('div', { class: 'actions m0' }, go, h('button', { type: 'button', onclick: () => fill(box) }, 'Cancel')), done)
      : h('div', { class: 'card' }, h('p', {}, 'Everything DNServ can import is already here.')));
  box.scrollIntoView({ behavior: 'smooth', block: 'start' });
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
    status.push(msg('err', 'This node is no longer part of its cluster (it was removed, or the cluster was recovered without it). It still answers DNS with the settings it last had. To bring it back, make a join code on a working node and use "Join another DNServ" below.'));
  } else if (!c.healthy) {
    status.push(msg('err', 'No leader: this node can’t reach enough of the cluster, so changes are paused. DNS keeps working everywhere with the current settings. Bring the missing node back, or if it’s gone for good, recover below.'));
  } else if (nodes.length === 1) {
    status.push(h('p', { class: 'muted' }, 'This DNServ runs on one server. Add a second so DNS keeps working if one goes down. Settings, accounts and blocklists stay the same on both.'));
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
      h('li', {}, 'On the new server, start DNServ the same way as this one (the same ', h('code', {}, 'docker compose'), ' file works). Make sure port ', h('b', {}, '8081'), ' is published and open between the servers.'),
      h('li', {}, 'Open its dashboard, enter its setup code, and choose ', h('b', {}, 'No, add this server to my DNServ'), '.'),
      h('li', {}, 'Paste the join code from here. It works once, for an hour.')),
    h('p', { class: 'muted small' }, 'Adding a ', h('b', {}, 'witness'), ' instead? It\u2019s the same image on a third machine; it only votes, so it needs very little. Make a join code and the next screen shows the command to start it.'),
    form({}, [
      h('label', { for: 'host' }, 'Other nodes reach this one at'),
      h('div', { class: 'row' }, h('input', { id: 'host', name: 'host', type: 'text', value: c.advertise_learned ? (c.advertise || '').replace(/:\d+$/, '').replace(/^\[|\]$/g, '') : location.hostname, required: true, spellcheck: 'false' }), h('span', { class: 'muted' }, ':' + ((c.advertise || '').match(/:(\d+)$/) || [, '8081'])[1])),
      h('p', { class: 'muted small' }, 'This server’s address on your network. Usually the one in your browser’s address bar.'),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Make a join code')),
    ], async (f) => {
      const r = await api('POST', '/cluster/join-codes', { host: val(f, 'host').trim() });
      const cmd = 'docker run -d --name dnserv-witness --restart unless-stopped \\\n  -p 8081:8081 -v dnserv-witness:/data \\\n  -e DNSERV_ROLE=witness -e DNSERV_JOIN=' + r.code + ' \\\n  ghcr.io/prezmc/dnserv:latest';
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
    h('p', { class: 'muted small' }, 'DNServ checks first that no other node answers. It can\u2019t tell a server that is switched off from a broken link between the servers, so if the other one might still be running, fix the link instead: recovering both sides would leave two separate DNServs. The nodes left out are locked out; to use one again, join it with a new code.'),
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

  const joinCard = data.can_join ? h('details', { class: 'card' }, h('summary', {}, 'Join another DNServ instead'),
    msg('warn', 'This replaces everything on this node (accounts, settings, devices and groups) with the other DNServ’s. You’ll sign in again with an account from there.'),
    form({}, [
      h('label', { for: 'jc' }, 'Join code from the other DNServ'),
      h('textarea', { id: 'jc', name: 'join', class: 'code', rows: 3, required: true, spellcheck: 'false', placeholder: 'DNSJ1-…' }),
      h('label', { for: 'jpw' }, 'Your password'),
      h('input', { id: 'jpw', name: 'password', type: 'password', autocomplete: 'current-password', required: true }),
      h('div', { class: 'actions' }, h('button', { class: 'primary danger-fill', type: 'submit' }, 'Replace and join')),
    ], async (f) => {
      if (!(await ask('Replace this node’s accounts and settings with the other DNServ’s?', 'Replace and join'))) return;
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

// ---------- local names ----------

const isIP = (v) => /^[0-9.]+$/.test(v) || v.includes(':');

async function localNames(main) {
  const title = 'Local names';
  page(main, title, h('p', { class: 'muted' }, 'Loading…'));
  let s;
  try { s = await api('GET', '/settings'); } catch (e) { return page(main, title, msg('err', e.message)); }
  const recs = (s.effective.DNS.Records || []).slice();
  const router = s.effective.DNS.LocalDNS;

  const saveAll = async (next, note) => {
    await api('PATCH', '/settings', { records: next });
    toast(note);
    route();
  };
  const kind = (r) => isIP(r.value) ? (r.value.includes(':') ? 'IPv6 address' : 'Address') : 'Alias for';

  const fields = (r) => [
    h('label', { for: 'rn' }, 'Name'),
    h('input', { id: 'rn', name: 'name', type: 'text', value: r.name || '', placeholder: 'nas.home', required: true, spellcheck: 'false', autocapitalize: 'off', autofocus: true }),
    h('p', { class: 'muted small' }, 'Start with *. to cover every name below it, like *.lab.home.'),
    h('label', { for: 'rv' }, 'Points to'),
    h('input', { id: 'rv', name: 'value', type: 'text', value: r.value || '', placeholder: '192.168.1.20', required: true, spellcheck: 'false', autocapitalize: 'off' }),
    h('p', { class: 'muted small' }, 'An IP address, or another name to make this one an alias (like files.home → nas.home).'),
    h('label', { for: 'rnote' }, 'Note (optional)'),
    h('input', { id: 'rnote', name: 'note', type: 'text', value: r.note || '', maxlength: 200 }),
  ];
  const read = (f) => ({ name: val(f, 'name').trim(), value: val(f, 'value').trim(), note: val(f, 'note').trim() || undefined });

  const edit = (i) => {
    const d = dialog('Edit ' + recs[i].name, form({}, [fields(recs[i]),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save'), h('button', { type: 'button', onclick: () => d.close() }, 'Cancel'))],
    async (f) => {
      const next = recs.slice();
      next[i] = read(f);
      await api('PATCH', '/settings', { records: next });
      d.close();
      toast('Saved ' + next[i].name);
      route();
    }));
  };
  const remove = async (i) => {
    if (!(await ask('Remove ' + recs[i].name + ' → ' + recs[i].value + '?', 'Remove'))) return;
    const next = recs.slice();
    next.splice(i, 1);
    try { await saveAll(next, 'Removed ' + recs[i].name); } catch (e) { toast(e.message, 'err'); }
  };

  const order = recs.map((r, i) => i).sort((a, b) => recs[a].name.localeCompare(recs[b].name) || recs[a].value.localeCompare(recs[b].value));
  const list = recs.length ? h('div', { class: 'scroll' }, h('table', {},
    h('thead', {}, h('tr', {}, h('th', {}, 'Name'), h('th', {}, 'Points to'), h('th', {}, 'Note'), h('th', {}))),
    h('tbody', {}, order.map(i => { const r = recs[i]; return h('tr', {},
      h('td', {}, h('b', {}, r.name)),
      h('td', {}, h('span', { class: 'muted small' }, kind(r) + ' '), h('code', {}, r.value)),
      h('td', { class: 'small muted' }, r.note || ''),
      h('td', {}, h('div', { class: 'row' },
        h('button', { class: 'link', onclick: () => edit(i) }, 'Edit'),
        h('button', { class: 'link danger', onclick: () => remove(i) }, 'Remove')))); }))))
    : h('p', { class: 'muted' }, 'No local names yet.');

  const add = h('div', { class: 'card' }, h('h2', {}, 'Add a name'),
    form({}, [fields({}), h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Add'))], async (f) => {
      const r = read(f);
      await saveAll(recs.concat([r]), r.name + ' now points to ' + r.value);
    }));

  page(main, title,
    h('p', { class: 'muted' }, 'Give names to things on your network, like nas.home or printer.office. Every DNServ node answers them, before blocklists and before asking the internet. They’re part of settings history and backups.'),
    h('div', { class: 'card' }, h('h2', {}, 'Your names'), list,
      h('p', { class: 'muted small' }, 'Pick names under a domain you control, or under .home.arpa, .home, .lan or .internal. A name here overrides the real one on the internet for your devices.')),
    add,
    h('div', { class: 'card' }, h('h2', {}, 'Names from your router'),
      router
        ? h('p', {}, 'Other local names (like a device’s own name) are looked up at your router, ', h('code', {}, router), '. Names on this page win over the router’s.')
        : h('p', {}, 'DNServ can also answer the names your router knows for each device. Add your router’s address under ', h('a', { href: '#/settings' }, 'Settings → Device names'), '.')));
}

// ---------- backups & history ----------

// apiForm posts a multipart form (a file upload).
async function apiForm(path, fd) {
  const r = await fetch('/api/v1' + path, { method: 'POST', body: fd, credentials: 'same-origin', headers: csrf ? { 'X-CSRF-Token': csrf } : {} });
  const text = await r.text();
  let data = null;
  if (text) { try { data = JSON.parse(text); } catch (_) { /* not JSON */ } }
  if (!r.ok) throw new Error((data && data.error) || ('Request failed (HTTP ' + r.status + ')'));
  return data;
}

// fetchFile downloads a file from the API and saves it.
async function fetchFile(method, path) {
  const r = await fetch('/api/v1' + path, { method, credentials: 'same-origin', headers: csrf ? { 'X-CSRF-Token': csrf } : {} });
  if (!r.ok) {
    let m = 'Download failed (HTTP ' + r.status + ')';
    try { m = (await r.json()).error || m; } catch (_) { /* keep */ }
    throw new Error(m);
  }
  const name = ((r.headers.get('Content-Disposition') || '').match(/filename="([^"]+)"/) || [, 'dnserv-backup.dnsbak'])[1];
  const a = h('a', { href: URL.createObjectURL(await r.blob()), download: name });
  document.body.append(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}

function fmtSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1 << 20) return (n / 1024).toFixed(0) + ' KB';
  return (n / (1 << 20)).toFixed(1) + ' MB';
}

const shown = (v) => (v === 'present' ? 'Exists' : v || '\u2014');

// settingName turns "settings.filtering.block_mode" into "Filtering › block mode".
function settingName(path) {
  const parts = path.split('.');
  const kind = parts.shift();
  const nice = parts.map(p => p.replace(/_/g, ' '));
  if (kind === 'devices') nice[0] = 'Device “' + nice[0] + '”';
  if (kind === 'groups') nice[0] = 'Group “' + nice[0] + '”';
  if (nice.length) nice[0] = nice[0].charAt(0).toUpperCase() + nice[0].slice(1);
  return nice.join(' › ');
}

function passphraseFields(label) {
  return [
    h('label', { for: 'pp' }, label || 'Backup passphrase'),
    h('input', { id: 'pp', name: 'pp', type: 'password', autocomplete: 'new-password', minlength: 12, required: true }),
    h('p', { class: 'muted small' }, 'At least 12 characters. Four or five random words works well. Use a different one from your password.'),
    h('label', { for: 'pp2' }, 'Confirm passphrase'),
    h('input', { id: 'pp2', name: 'pp2', type: 'password', autocomplete: 'new-password', required: true }),
    h('label', { for: 'bpw' }, 'Your DNServ password'),
    h('input', { id: 'bpw', name: 'password', type: 'password', autocomplete: 'current-password', required: true }),
  ];
}

async function backupsPage(main) {
  const title = 'Backups & history';
  page(main, title, h('p', { class: 'muted' }, 'Loading…'));
  let vers, bk;
  try { [vers, bk] = await Promise.all([api('GET', '/config/versions'), api('GET', '/backups')]); } catch (e) { return page(main, title, msg('err', e.message)); }

  // Settings history.
  const compare = async (v) => {
    let d;
    try { d = await api('GET', '/config/versions/' + v.id); } catch (e) { return toast(e.message, 'err'); }
    const ch = d.changes || [];
    const dl = dialog('Go back to ' + fmtTime(v.time) + '?', [
      h('p', { class: 'muted' }, 'Version ' + v.id + ': ' + v.summary + ' (' + v.actor + ')'),
      ch.length ? h('div', { class: 'scroll' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Setting'), h('th', {}, 'Now'), h('th', {}, 'After going back'))),
        h('tbody', {}, ch.map(c => h('tr', {}, h('td', {}, settingName(c.path)), h('td', { class: 'small' }, shown(c.now)), h('td', { class: 'small' }, shown(c.then)))))))
        : msg('ok', 'This version is the same as your current settings.'),
      h('p', { class: 'muted small' }, 'Accounts and API tokens stay as they are. Going back is recorded as a new version, so you can undo it.'),
      h('div', { class: 'actions' },
        ch.length ? h('button', { class: 'primary', type: 'button', onclick: async () => {
          try { await api('POST', '/config/versions/' + v.id + '/restore', {}); toast('Settings are back to how they were on ' + fmtTime(v.time)); dl.close(); } catch (e) { toast(e.message, 'err'); }
        } }, 'Go back to this version') : null,
        h('button', { type: 'button', autofocus: true, onclick: () => dl.close() }, 'Cancel'))]);
    dl.classList.add('wide');
    dl.addEventListener('close', () => route());
  };
  const history = h('div', { class: 'card' }, h('h2', {}, 'Settings history'),
    h('p', { class: 'muted' }, 'DNServ keeps the last ' + vers.max + ' versions of your settings, devices and groups, on every node. Look at what changed and go back to any of them. Accounts aren’t part of this, so going back never brings back an old password.'),
    vers.versions.length ? h('div', { class: 'scroll' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'When'), h('th', {}, 'Who'), h('th', {}, 'What changed'), h('th', {}))),
      h('tbody', {}, vers.versions.map(v => h('tr', {},
        h('td', { class: 'nowrap' }, fmtTime(v.time)), h('td', {}, v.actor), h('td', {}, v.summary),
        h('td', {}, v.id === vers.current ? h('span', { class: 'badge' }, 'current') : h('button', { class: 'link', onclick: () => compare(v) }, 'Compare and go back')))))))
      : h('p', { class: 'muted' }, 'No changes yet. Each change you save from now on appears here.'));

  // Backups.
  const backupCard = !bk.configured ? setupBackups() : scheduleCard();

  function setupBackups() {
    return h('div', { class: 'card highlight' }, h('h2', {}, 'Set up backups'),
      h('p', {}, 'A backup holds your accounts, settings, devices, groups and settings history in one file, encrypted with a passphrase you choose. Use one to rebuild DNServ on a new server, or to undo a mistake.'),
      msg('warn', 'Write the passphrase down somewhere safe, like a password manager. DNServ doesn’t keep it, so without it nobody, including you, can open a backup.'),
      form({}, [passphraseFields(), h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Set up backups'))], async (f) => {
        if (val(f, 'pp') !== val(f, 'pp2')) throw new Error("The passphrases don't match.");
        await api('POST', '/backups/passphrase', { passphrase: val(f, 'pp'), password: val(f, 'password') });
        toast('Backups are set up');
        route();
      }));
  }

  function scheduleCard() {
    const files = bk.files || [];
    return h('div', { class: 'card' }, h('h2', {}, 'Backups'),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'button', onclick: async (ev) => {
        ev.target.disabled = true;
        try { await fetchFile('POST', '/backups/download'); } catch (e) { toast(e.message, 'err'); }
        ev.target.disabled = false;
      } }, 'Download a backup now')),
      form({ 'data-track': true }, [
        h('h3', {}, 'Automatic backups'),
        h('label', { for: 'every' }, 'How often'),
        h('select', { id: 'every', name: 'every' },
          h('option', { value: '', selected: !bk.every }, 'Off (download by hand only)'),
          h('option', { value: 'daily', selected: bk.every === 'daily' }, 'Every day'),
          h('option', { value: 'weekly', selected: bk.every === 'weekly' }, 'Every week, on Sunday')),
        h('label', { for: 'at' }, 'At'),
        h('input', { id: 'at', name: 'at', type: 'time', value: bk.at || '03:00' }),
        h('p', { class: 'muted small' }, 'In ', h('b', {}, bk.time_zone), ' time, the same as group schedules.', can('network.manage') ? [' ', h('a', { href: '#/settings' }, 'Change')] : null),
        h('label', { for: 'keep' }, 'Keep the last'),
        h('div', { class: 'row' }, h('input', { id: 'keep', name: 'keep', type: 'number', min: 1, max: 365, value: bk.keep || bk.default_keep }), h('span', { class: 'muted' }, 'backups')),
        h('label', { for: 'offsite' }, 'Also copy to a folder (optional)'),
        h('input', { id: 'offsite', name: 'offsite', type: 'text', value: bk.offsite || '', placeholder: '/backups', spellcheck: 'false' }),
        h('p', { class: 'muted small' }, 'Every node keeps its own backups in ', h('code', {}, bk.dir || '/data/backups'),
          '. To keep copies off the server too, mount a folder from your NAS or another disk into the container (for example ', h('code', {}, '-v /mnt/nas/dnserv:/backups'),
          ') and enter its path here. The leading node writes one copy per backup there.'),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Save schedule')),
      ], async (f) => {
        await api('PUT', '/backups/schedule', { every: val(f, 'every'), at: val(f, 'at'), keep: parseInt(val(f, 'keep'), 10) || 0, offsite: val(f, 'offsite').trim() });
        setTimeout(route, 900);
        return val(f, 'every') ? 'Saved. Backups run ' + (val(f, 'every') === 'daily' ? 'every day' : 'every Sunday') + ' at ' + val(f, 'at') + '.' : 'Saved. Automatic backups are off.';
      }),
      h('h3', {}, 'Saved backups'),
      files.length ? h('div', { class: 'scroll' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Made'), h('th', {}, 'By node'), h('th', {}, 'Where'), h('th', {}, 'Size'), h('th', {}))),
        h('tbody', {}, files.map(x => h('tr', {},
          h('td', { class: 'nowrap' }, fmtTime(x.created)), h('td', {}, x.node || '—'),
          h('td', {}, x.where === 'offsite' ? 'Copy folder' : 'This node'), h('td', { class: 'small muted' }, fmtSize(x.size)),
          h('td', {}, h('button', { class: 'link', onclick: () => fetchFile('GET', '/backups/files/' + x.where + '/' + encodeURIComponent(x.name)).catch(e => toast(e.message, 'err')) }, 'Download')))))))
        : h('p', { class: 'muted' }, bk.every ? 'None yet. The first one is made at the next scheduled time.' : 'None saved on this node. Turn on automatic backups above, or download one now.'),
      h('details', {}, h('summary', {}, 'Change the backup passphrase'),
        h('p', { class: 'muted small' }, 'New backups use the new passphrase. Backups you already have still open with the old one, so keep it until they’re no longer needed.'),
        form({}, [passphraseFields('New backup passphrase'), h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Change passphrase'))], async (f) => {
          if (val(f, 'pp') !== val(f, 'pp2')) throw new Error("The passphrases don't match.");
          await api('POST', '/backups/passphrase', { passphrase: val(f, 'pp'), password: val(f, 'password') });
          f.reset();
          return 'Changed. New backups use the new passphrase.';
        })));
  }

  const restoreCard = h('details', { class: 'card' }, h('summary', {}, 'Restore from a backup file'),
    msg('warn', 'This replaces the accounts, settings, devices, groups and settings history on every node with the backup’s. The cluster’s nodes and the backup settings stay as they are.'),
    form({}, [
      h('label', { for: 'rf' }, 'Backup file'),
      h('input', { id: 'rf', name: 'file', type: 'file', accept: '.dnsbak', required: true }),
      h('label', { for: 'rpp' }, 'The passphrase it was made with'),
      h('input', { id: 'rpp', name: 'passphrase', type: 'password', autocomplete: 'off', required: true }),
      h('label', { for: 'rpw2' }, 'Your DNServ password'),
      h('input', { id: 'rpw2', name: 'password', type: 'password', autocomplete: 'current-password', required: true }),
      h('div', { class: 'actions' }, h('button', { class: 'primary danger-fill', type: 'submit' }, 'Restore')),
    ], async (f) => {
      if (!(await ask('Replace the accounts and settings with the backup’s?', 'Restore'))) return;
      const fd = new FormData();
      fd.append('file', f.elements.file.files[0]);
      fd.append('passphrase', val(f, 'passphrase'));
      fd.append('password', val(f, 'password'));
      const r = await apiForm('/backups/restore', fd);
      toast('Restored the backup made on ' + fmtTime(r.created) + (r.node ? ' by ' + r.node : ''));
      if (r.signed_out) { csrf = ''; ME = null; boot(); return; }
      try { ME = await api('GET', '/auth/me'); } catch (_) { /* boot handles it */ }
      route();
    }));

  page(main, title, history, backupCard, restoreCard);
}

// setupRestore: first run from a backup file.
function setupRestore(code) {
  render(centered(
    h('h1', {}, 'Restore DNServ from a backup'),
    h('p', { class: 'muted' }, 'Use a backup file from this or another DNServ. Its accounts, settings, devices, groups and backup schedule come back as they were.'),
    form({}, [
      h('label', { for: 'sf' }, 'Backup file (.dnsbak)'),
      h('input', { id: 'sf', name: 'file', type: 'file', accept: '.dnsbak', required: true, autofocus: true }),
      h('label', { for: 'spp' }, 'Backup passphrase'),
      h('input', { id: 'spp', name: 'passphrase', type: 'password', autocomplete: 'off', required: true }),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Restore'), h('button', { class: 'link', type: 'button', onclick: () => setupChoice(code) }, 'Back')),
    ], async (f) => {
      const fd = new FormData();
      fd.append('file', f.elements.file.files[0]);
      fd.append('passphrase', val(f, 'passphrase'));
      fd.append('code', code);
      const r = await apiForm('/setup/restore', fd);
      render(centered(
        h('h1', {}, 'DNServ is restored'),
        msg('ok', 'Everything from the backup made on ' + fmtTime(r.created) + ' is back.'),
        h('p', {}, 'Sign in with an account from the backup. If this server has a new address, update the DNS servers in your router.'),
        h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'button', autofocus: true, onclick: boot }, 'Sign in'))));
    }),
  ));
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
  const text = 'DNServ recovery codes for ' + ME.user.username + ' on ' + location.hostname + '\n' +
    'Each code works once. Keep them somewhere safe.\n\n' + codes.join('\n') + '\n';
  const done = h('button', { class: 'primary', type: 'button', disabled: true, onclick: () => d.close() }, 'Done');
  const d = dialog(title, [
    h('p', { class: 'muted' }, 'Your old recovery codes no longer work. Each of these lets you sign in once if you lose your phone.'),
    h('div', { class: 'codes mono' }, codes.map(c => h('div', {}, c))),
    h('div', { class: 'actions' },
      h('button', { type: 'button', onclick: () => download('dnserv-recovery-codes.txt', text) }, 'Download'),
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
