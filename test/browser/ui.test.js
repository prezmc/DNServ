// Browser tests: a real DNServ node, driven through its web dashboard in
// Chromium the way a person would use it, with DNS lookups sent to the
// node to check that what the dashboard says is what DNS does.
//
//   go build -o dnserv-browser-test ./cmd/dnserv
//   cd test/browser && npm ci && npx playwright install chromium
//   node --test
//
// See docs/testing.md.
'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');
const { startNode, authenticator } = require('./node');
const { lookup } = require('./dns');

const USER = 'admin', PASS = 'correct horse battery staple';
const SHOTS = process.env.BROWSER_SHOTS; // folder for failure screenshots

let node, browser, context, page, otp;
const problems = []; // page errors and failed API calls

before(async () => {
  node = await startNode();
  browser = await chromium.launch();
  context = await browser.newContext({ viewport: { width: 1280, height: 900 }, acceptDownloads: true });
  page = await context.newPage();
  page.setDefaultTimeout(10000);
  page.on('pageerror', e => problems.push('page error: ' + e.message));
  page.on('console', m => { if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) problems.push('console: ' + m.text()); });
  page.on('response', r => {
    if (r.url().includes('/api/') && r.status() >= 500) problems.push(r.status() + ' ' + r.request().method() + ' ' + r.url());
  });
});

after(async () => {
  if (browser) await browser.close();
  if (node) await node.stop();
});

// step wraps a test: on failure it saves a screenshot, and every step
// fails if the page logged an error or an API call failed.
function step(name, fn) {
  test(name, async () => {
    problems.length = 0;
    try {
      await fn();
      assert.deepEqual(problems, [], 'the page reported problems');
    } catch (e) {
      if (SHOTS) {
        fs.mkdirSync(SHOTS, { recursive: true });
        await page.screenshot({ path: path.join(SHOTS, name.replace(/[^a-z0-9]+/gi, '-') + '.png'), fullPage: true }).catch(() => {});
      }
      throw e;
    }
  });
}

// go opens a page afresh (a hash change alone keeps open dialogs).
const go = async (hash) => { await page.goto('about:blank'); await page.goto(node.url + '#/' + hash); await page.waitForLoadState('networkidle'); };
const heading = (text) => page.getByRole('heading', { name: text, exact: true }).first();
const toastSays = (text) => page.locator('#toasts').getByText(text).first().waitFor();
const until = async (what, fn, ms = 15000) => {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn().catch(() => false);
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out waiting for ' + what);
    await new Promise(r => setTimeout(r, 300));
  }
};
// api calls the node's API from the signed-in page, for checks.
const api = (method, p, body) => page.evaluate(async ([method, p, body]) => {
  const r = await fetch('/api/v1' + p, { method, headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': typeof csrf === 'undefined' ? '' : csrf }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text();
  if (!r.ok) throw new Error(r.status + ' ' + t);
  return t ? JSON.parse(t) : null;
}, [method, p, body]);

step('setup wizard creates the admin with an authenticator', async () => {
  await page.goto(node.url);
  await page.fill('#code', await node.setupCode());
  await page.click('button[type=submit]');
  await page.getByText(/Yes, set up a new/).click();
  await page.fill('#password', PASS);
  await page.fill('#confirm', PASS);
  await page.click('button[type=submit]');
  // The authenticator step: read the key the page shows for typing in.
  await page.locator('details summary').click();
  const key = (await page.locator('details code').innerText()).replace(/\s+/g, '');
  otp = authenticator(key);
  await page.fill('#code', await otp.next());
  await page.click('button[type=submit]');
  // Recovery codes must be acknowledged.
  await page.locator('input[type=checkbox]').check();
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('button', { name: 'Skip' }).click();
  await page.getByRole('button', { name: 'Open the dashboard' }).click();
  await heading('Dashboard').waitFor();
});

step('DNS answers through the fake upstream', async () => {
  const r = await lookup(node.dnsPort, 'www.example.test');
  assert.equal(r.rcode, 'NOERROR');
  assert.deepEqual(r.a, ['203.0.113.7']);
  assert.ok(node.upstream.seen.includes('www.example.test'));
  // Asked again, it comes from the cache: the upstream sees it once.
  await lookup(node.dnsPort, 'www.example.test');
  assert.equal(node.upstream.seen.filter(n => n === 'www.example.test').length, 1);
});

step('every page opens without errors', async () => {
  const pages = [['', 'Dashboard'], ['devices', 'Devices'], ['analytics', 'Analytics'], ['performance', 'Performance'], ['queries', 'Query log'],
    ['names', 'Local names'], ['settings', 'Settings'], ['users', 'Users'], ['cluster', 'Cluster'], ['backups', 'Backups & history'],
    ['import', 'Import from AdGuard Home'], ['audit', 'Audit log'], ['account', 'Your account']];
  for (const [hash, title] of pages) {
    await go(hash);
    await heading(title).waitFor();
    assert.equal(await page.locator('.msg.err').count(), 0, title + ' shows an error');
  }
  // The menu links to each page shown.
  const links = await page.locator('nav a[href^="#/"]').count();
  assert.ok(links >= 10, 'menu has ' + links + ' links');
});

step('block a domain from the dashboard, then remove the rule', async () => {
  await go('');
  const card = page.locator('.d-check');
  await card.locator('input[name=domain]').fill('ads.blockme.test');
  await card.getByRole('button', { name: 'Block', exact: true }).click();
  await card.getByText('Blocked ads.blockme.test.').waitFor();
  // Rules apply at once, to the domain and its subdomains.
  const r = await until('the block', async () => { const x = await lookup(node.dnsPort, 'x.ads.blockme.test'); return x.a[0] === '0.0.0.0' && x; });
  assert.deepEqual(r.a, ['0.0.0.0']);
  await card.locator('input[name=domain]').fill('ads.blockme.test');
  await card.getByRole('button', { name: 'Check' }).click();
  await card.getByText(/is blocked/).waitFor();
  await card.locator('input[name=domain]').fill('ads.blockme.test');
  await card.getByRole('button', { name: 'Remove rule' }).click();
  await card.getByText(/Removed your rule/).waitFor();
  await until('the rule to go', async () => (await lookup(node.dnsPort, 'y.ads.blockme.test')).a[0] === '203.0.113.7');
});

step('a blocklist added in Settings downloads and blocks', async () => {
  await go('settings');
  const editor = page.locator('[data-list=lists]');
  await editor.getByRole('button', { name: 'Add list' }).click();
  const row = editor.locator('tbody tr').last();
  await row.locator('[data-f=name]').fill('Browser test list');
  await row.locator('[data-f=url]').fill(node.listURL);
  await editor.locator('xpath=ancestor::form').getByRole('button', { name: 'Save' }).click();
  await until('the list to load', async () => {
    const st = await api('GET', '/status');
    const l = (st.filter && st.filter.lists || []).find(x => x.name === 'Browser test list');
    return l && l.rules === 2;
  }, 30000);
  assert.deepEqual((await lookup(node.dnsPort, 'ads.listed.test')).a, ['0.0.0.0']);
  // The Lists card says when the list's owner last changed it, from the
  // list's own header.
  await go('');
  const lists = page.locator('.card', { has: page.getByRole('heading', { name: 'Lists', exact: true }) });
  await lists.getByText('Browser test list').waitFor();
  const changed = await lists.locator('tr', { hasText: 'Browser test list' }).getAttribute('title').catch(() => null);
  const cell = await lists.locator('tr', { hasText: 'Browser test list' }).innerText();
  assert.match(cell + ' ' + (changed || ''), /ago|2026/, 'last changed shown');
});

step('local names answer on DNS', async () => {
  await go('names');
  await page.fill('#rn', 'nas.home');
  await page.fill('#rv', '192.168.50.20');
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  await toastSays('nas.home now points to 192.168.50.20');
  await page.getByRole('cell', { name: 'nas.home' }).waitFor();
  const r = await until('the name', async () => { const x = await lookup(node.dnsPort, 'nas.home'); return x.a.length && x; });
  assert.deepEqual(r.a, ['192.168.50.20']);
  assert.ok(!node.upstream.seen.includes('nas.home'), 'local names never go upstream');
});

step('pause filtering lets blocked names through, and resume undoes it', async () => {
  await go('');
  await page.getByRole('button', { name: 'Pause filtering' }).click();
  await page.getByRole('dialog').getByRole('button', { name: '5 minutes', exact: true }).click();
  await toastSays('Filtering paused');
  await until('the pause', async () => (await lookup(node.dnsPort, 'tracker.listed.test')).a[0] === '203.0.113.7');
  await page.locator('.d-pause').getByRole('button', { name: /back on/ }).first().click();
  await until('filtering back on', async () => (await lookup(node.dnsPort, 'tracker.listed.test')).a[0] === '0.0.0.0');
});

step('the query log finds lookups and exports CSV', async () => {
  await go('queries');
  await page.getByRole('combobox', { name: 'Search domains' }).fill('ads.listed.test');
  await page.keyboard.press('Enter');
  await page.locator('table').getByText('ads.listed.test').first().waitFor();
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export CSV' }).click()]);
  const csv = fs.readFileSync(await dl.path(), 'utf8');
  assert.match(csv.split('\n')[0], /^time,server,client/);
  assert.match(csv, /ads\.listed\.test/);
});

step('dashboard shows the lookups', async () => {
  await go('');
  const tiles = page.locator('.d-tiles');
  await tiles.getByText('Queries').first().waitFor();
  const q = await tiles.locator('.tile').first().innerText();
  assert.match(q, /[1-9]/, 'queries tile counts lookups: ' + q);
  await page.locator('.d-chart svg.chart').waitFor();
  await page.locator('.d-flow svg.flow').waitFor();
  // Picking a device redraws the map with only its lookups, and opens
  // its profile; All devices goes back.
  await page.locator('.d-flow .flow-node').first().click();
  await page.locator('.flow-focus').getByText(/Showing only/).waitFor();
  await page.locator('.dev-profile').getByText(/Profile:/).waitFor();
  const devices = await page.locator('.d-flow .flow-node').evaluateAll(ns => ns.filter(n => n.querySelector('text') && n.getBoundingClientRect().left < 300).length);
  assert.equal(devices, 1, 'one device on the map');
  await page.getByRole('button', { name: 'All devices' }).click();
  await until('the full map', async () => (await page.locator('.flow-focus').count()) === 0);
});

step('performance shows how full the cache is, and the size can change', async () => {
  await go('performance');
  const card = page.locator('.card', { has: page.getByRole('heading', { name: 'How full the cache is' }) });
  await card.waitFor();
  assert.match(await card.innerText(), /of 100,000 answers/);
  await go('settings');
  await page.fill('#csize', '50000');
  await page.locator('#csize').locator('xpath=ancestor::form').getByRole('button', { name: 'Save' }).click();
  await until('the new size', async () => (await api('GET', '/settings')).effective.Cache.MaxEntries === 50000);
  await go('performance');
  await page.getByText(/of 50,000 answers/).first().waitFor();
});

step('arranging the dashboard is saved with the account', async () => {
  await go('');
  await page.getByRole('button', { name: 'Arrange' }).click();
  await page.locator('.d-check .arrange-bar').getByRole('button', { name: 'Hide' }).click();
  await page.getByRole('button', { name: 'Done' }).click();
  await toastSays('Dashboard layout saved');
  await page.reload(); await page.waitForLoadState('networkidle');
  await heading('Dashboard').waitFor();
  assert.equal(await page.locator('.d-check').isVisible(), false, 'hidden card stays hidden');
  const me = await api('GET', '/auth/me');
  assert.ok((me.dashboard || []).includes('-check'));
  await api('PUT', '/auth/dashboard', { layout: [] });
});

step('backups: set a passphrase and download a backup', async () => {
  await go('backups');
  await page.fill('#pp', 'browser test passphrase');
  await page.fill('#pp2', 'browser test passphrase');
  await page.fill('#bpw', PASS);
  await page.getByRole('button', { name: 'Set up backups' }).click();
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download a backup now' }).click()]);
  const size = fs.statSync(await dl.path()).size;
  assert.ok(size > 100, 'backup file has ' + size + ' bytes');
  // Encrypted: the admin's name isn't readable in the file.
  assert.ok(!fs.readFileSync(await dl.path()).includes(Buffer.from(USER + '"')), 'backup is encrypted');
});

step('a viewer signs in, sets up two-factor and can only look', async () => {
  await go('users');
  const pass = 'viewer temporary pass 1';
  await page.getByLabel('Username').fill('viewer1');
  await page.getByLabel('Temporary password').fill(pass);
  await page.getByRole('button', { name: 'Add user' }).click();
  await page.getByRole('dialog').getByText('Added viewer1').waitFor();
  // The viewer, in a browser of their own.
  const vc = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const vp = await vc.newPage();
  vp.setDefaultTimeout(10000);
  vp.on('pageerror', e => problems.push('viewer page error: ' + e.message));
  try {
    await vp.goto(node.url);
    await vp.fill('#username', 'viewer1');
    await vp.fill('#password', pass);
    await vp.click('button[type=submit]');
    await vp.locator('details summary').click();
    const vo = authenticator((await vp.locator('details code').innerText()).replace(/\s+/g, ''));
    await vp.fill('#code', await vo.next());
    await vp.getByRole('button', { name: 'Turn on two-factor sign-in' }).click();
    await vp.locator('input[type=checkbox]').check();
    await vp.getByRole('button', { name: 'Continue' }).click();
    await vp.getByRole('heading', { name: 'Dashboard', exact: true }).waitFor();
    const nav = await vp.locator('nav').innerText();
    for (const hidden of ['Settings', 'Users', 'Cluster', 'Backups', 'Query log', 'Audit log']) assert.ok(!nav.includes(hidden), 'viewer menu has ' + hidden);
    assert.equal(await vp.locator('.d-check').getByRole('button', { name: 'Block', exact: true }).count(), 0, 'viewer gets no Block button');
    // The API refuses changes too, not just the menu.
    const status = await vp.evaluate(async () => (await fetch('/api/v1/settings', { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: '{"filtering_enabled":false}' })).status);
    assert.equal(status, 403);
  } finally {
    await vc.close();
  }
});

step('pages fit a phone screen', async () => {
  await page.setViewportSize({ width: Number(process.env.PHONE_WIDTH) || 390, height: 844 });
  try {
    for (const hash of ['', 'queries', 'settings', 'names', 'analytics', 'performance']) {
      await go(hash);
      await page.waitForTimeout(300);
      const over = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      // Name what sticks out (outside anything meant to scroll sideways).
      const wide = over > 1 ? await page.evaluate(() => [...document.querySelectorAll('main *')]
        .filter(e => e.getBoundingClientRect().right > window.innerWidth + 1 && !e.closest('.scroll'))
        .slice(-3).map(e => e.tagName.toLowerCase() + (e.className ? '.' + String(e.className).split(' ').join('.') : '') + ' "' + (e.textContent || '').trim().slice(0, 40) + '"').join('; ')) : '';
      assert.ok(over <= 1, '#/' + hash + ' scrolls sideways by ' + over + 'px on a phone: ' + wide);
    }
  } finally {
    await page.setViewportSize({ width: 1280, height: 900 });
  }
});

step('sign out and back in with the authenticator', async () => {
  await go('');
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.locator('#username').or(page.locator('input[name=username]')).first().fill(USER);
  await page.locator('#password').or(page.locator('input[name=password]')).first().fill(PASS);
  await page.click('button[type=submit]');
  await page.getByLabel('Authentication code').fill(await otp.next());
  await page.click('button[type=submit]');
  await heading('Dashboard').waitFor();
  // A wrong password is refused.
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.locator('#username').or(page.locator('input[name=username]')).first().fill(USER);
  await page.locator('#password').or(page.locator('input[name=password]')).first().fill('wrong password');
  await page.click('button[type=submit]');
  await page.locator('.msg.err').first().waitFor();
  problems.length = 0; // the 401 is expected
});
