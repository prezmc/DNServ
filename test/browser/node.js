// Starts a DNServ node from a built binary in a temporary folder, with a
// fake upstream and a local web server for a blocklist.
'use strict';
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { fakeUpstream } = require('./dns');

// Picks n different free ports. All are held open together (TCP and UDP,
// since DNS listens on both) so the same port can't be handed out twice,
// then released just before the node starts. Ports in `avoid` (the fake
// upstream and list server) are skipped. Another process can still grab
// one in between, so startNode retries when the node can't bind.
async function freePorts(n, avoid) {
  const dgram = require('node:dgram');
  const held = [];
  const ports = [];
  try {
    while (ports.length < n) {
      const t = net.createServer();
      await new Promise((resolve, reject) => { t.once('error', reject); t.listen(0, '127.0.0.1', resolve); });
      held.push(t);
      const p = t.address().port;
      if (avoid.includes(p) || ports.includes(p)) continue;
      const u = dgram.createSocket('udp4');
      const ok = await new Promise(resolve => { u.once('error', () => resolve(false)); u.bind(p, '127.0.0.1', () => resolve(true)); });
      if (!ok) { u.close(); continue; }
      held.push(u);
      ports.push(p);
    }
  } finally {
    await Promise.all(held.map(h => new Promise(r => h.close(() => r()))));
  }
  return ports;
}

// The blocklist served to the node: hosts format, with a header date.
const BLOCKLIST = `# Title: Browser test list
# Last modified: 2026-01-02 03:04:05 UTC
0.0.0.0 ads.listed.test
0.0.0.0 tracker.listed.test
`;

async function startNode() {
  for (let attempt = 1; ; attempt++) {
    try {
      return await startNodeOnce();
    } catch (e) {
      if (attempt >= 3 || !/address already in use/.test(e.message)) throw e;
    }
  }
}

async function startNodeOnce() {
  const bin = process.env.DNSERV_BIN || path.resolve(__dirname, '../../dnserv-browser-test');
  if (!fs.existsSync(bin)) throw new Error('build the node first: go build -o ' + bin + ' ./cmd/dnserv (or set DNSERV_BIN)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dnserv-browser-'));
  const up = await fakeUpstream();
  const lists = http.createServer((req, res) => {
    if (req.url === '/list.txt') { res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end(BLOCKLIST); return; }
    res.writeHead(404); res.end();
  });
  await new Promise(r => lists.listen(0, '127.0.0.1', r));
  const [dnsPort, httpPort, clusterPort, dotPort, dohPort] = await freePorts(5, [up.port, lists.address().port]);
  const cfg = path.join(dir, 'dnserv.yaml');
  fs.writeFileSync(cfg, [
    'data_dir: ' + path.join(dir, 'data'),
    'dns:', '  listen: ["127.0.0.1:' + dnsPort + '"]', '  tls:', '    dot_listen: ["127.0.0.1:' + dotPort + '"]', '    doh_listen: ["127.0.0.1:' + dohPort + '"]',
    'http:', '  listen: "127.0.0.1:' + httpPort + '"',
    'cluster:', '  listen: "127.0.0.1:' + clusterPort + '"', '  advertise: "127.0.0.1:' + clusterPort + '"',
    'upstream:', '  mode: forward', '  servers: ["udp://127.0.0.1:' + up.port + '"]',
    'filtering:', '  lists: []', '',
  ].join('\n'));
  const log = [];
  const proc = spawn(bin, ['-config', cfg], { env: { ...process.env, DNSERV_HTTPS: 'off' }, stdio: ['ignore', 'pipe', 'pipe'] });
  const onData = (d) => log.push(d.toString());
  proc.stdout.on('data', onData); proc.stderr.on('data', onData);
  let exited = false;
  proc.once('exit', () => { exited = true; });
  const node = {
    dir, dnsPort, httpPort, url: 'http://127.0.0.1:' + httpPort + '/',
    listURL: 'http://127.0.0.1:' + lists.address().port + '/list.txt',
    upstream: up, log,
    async setupCode() {
      for (let i = 0; i < 100; i++) {
        const m = [...log.join('').matchAll(/setup_code=([A-Z0-9-]+)/g)];
        if (m.length) return m[m.length - 1][1];
        await new Promise(r => setTimeout(r, 200));
      }
      throw new Error('no setup code in the log:\n' + log.join(''));
    },
    async stop() {
      if (!exited) {
        proc.kill('SIGTERM');
        await new Promise(r => { proc.once('exit', r); setTimeout(r, 5000); });
      }
      up.close(); lists.close();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
  // Wait for the dashboard to answer.
  for (let i = 0; i < 100 && !exited; i++) {
    try { const r = await fetch(node.url + 'healthz'); if (r.status < 500) return node; } catch (_) { /* not up yet */ }
    await new Promise(r => setTimeout(r, 200));
  }
  await node.stop();
  throw new Error('node did not start:\n' + log.join(''));
}

function b32(s) {
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of s.replace(/=+$/, '').toUpperCase()) bits += a.indexOf(c).toString(2).padStart(5, '0');
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}

// Authenticator codes. The server accepts each 30-second step once, so
// next() waits for a fresh step when the last one was used.
function authenticator(secret) {
  let last = -1;
  const code = (step) => {
    const c = Buffer.alloc(8);
    c.writeBigUInt64BE(BigInt(step));
    const h = crypto.createHmac('sha1', b32(secret)).update(c).digest();
    const o = h[19] & 15;
    return String((h.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, '0');
  };
  return {
    async next() {
      let step = Math.floor(Date.now() / 30000);
      while (step <= last) { await new Promise(r => setTimeout(r, 1000)); step = Math.floor(Date.now() / 30000); }
      last = step;
      return code(step);
    },
  };
}

module.exports = { startNode, authenticator, BLOCKLIST };
