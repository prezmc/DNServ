// Minimal DNS over UDP for the browser tests: a client to ask the node,
// and a fake upstream server that answers every A lookup.
'use strict';
const dgram = require('node:dgram');

function encodeName(name) {
  const parts = name.replace(/\.$/, '').split('.');
  const bufs = parts.map(p => Buffer.concat([Buffer.from([p.length]), Buffer.from(p)]));
  return Buffer.concat([...bufs, Buffer.from([0])]);
}

function query(id, name, type) {
  const head = Buffer.alloc(12);
  head.writeUInt16BE(id, 0);
  head.writeUInt16BE(0x0100, 2); // recursion desired
  head.writeUInt16BE(1, 4);
  const q = Buffer.alloc(4);
  q.writeUInt16BE(type, 0);
  q.writeUInt16BE(1, 2);
  return Buffer.concat([head, encodeName(name), q]);
}

// skipName moves past a (possibly compressed) name.
function skipName(b, off) {
  for (;;) {
    const l = b[off];
    if (l === 0) return off + 1;
    if ((l & 0xc0) === 0xc0) return off + 2;
    off += l + 1;
  }
}

function readName(b, off) {
  const labels = [];
  for (;;) {
    const l = b[off];
    if (l === 0) break;
    if ((l & 0xc0) === 0xc0) { labels.push(readName(b, ((l & 0x3f) << 8) | b[off + 1])); break; }
    labels.push(b.slice(off + 1, off + 1 + l).toString());
    off += l + 1;
  }
  return labels.join('.');
}

// parse returns the response code and the A record addresses.
function parse(b) {
  const rcode = b.readUInt16BE(2) & 0xf;
  const qd = b.readUInt16BE(4), an = b.readUInt16BE(6);
  let off = 12;
  for (let i = 0; i < qd; i++) off = skipName(b, off) + 4;
  const a = [];
  for (let i = 0; i < an; i++) {
    off = skipName(b, off);
    const type = b.readUInt16BE(off), len = b.readUInt16BE(off + 8);
    if (type === 1 && len === 4) a.push([...b.slice(off + 10, off + 14)].join('.'));
    off += 10 + len;
  }
  return { rcode, a };
}

const RCODES = { 0: 'NOERROR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED' };

// lookup asks a DNS server for name's A records.
function lookup(port, name, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket('udp4');
    const id = Math.floor(Math.random() * 65535);
    const t = setTimeout(() => { s.close(); reject(new Error('DNS timeout for ' + name)); }, timeoutMs);
    s.on('message', (m) => {
      if (m.readUInt16BE(0) !== id) return;
      clearTimeout(t); s.close();
      const r = parse(m);
      resolve({ rcode: RCODES[r.rcode] || String(r.rcode), a: r.a });
    });
    s.send(query(id, name, 1), port, '127.0.0.1');
  });
}

// fakeUpstream answers A lookups with 203.0.113.7 (TTL 300) and anything
// else with an empty answer. Names under fail.test get SERVFAIL.
function fakeUpstream() {
  return new Promise((resolve) => {
    const s = dgram.createSocket('udp4');
    const seen = [];
    s.on('message', (m, rinfo) => {
      const name = readName(m, 12);
      const qend = skipName(m, 12);
      const type = m.readUInt16BE(qend);
      seen.push(name);
      const head = Buffer.from(m.slice(0, 12));
      const fail = /(^|\.)fail\.test$/.test(name);
      head.writeUInt16BE(0x8180 | (fail ? 2 : 0), 2);
      head.writeUInt16BE(1, 4);
      head.writeUInt16BE(type === 1 && !fail ? 1 : 0, 6);
      head.writeUInt16BE(0, 8); head.writeUInt16BE(0, 10);
      const parts = [head, m.slice(12, qend + 4)];
      if (type === 1 && !fail) {
        const rr = Buffer.alloc(16);
        rr.writeUInt16BE(0xc00c, 0); rr.writeUInt16BE(1, 2); rr.writeUInt16BE(1, 4);
        rr.writeUInt32BE(300, 6); rr.writeUInt16BE(4, 10);
        Buffer.from([203, 0, 113, 7]).copy(rr, 12);
        parts.push(rr);
      }
      s.send(Buffer.concat(parts), rinfo.port, rinfo.address);
    });
    s.bind(0, '127.0.0.1', () => resolve({ port: s.address().port, seen, close: () => s.close() }));
  });
}

module.exports = { lookup, fakeUpstream };
