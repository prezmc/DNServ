import { test } from 'node:test';
import assert from 'node:assert/strict';
import { clean, summarize } from './index.js';

test('clean keeps only known fields', () => {
  const r = clean({ report_id: 'a'.repeat(32), week: '2026-W46', schema: 1, version: '1.2.0', channel: 'stable',
    devices: '11-50', features: ['https', 'evil.example'], ip: '1.2.3.4', hostname: 'home' });
  assert.equal(r.devices, '11-50');
  assert.deepEqual(r.features, ['https']);
  assert.equal(r.ip, undefined);
  assert.equal(r.hostname, undefined);
  assert.equal(clean({ week: '2026-W46' }), null);
  assert.equal(clean({ report_id: 'x', week: '2026-W46', schema: 1 }), null);
});

test('summarize hides small countries', () => {
  const rows = [];
  for (let i = 0; i < 6; i++) rows.push({ country: 'US', version: '1.0.0', servers: 2, features: '["https"]', answer_ms_p50: i });
  rows.push({ country: 'IS', version: '1.0.0', servers: 1, features: '[]', answer_ms_p50: 9 });
  const t = summarize('2026-W46', rows);
  assert.equal(t.clusters, 7);
  assert.equal(t.servers, 13);
  assert.deepEqual(t.countries, { US: 6, other: 1 });
  assert.equal(t.features.https, 6);
  assert.equal(t.median.answer_ms_p50, 3);
});
