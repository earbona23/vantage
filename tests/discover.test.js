import { test } from 'node:test';
import assert from 'node:assert/strict';
import { discoverSubdomains, parseCrtShRows } from '../src/discover.js';
import { checkTakeover } from '../src/checks/takeover.js';
import { makeHttp } from './fixtures/fake-clients.js';

// A recorded crt.sh JSON response (trimmed shape: crt.sh returns objects with
// name_value, sometimes multi-line, sometimes wildcards).
const CRT_SH_FIXTURE = JSON.stringify([
  { name_value: 'www.acme.test\napi.acme.test' },
  { name_value: '*.acme.test' },
  { name_value: 'shop.acme.test' },
  { name_value: 'api.acme.test' }, // duplicate
  { name_value: 'acme.test' }, // apex — excluded
  { name_value: 'unrelated.example.com' }, // different domain — excluded
  { common_name: 'legacy.acme.test' },
]);

test('parseCrtShRows extracts unique real subdomains, dropping apex/wildcards/foreign', () => {
  const r = parseCrtShRows(JSON.parse(CRT_SH_FIXTURE), 'acme.test');
  assert.equal(r.evaluable, true);
  assert.deepEqual(r.names, ['api.acme.test', 'legacy.acme.test', 'shop.acme.test', 'www.acme.test']);
  assert.ok(!r.names.includes('acme.test'));
  assert.ok(!r.names.includes('unrelated.example.com'));
});

test('parseCrtShRows honours the max cap and flags truncation', () => {
  const r = parseCrtShRows(JSON.parse(CRT_SH_FIXTURE), 'acme.test', 2);
  assert.equal(r.names.length, 2);
  assert.equal(r.truncated, true);
  assert.equal(r.total, 4);
});

test('discoverSubdomains reads crt.sh via the injected client', async () => {
  const http = makeHttp({
    ['https://crt.sh/?q=%25.acme.test&output=json']: { status: 200, body: CRT_SH_FIXTURE },
  });
  const r = await discoverSubdomains('acme.test', http);
  assert.equal(r.evaluable, true);
  assert.equal(r.source, 'crt.sh');
  assert.ok(r.names.includes('shop.acme.test'));
});

test('discoverSubdomains is NOT EVALUABLE when crt.sh does not answer', async () => {
  const http = makeHttp({}); // no crt.sh fixture -> unreachable
  const r = await discoverSubdomains('acme.test', http);
  assert.equal(r.evaluable, false);
  assert.ok(r.error);
  assert.deepEqual(r.names, []);
});

test('discoverSubdomains is NOT EVALUABLE on a non-JSON (e.g. truncated/rate-limited) body', async () => {
  const http = makeHttp({
    ['https://crt.sh/?q=%25.acme.test&output=json']: { status: 200, body: '<html>rate limited</html>' },
  });
  const r = await discoverSubdomains('acme.test', http);
  assert.equal(r.evaluable, false);
  assert.match(r.error, /non-JSON/);
});

test('takeover: crt.sh unavailable + no dangling found => NOT EVALUABLE, never a clean bill', () => {
  const r = checkTakeover({
    subdomains: {
      evaluable: true,
      probed: ['www.acme.test'],
      entries: {}, // no CNAMEs among the seed hosts
      discovery: { source: 'crt.sh', evaluable: false, error: 'crt.sh returned status 502' },
    },
  });
  assert.equal(r.state, 'not_evaluable');
  assert.match(r.reason, /crt\.sh/);
});

test('takeover: a real dangling CNAME is reported even when discovery failed', () => {
  const r = checkTakeover({
    subdomains: {
      evaluable: true,
      probed: ['shop.acme.test'],
      entries: { 'shop.acme.test': { cname: 'x.myshopify.com', targetResolves: true, body: 'Sorry, this shop is currently unavailable' } },
      discovery: { source: 'crt.sh', evaluable: false, error: 'timeout' },
    },
  });
  assert.equal(r.state, 'finding');
  assert.equal(r.findings[0].rule_id, 'takeover.dangling_cname');
});
