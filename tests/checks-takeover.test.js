import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkTakeover } from '../src/checks/takeover.js';
import { matchTakeover } from '../src/fingerprints.js';

test('matchTakeover matches a Shopify unclaimed-page body fingerprint', () => {
  const fp = matchTakeover('shop.myshopify.com', 'Sorry, this shop is currently unavailable', true);
  assert.ok(fp);
  assert.equal(fp.service, 'Shopify');
});

test('matchTakeover uses NXDOMAIN signal for Azure', () => {
  assert.ok(matchTakeover('foo.azurewebsites.net', '', false));
  // Azure with a resolving target and no body signal is NOT a takeover.
  assert.equal(matchTakeover('foo.azurewebsites.net', '', true), null);
});

test('matchTakeover ignores a healthy CNAME', () => {
  assert.equal(matchTakeover('cdn.cloudflare.net', 'welcome', true), null);
});

test('takeover check flags a dangling CNAME as critical and zeroes the check', () => {
  const r = checkTakeover({
    subdomains: {
      evaluable: true,
      probed: ['shop.x.com'],
      entries: { 'shop.x.com': { cname: 'x.myshopify.com', targetResolves: true, body: 'Sorry, this shop is currently unavailable' } },
    },
  });
  assert.equal(r.state, 'finding');
  assert.equal(r.earned, 0);
  assert.equal(r.findings[0].rule_id, 'takeover.dangling_cname');
  assert.equal(r.findings[0].severity, 'critical');
});

test('takeover check is clean when CNAMEs are healthy', () => {
  const r = checkTakeover({
    subdomains: { evaluable: true, probed: ['www.x.com'], entries: { 'www.x.com': { cname: 'x.com.cdn.cloudflare.net', targetResolves: true, body: 'ok' } } },
  });
  assert.equal(r.state, 'clean');
  assert.equal(r.earned, r.weight);
});

test('takeover check is NOT EVALUABLE when subdomains could not be resolved', () => {
  const r = checkTakeover({ subdomains: { evaluable: false, probed: [], entries: {} } });
  assert.equal(r.state, 'not_evaluable');
  assert.equal(r.weight, 0);
});
