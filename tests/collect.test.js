import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collect } from '../src/collect.js';
import { analyzeEvidence } from '../src/analyze.js';
import { makeDns, makeHttp, makeTls } from './fixtures/fake-clients.js';

// A full recorded fixture for one domain, exercising the collector end to end
// with zero network. This is the "recorded fixture" the task asks for.
function fixtureDeps(domain = 'acme.test') {
  const dns = makeDns({
    txt: {
      [domain]: ['v=spf1 include:_spf.google.com -all'],
      [`_dmarc.${domain}`]: ['v=DMARC1; p=reject; rua=mailto:d@acme.test'],
      [`_smtp._tls.${domain}`]: ['v=TLSRPTv1; rua=mailto:t@acme.test'],
      [`_mta-sts.${domain}`]: ['v=STSv1; id=20260101'],
      [`google._domainkey.${domain}`]: ['v=DKIM1; k=rsa; p=MIIBpub'],
    },
    mx: { [domain]: [{ exchange: 'aspmx.l.google.com', priority: 1 }] },
    caa: { [domain]: [{ critical: 0, issue: 'letsencrypt.org' }] },
    ns: { [domain]: ['ns1', 'ns2'] },
    cname: {
      [`shop.${domain}`]: ['acme.myshopify.com'],
    },
    doh: {
      [`${domain}|DS`]: { Status: 0, AD: true, Answer: [{ type: 43, data: '...' }] },
      ['acme.myshopify.com|A']: { Status: 0, Answer: [{ type: 1, data: '1.2.3.4' }] },
    },
  });

  const http = makeHttp({
    [`https://${domain}/`]: {
      status: 200,
      headers: {
        'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
        'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=()',
      },
    },
    [`https://${domain}/.well-known/security.txt`]: {
      status: 200,
      body: 'Contact: mailto:security@acme.test\nExpires: 2099-01-01T00:00:00Z',
    },
    [`https://mta-sts.${domain}/.well-known/mta-sts.txt`]: {
      status: 200,
      body: 'version: STSv1\nmode: enforce\nmx: aspmx.l.google.com\nmax_age: 604800',
    },
    [`https://shop.${domain}/`]: { status: 200, body: 'Sorry, this shop is currently unavailable' },
  });

  const tls = makeTls({
    [domain]: { authorized: true, protocol: 'TLSv1.3', daysToExpiry: 45 },
  });

  return { dns, http, tls };
}

test('collector builds evidence from fake clients with no network', async () => {
  const deps = fixtureDeps();
  const ev = await collect('acme.test', deps, { subdomains: ['shop'] });

  assert.deepEqual(ev.spf, ['v=spf1 include:_spf.google.com -all']);
  assert.equal(ev.dmarc.length, 1);
  assert.equal(ev.mx.present, true);
  assert.equal(ev.dnssec.evaluable, true);
  assert.equal(ev.dnssec.ds, true);
  assert.equal(ev.dnssec.ad, true);
  assert.equal(ev.mtasts.policy.fetched, true);
  assert.equal(ev.dkim.google.length, 1);
  assert.ok(ev.subdomains.entries['shop.acme.test']);
  assert.equal(ev.subdomains.entries['shop.acme.test'].cname, 'acme.myshopify.com');
});

test('collector output flows through analyze and catches the dangling shop CNAME', async () => {
  const deps = fixtureDeps();
  const ev = await collect('acme.test', deps, { subdomains: ['shop'] });
  const report = analyzeEvidence(ev);
  assert.ok(report.findings.some((f) => f.rule_id === 'takeover.dangling_cname'));
});

test('collector marks DNSSEC not evaluable when the DoH query fails', async () => {
  const deps = fixtureDeps();
  // Remove the DS fixture so doh rejects.
  const dns = makeDns({ txt: {}, mx: {}, caa: {}, ns: {}, cname: {}, doh: {} });
  const ev = await collect('nowhere.test', { dns, http: deps.http, tls: deps.tls }, { subdomains: [] });
  assert.equal(ev.dnssec.evaluable, false);
});

test('discovery finds a host NOT in the seed list and probes it for takeover', async () => {
  const domain = 'acme.test';
  const deps = fixtureDeps(domain);
  // Add a crt.sh fixture that surfaces a host the caller never named, pointing
  // at an unclaimed Heroku app (NXDOMAIN target => takeover signal).
  const http = makeHttp({
    [`https://${domain}/`]: { status: 200, headers: {} },
    [`https://${domain}/.well-known/security.txt`]: { status: 404 },
    ['https://crt.sh/?q=%25.acme.test&output=json']: {
      status: 200,
      body: JSON.stringify([{ name_value: 'legacy.acme.test' }, { name_value: 'www.acme.test' }]),
    },
    [`https://legacy.${domain}/`]: { status: 404, body: 'No such app' },
  });
  const dns = makeDns({
    txt: { [domain]: ['v=spf1 -all'] },
    mx: {},
    caa: {},
    ns: { [domain]: ['ns1'] },
    cname: { [`legacy.${domain}`]: ['ghost-app.herokuapp.com'] },
    doh: {
      [`${domain}|DS`]: { Status: 0, AD: false, Answer: [] },
      ['ghost-app.herokuapp.com|A']: { Status: 3, Answer: [] }, // NXDOMAIN target
    },
  });

  const ev = await collect(domain, { dns, http, tls: deps.tls }, { subdomains: [] });
  assert.equal(ev.discovery.evaluable, true);
  assert.ok(ev.discovery.names.includes('legacy.acme.test'));

  const report = analyzeEvidence(ev);
  const takeover = report.findings.find((f) => f.rule_id === 'takeover.dangling_cname');
  assert.ok(takeover, 'discovered dangling Heroku host should be flagged');
  assert.match(takeover.message, /legacy\.acme\.test/);
});

test('collect marks discovery NOT EVALUABLE when crt.sh is unreachable', async () => {
  const domain = 'acme.test';
  const deps = fixtureDeps(domain);
  const ev = await collect(domain, deps, { subdomains: ['shop'] }); // fixtureDeps http has no crt.sh
  assert.equal(ev.discovery.evaluable, false);
  assert.ok(ev.discovery.error);
});

test('a hard DNS failure (SERVFAIL) becomes not-evaluable evidence, not empty-clean', async () => {
  // caa fixture value null => the fake throws SERVFAIL.
  const dns = makeDns({ txt: {}, mx: {}, caa: { 'x.test': null }, ns: {}, cname: {}, doh: {} });
  const http = makeHttp({});
  const tls = makeTls({});
  const ev = await collect('x.test', { dns, http, tls }, { subdomains: [] });
  assert.equal(ev.caa.evaluable, false);
});
