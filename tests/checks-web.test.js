import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkHeaders } from '../src/checks/headers.js';
import { checkSecurityTxt } from '../src/checks/securitytxt.js';
import { checkTls } from '../src/checks/tls.js';

const fullHeaders = {
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'geolocation=()',
};

test('headers: all present is clean and full marks', () => {
  const r = checkHeaders({ http: { root: { ok: true, status: 200, headers: fullHeaders } } });
  assert.equal(r.state, 'clean');
  assert.equal(r.earned, r.weight);
});

test('headers: unreachable site is NOT EVALUABLE, not a pile of failures', () => {
  const r = checkHeaders({ http: { root: { ok: false, error: 'ENOTFOUND' } } });
  assert.equal(r.state, 'not_evaluable');
  assert.equal(r.weight, 0);
});

test('headers: missing HSTS is high, missing CSP is medium', () => {
  const r = checkHeaders({ http: { root: { ok: true, status: 200, headers: {} } } });
  const ids = r.findings.map((f) => f.rule_id);
  assert.ok(ids.includes('headers.hsts_missing'));
  assert.ok(ids.includes('headers.csp_missing'));
  assert.ok(ids.includes('headers.framing_missing'));
  assert.ok(r.earned < r.weight);
});

test('headers: missing ONLY HSTS still costs points (deduction is real)', () => {
  const h = { ...fullHeaders };
  delete h['strict-transport-security'];
  const r = checkHeaders({ http: { root: { ok: true, status: 200, headers: h } } });
  assert.ok(r.findings.some((f) => f.rule_id === 'headers.hsts_missing'));
  // Everything else is present, so any shortfall from full marks is the HSTS
  // deduction alone. If it were free, earned would equal weight.
  assert.equal(r.earned, r.weight - 5);
});

test('headers: CSP frame-ancestors alone satisfies clickjacking protection', () => {
  const h = { ...fullHeaders };
  delete h['x-frame-options'];
  const r = checkHeaders({ http: { root: { ok: true, status: 200, headers: h } } });
  assert.ok(!r.findings.some((f) => f.rule_id === 'headers.framing_missing'));
});

test('headers: short HSTS max-age is flagged as weak', () => {
  const h = { ...fullHeaders, 'strict-transport-security': 'max-age=3600' };
  const r = checkHeaders({ http: { root: { ok: true, status: 200, headers: h } } });
  assert.ok(r.findings.some((f) => f.rule_id === 'headers.hsts_weak'));
});

test('headers: version disclosure is info only (no score change)', () => {
  const r = checkHeaders({ http: { root: { ok: true, status: 200, headers: { ...fullHeaders, 'x-powered-by': 'PHP/7.2' } } } });
  const info = r.findings.find((f) => f.rule_id === 'headers.version_disclosure');
  assert.equal(info.severity, 'info');
  assert.equal(r.earned, r.weight); // info does not deduct
});

test('security.txt present and valid is clean', () => {
  const r = checkSecurityTxt({
    http: { root: { ok: true }, securitytxt: { ok: true, body: 'Contact: mailto:s@x.com\nExpires: 2099-01-01T00:00:00Z' } },
  });
  assert.equal(r.state, 'clean');
});

test('security.txt expired is a medium finding', () => {
  const r = checkSecurityTxt(
    { http: { root: { ok: true }, securitytxt: { ok: true, body: 'Contact: mailto:s@x.com\nExpires: 2000-01-01T00:00:00Z' } } },
    new Date('2026-01-01T00:00:00Z')
  );
  assert.ok(r.findings.some((f) => f.rule_id === 'securitytxt.expired' && f.severity === 'medium'));
});

test('security.txt not evaluable when the whole site is down', () => {
  const r = checkSecurityTxt({ http: { root: { ok: false }, securitytxt: { ok: false } } });
  assert.equal(r.state, 'not_evaluable');
});

test('security.txt missing (site up) is a low finding', () => {
  const r = checkSecurityTxt({ http: { root: { ok: true }, securitytxt: { ok: false } } });
  assert.equal(r.findings[0].rule_id, 'securitytxt.missing');
});

test('TLS expired is critical; obsolete protocol is high; handshake failure not evaluable', () => {
  const expired = checkTls({ tls: { evaluable: true, authorized: true, protocol: 'TLSv1.3', daysToExpiry: -2 } });
  assert.ok(expired.findings.some((f) => f.rule_id === 'tls.expired' && f.severity === 'critical'));

  const old = checkTls({ tls: { evaluable: true, authorized: true, protocol: 'TLSv1', daysToExpiry: 100 } });
  assert.ok(old.findings.some((f) => f.rule_id === 'tls.obsolete_protocol'));

  assert.equal(checkTls({ tls: { evaluable: false } }).state, 'not_evaluable');
});

test('TLS untrusted chain is a high finding', () => {
  const r = checkTls({ tls: { evaluable: true, authorized: false, authorizationError: 'SELF_SIGNED', protocol: 'TLSv1.2', daysToExpiry: 100 } });
  assert.ok(r.findings.some((f) => f.rule_id === 'tls.untrusted_chain'));
});
