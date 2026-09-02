import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkMx } from '../src/checks/mx.js';
import { checkMtaSts } from '../src/checks/mtasts.js';
import { checkTlsRpt } from '../src/checks/tlsrpt.js';
import { checkDnssec } from '../src/checks/dnssec.js';
import { checkCaa } from '../src/checks/caa.js';

const withMx = { mx: { present: true, records: [{ exchange: 'm', priority: 1 }] } };
const noMx = { mx: { present: false } };

test('MTA-STS is NOT EVALUABLE when there is no MX', () => {
  const r = checkMtaSts({ ...noMx, mtasts: { record: [], policy: {} } });
  assert.equal(r.state, 'not_evaluable');
  assert.equal(r.weight, 0); // excluded from score entirely
});

test('MTA-STS missing (with MX) is a medium finding worth zero', () => {
  const r = checkMtaSts({ ...withMx, mtasts: { record: [], policy: { fetched: false } } });
  assert.equal(r.state, 'finding');
  assert.equal(r.earned, 0);
  assert.equal(r.findings[0].rule_id, 'mtasts.missing');
});

test('MTA-STS record present but policy unreachable is flagged', () => {
  const r = checkMtaSts({ ...withMx, mtasts: { record: ['v=STSv1; id=1'], policy: { fetched: false, error: '404' } } });
  assert.ok(r.findings.some((f) => f.rule_id === 'mtasts.policy_unreachable'));
});

test('MTA-STS enforce mode is clean; testing mode deducts', () => {
  const enforce = checkMtaSts({ ...withMx, mtasts: { record: ['v=STSv1'], policy: { fetched: true, body: 'version: STSv1\nmode: enforce' } } });
  assert.equal(enforce.state, 'clean');
  const testing = checkMtaSts({ ...withMx, mtasts: { record: ['v=STSv1'], policy: { fetched: true, body: 'version: STSv1\nmode: testing' } } });
  assert.ok(testing.findings.some((f) => f.rule_id === 'mtasts.mode_testing'));
  assert.ok(testing.earned < enforce.earned);
});

test('TLS-RPT not evaluable without MX, missing-with-MX is a low finding', () => {
  assert.equal(checkTlsRpt({ ...noMx, tlsrpt: [] }).state, 'not_evaluable');
  const r = checkTlsRpt({ ...withMx, tlsrpt: [] });
  assert.equal(r.findings[0].rule_id, 'tlsrpt.missing');
  const ok = checkTlsRpt({ ...withMx, tlsrpt: ['v=TLSRPTv1; rua=mailto:a@b'] });
  assert.equal(ok.state, 'clean');
});

test('DNSSEC signed is clean; unsigned is medium; unknown is not evaluable', () => {
  assert.equal(checkDnssec({ dnssec: { evaluable: true, ad: true, ds: true } }).state, 'clean');
  const unsigned = checkDnssec({ dnssec: { evaluable: true, ad: false, ds: false } });
  assert.equal(unsigned.earned, 0);
  assert.equal(unsigned.findings[0].rule_id, 'dnssec.unsigned');
  assert.equal(checkDnssec({ dnssec: { evaluable: false } }).state, 'not_evaluable');
});

test('DNSSEC DS present but no AD is a broken-chain finding', () => {
  const r = checkDnssec({ dnssec: { evaluable: true, ad: false, ds: true } });
  assert.equal(r.findings[0].rule_id, 'dnssec.broken_chain');
});

test('CAA absent is a low finding; present is clean', () => {
  const absent = checkCaa({ caa: { evaluable: true, records: [] } });
  assert.equal(absent.findings[0].rule_id, 'caa.absent');
  const present = checkCaa({ caa: { evaluable: true, records: [{ issue: 'letsencrypt.org' }, { issuewild: ';' }] } });
  assert.equal(present.state, 'clean');
  assert.equal(present.earned, present.weight);
});
