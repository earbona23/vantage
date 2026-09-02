import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkSpf } from '../src/checks/spf.js';
import { checkDmarc } from '../src/checks/dmarc.js';
import { checkDkim } from '../src/checks/dkim.js';
import { checkBimi } from '../src/checks/bimi.js';

function ruleIds(r) {
  return r.findings.map((f) => f.rule_id);
}

test('SPF missing is a high finding worth zero', () => {
  const r = checkSpf({ spf: [] });
  assert.equal(r.state, 'finding');
  assert.equal(r.earned, 0);
  assert.ok(ruleIds(r).includes('spf.missing'));
});

test('SPF +all is critical and zeroed even though a record exists', () => {
  const r = checkSpf({ spf: ['v=spf1 +all'] });
  assert.equal(r.earned, 0);
  assert.equal(r.findings[0].severity, 'critical');
  assert.ok(ruleIds(r).includes('spf.pass_all'));
});

test('SPF -all is clean and full marks', () => {
  const r = checkSpf({ spf: ['v=spf1 include:_spf.google.com -all'] });
  assert.equal(r.state, 'clean');
  assert.equal(r.earned, r.weight);
});

test('SPF ~all is accepted with a small deduction, no finding', () => {
  const r = checkSpf({ spf: ['v=spf1 ~all'] });
  assert.equal(r.state, 'clean');
  assert.ok(r.earned < r.weight && r.earned > 0);
});

test('multiple SPF records is a permerror finding', () => {
  const r = checkSpf({ spf: ['v=spf1 -all', 'v=spf1 ~all'] });
  assert.ok(ruleIds(r).includes('spf.multiple'));
  assert.ok(r.earned < r.weight);
});

test('DMARC reject scores full, none is a medium finding', () => {
  const reject = checkDmarc({ dmarc: ['v=DMARC1; p=reject; rua=mailto:a@b.com'] });
  assert.equal(reject.state, 'clean');
  assert.equal(reject.earned, reject.weight);

  const none = checkDmarc({ dmarc: ['v=DMARC1; p=none; rua=mailto:a@b.com'] });
  assert.equal(none.state, 'finding');
  assert.ok(none.findings.some((f) => f.rule_id === 'dmarc.policy_none' && f.severity === 'medium'));
  assert.ok(none.earned < reject.earned);
});

test('DMARC missing is high and zero', () => {
  const r = checkDmarc({ dmarc: [] });
  assert.equal(r.earned, 0);
  assert.ok(ruleIds(r).includes('dmarc.missing'));
});

test('DMARC pct<100 and no rua both deduct', () => {
  const r = checkDmarc({ dmarc: ['v=DMARC1; p=reject; pct=50'] });
  assert.ok(ruleIds(r).includes('dmarc.partial_pct'));
  assert.ok(ruleIds(r).includes('dmarc.no_rua'));
  assert.ok(r.earned < r.weight);
});

test('DKIM found at a common selector is clean', () => {
  const r = checkDkim({ dkim: { google: ['v=DKIM1; k=rsa; p=MIIB'] } });
  assert.equal(r.state, 'clean');
  assert.equal(r.earned, r.weight);
});

test('DKIM with no common selector is inconclusive info, not a failure', () => {
  const r = checkDkim({ dkim: {} });
  assert.equal(r.state, 'finding');
  assert.equal(r.findings[0].severity, 'info');
  assert.ok(r.earned > 0); // not penalised as if confirmed-broken
});

test('BIMI presence and absence both avoid a real (non-info) finding', () => {
  const present = checkBimi({ bimi: ['v=BIMI1; l=https://x/logo.svg'] });
  assert.equal(present.state, 'clean');
  const absent = checkBimi({ bimi: [] });
  assert.equal(absent.findings[0].severity, 'info');
});
