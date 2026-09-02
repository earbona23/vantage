import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeBatch, diffReports } from '../src/pro.js';
import { analyzeEvidence } from '../src/analyze.js';
import { strongEvidence, weakEvidence } from './fixtures/evidence.js';

test('analyzeBatch produces one report per evidence object', () => {
  const reports = analyzeBatch([strongEvidence('a.example'), weakEvidence('b.example')]);
  assert.equal(reports.length, 2);
  assert.equal(reports[0].domain, 'a.example');
  assert.equal(reports[1].domain, 'b.example');
});

test('diffReports reports a newly appeared finding and score drop', () => {
  const before = analyzeEvidence(strongEvidence('x.example'), { now: new Date('2026-01-01') });
  // Same domain, but now SPF is gone: a new finding should appear.
  const degraded = strongEvidence('x.example');
  degraded.spf = [];
  const after = analyzeEvidence(degraded, { now: new Date('2026-02-01') });

  const d = diffReports(before, after);
  assert.equal(d.changed, true);
  assert.ok(d.appeared.some((f) => f.rule_id === 'spf.missing'));
  assert.ok(d.score_delta < 0);
});

test('diffReports reports a resolved finding and score rise', () => {
  const weak = analyzeEvidence(weakEvidence('y.example'), { now: new Date('2026-01-01') });
  const fixed = weakEvidence('y.example');
  fixed.spf = ['v=spf1 -all'];
  const after = analyzeEvidence(fixed, { now: new Date('2026-02-01') });

  const d = diffReports(weak, after);
  assert.ok(d.resolved.some((f) => f.rule_id === 'spf.missing'));
  assert.ok(d.score_delta > 0);
});

test('diffReports on identical reports reports no change', () => {
  const a = analyzeEvidence(strongEvidence('z.example'), { now: new Date('2026-01-01') });
  const b = analyzeEvidence(strongEvidence('z.example'), { now: new Date('2026-02-01') });
  const d = diffReports(a, b);
  assert.equal(d.changed, false);
  assert.equal(d.appeared.length, 0);
  assert.equal(d.resolved.length, 0);
});

test('diffReports flags a check state flip (clean -> not evaluable)', () => {
  const up = strongEvidence('w.example');
  const before = analyzeEvidence(up, { now: new Date('2026-01-01') });
  const down = strongEvidence('w.example');
  down.http.root = { ok: false, error: 'ENOTFOUND', headers: {} };
  const after = analyzeEvidence(down, { now: new Date('2026-02-01') });
  const d = diffReports(before, after);
  assert.ok(d.state_changes.some((s) => s.check === 'headers' && s.to === 'not_evaluable'));
});
