import { test } from 'node:test';
import assert from 'node:assert/strict';
import { score, verdictFor, collectFindings, countBySeverity } from '../src/scoring.js';
import { analyzeEvidence } from '../src/analyze.js';
import { strongEvidence, weakEvidence, unreachableEvidence } from './fixtures/evidence.js';

test('verdict bands map score to grade', () => {
  assert.equal(verdictFor(95).grade, 'A');
  assert.equal(verdictFor(90).grade, 'A');
  assert.equal(verdictFor(89).grade, 'B');
  assert.equal(verdictFor(75).grade, 'B');
  assert.equal(verdictFor(74).grade, 'C');
  assert.equal(verdictFor(60).grade, 'C');
  assert.equal(verdictFor(59).grade, 'D');
  assert.equal(verdictFor(40).grade, 'D');
  assert.equal(verdictFor(39).grade, 'F');
  assert.equal(verdictFor(0).grade, 'F');
});

test('not_evaluable checks are excluded from BOTH numerator and denominator', () => {
  const results = [
    { state: 'clean', earned: 10, weight: 10, findings: [] },
    { state: 'not_evaluable', earned: 0, weight: 0, findings: [] },
    { state: 'finding', earned: 5, weight: 10, findings: [] },
  ];
  const s = score(results);
  // Only the two evaluable checks count: (10+5)/(10+10) = 75.
  assert.equal(s.value, 75);
  assert.equal(s.evaluated, 2);
  assert.equal(s.notEvaluable, 1);
});

test('score is null when nothing is evaluable — never a false 0 or 100', () => {
  const s = score([{ state: 'not_evaluable', earned: 0, weight: 0, findings: [] }]);
  assert.equal(s.value, null);
  assert.equal(s.verdict, null);
});

test('a not_evaluable check cannot drag the score down', () => {
  const clean = score([{ state: 'clean', earned: 10, weight: 10, findings: [] }]);
  const cleanPlusUnknown = score([
    { state: 'clean', earned: 10, weight: 10, findings: [] },
    { state: 'not_evaluable', earned: 0, weight: 0, findings: [] },
  ]);
  assert.equal(clean.value, 100);
  assert.equal(cleanPlusUnknown.value, 100);
});

test('collectFindings flattens and sorts worst-first', () => {
  const results = [
    { id: 'a', category: 'x', findings: [{ rule_id: 'a.low', severity: 'low' }] },
    { id: 'b', category: 'y', findings: [{ rule_id: 'b.crit', severity: 'critical' }] },
  ];
  const flat = collectFindings(results);
  assert.equal(flat[0].severity, 'critical');
  assert.equal(flat[0].check, 'b');
});

test('countBySeverity tallies each bucket', () => {
  const c = countBySeverity([{ severity: 'high' }, { severity: 'high' }, { severity: 'info' }]);
  assert.equal(c.high, 2);
  assert.equal(c.info, 1);
});

test('end to end: strong evidence grades A, weak grades poorly, unreachable is null', () => {
  const strong = analyzeEvidence(strongEvidence());
  assert.equal(strong.verdict.grade, 'A');
  assert.ok(strong.score >= 90);

  const weak = analyzeEvidence(weakEvidence());
  assert.ok(weak.score < 75, `weak scored ${weak.score}`);
  assert.ok(weak.summary.findings_by_severity.critical >= 1); // dangling CNAME

  const gone = analyzeEvidence(unreachableEvidence());
  assert.equal(gone.score, null);
  assert.equal(gone.verdict, null);
  assert.ok(gone.summary.not_evaluable >= 5);
});
