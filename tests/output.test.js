import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeEvidence } from '../src/analyze.js';
import { renderTerminal } from '../src/output/terminal.js';
import { renderJson } from '../src/output/json.js';
import { renderSarif } from '../src/output/sarif.js';
import { renderMarkdown } from '../src/output/markdown.js';
import { renderJsonl } from '../src/output/jsonl.js';
import { renderHtml } from '../src/output/html.js';
import { strongEvidence, weakEvidence, unreachableEvidence } from './fixtures/evidence.js';

const weak = analyzeEvidence(weakEvidence());
const strong = analyzeEvidence(strongEvidence());
const gone = analyzeEvidence(unreachableEvidence());

test('terminal output shows verdict, score bar and the check ledger', () => {
  const out = renderTerminal(weak);
  assert.match(out, /vantage report/);
  assert.match(out, /Posture score:/);
  assert.match(out, /Check ledger:/);
  assert.match(out, /takeover/);
});

test('terminal output for an unreachable domain says NOT EVALUABLE, never a score', () => {
  const out = renderTerminal(gone);
  assert.match(out, /NOT EVALUABLE/);
  assert.doesNotMatch(out, /Posture score:/);
});

test('json output is valid and round-trips the contract fields', () => {
  const parsed = JSON.parse(renderJson(weak));
  assert.equal(parsed.schema, '1.0');
  assert.equal(parsed.tool, 'vantage');
  assert.ok(Array.isArray(parsed.findings));
  assert.ok(parsed.summary.findings_by_severity.critical >= 1);
});

test('sarif output is valid 2.1.0 with rules and results', () => {
  const s = JSON.parse(renderSarif(weak));
  assert.equal(s.version, '2.1.0');
  const run = s.runs[0];
  assert.equal(run.tool.driver.name, 'vantage');
  assert.ok(run.tool.driver.rules.length > 0);
  assert.ok(run.results.length > 0);
  assert.equal(run.results[0].level, 'error'); // critical/high -> error
});

test('markdown output has a findings table', () => {
  const md = renderMarkdown(weak);
  assert.match(md, /## Findings/);
  assert.match(md, /\| Severity \| Rule \|/);
});

test('jsonl output is one JSON object per line', () => {
  const jsonl = renderJsonl([weak, strong]);
  const lines = jsonl.split('\n');
  assert.equal(lines.length, 2);
  assert.equal(JSON.parse(lines[0]).domain, weak.domain);
});

test('html output is a self-contained document with no external resource loads', () => {
  const html = renderHtml(weak);
  assert.match(html, /<!doctype html>/i);
  assert.match(html, /vantage report/);
  // No external scripts or stylesheets — offline by construction.
  assert.doesNotMatch(html, /<script/i);
  assert.doesNotMatch(html, /https?:\/\/[^"']*\.(js|css)/i);
});

test('html escapes angle brackets from findings', () => {
  const ev = weakEvidence();
  ev.http.root.headers = { server: '<script>x</script>' };
  const html = renderHtml(analyzeEvidence(ev));
  assert.doesNotMatch(html, /<script>x<\/script>/);
});
