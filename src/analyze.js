import { collect } from './collect.js';
import { runChecks } from './checks/index.js';
import { score, collectFindings, countBySeverity } from './scoring.js';
import { normaliseDomain } from './parse.js';
import { createDnsClient } from './net/dns.js';
import { createHttpClient } from './net/http.js';
import { createTlsClient } from './net/tls.js';

export const SCHEMA_VERSION = '1.0';
export const TOOL_VERSION = '0.1.0';

// Build a report from an already-collected evidence object. Pure: no network.
// This is the seam the tests drive with hand-built or fixture evidence.
export function analyzeEvidence(evidence, { now = new Date(), includeRaw = false } = {}) {
  const checks = runChecks(evidence, now);
  const scored = score(checks);
  const findings = collectFindings(checks);

  // The three states, counted separately and shown — never collapsed.
  const checksByState = { finding: 0, clean: 0, not_evaluable: 0 };
  for (const c of checks) checksByState[c.state] = (checksByState[c.state] || 0) + 1;

  const disc = evidence.discovery || null;

  const report = {
    schema: SCHEMA_VERSION,
    tool: 'vantage',
    tool_version: TOOL_VERSION,
    domain: evidence.domain,
    scanned_at: now.toISOString(),
    score: scored.value,
    verdict: scored.verdict,
    discovery: disc
      ? { source: disc.source, evaluable: disc.evaluable, discovered: disc.total, truncated: !!disc.truncated, error: disc.error || null, names: disc.names || [] }
      : null,
    summary: {
      checks_by_state: checksByState,
      evaluated: scored.evaluated,
      not_evaluable: scored.notEvaluable,
      points: { earned: scored.earned, possible: scored.weight },
      findings_by_severity: countBySeverity(findings),
    },
    checks: checks.map((c) => ({
      id: c.id,
      title: c.title,
      category: c.category,
      state: c.state,
      weight: c.weight,
      earned: c.earned,
      reason: c.reason || null,
      findings: c.findings,
    })),
    findings,
  };

  // --raw / --all: attach the full recorded evidence so nothing can hide behind
  // the score. Every record, header, and probed host is here, unsummarised.
  if (includeRaw) report.raw = evidence;

  return report;
}

// Full scan: collect evidence over the network, then analyze. deps are
// injectable so callers (and tests) can supply fakes.
export async function scanDomain(rawDomain, { deps, now, subdomains, selectors, discover, includeRaw = false } = {}) {
  const domain = normaliseDomain(rawDomain);
  if (!domain) throw new Error('A domain is required.');

  const clients = deps || {
    dns: createDnsClient(),
    http: createHttpClient(),
    tls: createTlsClient(),
  };

  const evidence = await collect(domain, clients, { subdomains, selectors, discover });
  return analyzeEvidence(evidence, { now: now || new Date(), includeRaw });
}
