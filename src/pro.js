import { scanDomain, analyzeEvidence } from './analyze.js';

// PRO-tier scope features. Note the deliberate boundary: nothing here changes
// how a single domain is scored. The FREE core decides the verdict; PRO adds
// reach (portfolios, monitoring diffs, extra output shapes) on top of the same
// scoring. Gating is the caller's job (see cli.js / license.js).

// Scan a portfolio of domains. Returns an array of reports. Failures per domain
// are captured, not thrown, so one bad domain does not sink the batch.
export async function scanBatch(domains, { deps, now } = {}) {
  const reports = [];
  for (const domain of domains) {
    try {
      reports.push(await scanDomain(domain, { deps, now }));
    } catch (err) {
      reports.push({ domain, error: err.message, score: null });
    }
  }
  return reports;
}

// Analyze a batch of already-collected evidence objects (offline; for tests).
export function analyzeBatch(evidences, { now } = {}) {
  return evidences.map((e) => analyzeEvidence(e, { now }));
}

// Diff two reports for the same domain (monitoring). Reports WHAT CHANGED:
// score delta, findings that appeared, findings that were resolved, and checks
// whose state flipped. A pure function — no network.
export function diffReports(previous, current) {
  const prevFindings = indexFindings(previous);
  const currFindings = indexFindings(current);

  const appeared = [];
  const resolved = [];

  for (const [key, f] of currFindings) {
    if (!prevFindings.has(key)) appeared.push(f);
  }
  for (const [key, f] of prevFindings) {
    if (!currFindings.has(key)) resolved.push(f);
  }

  const stateChanges = [];
  const prevChecks = indexChecks(previous);
  for (const chk of current.checks || []) {
    const before = prevChecks.get(chk.id);
    if (before && before.state !== chk.state) {
      stateChanges.push({ check: chk.id, from: before.state, to: chk.state });
    }
  }

  return {
    domain: current.domain,
    from: previous.scanned_at || null,
    to: current.scanned_at || null,
    score_before: previous.score,
    score_after: current.score,
    score_delta: numeric(current.score) - numeric(previous.score),
    appeared,
    resolved,
    state_changes: stateChanges,
    changed: appeared.length > 0 || resolved.length > 0 || stateChanges.length > 0,
  };
}

function indexFindings(report) {
  const map = new Map();
  for (const f of report.findings || []) {
    // A finding is identified by its rule and the check it came from; a domain
    // can only have one instance of a given rule per check, except takeover
    // which also keys on the affected subdomain in the message.
    map.set(`${f.check}:${f.rule_id}:${f.message}`, f);
  }
  return map;
}

function indexChecks(report) {
  const map = new Map();
  for (const c of report.checks || []) map.set(c.id, c);
  return map;
}

function numeric(v) {
  return typeof v === 'number' ? v : 0;
}
