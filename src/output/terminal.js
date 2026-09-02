import { SEVERITY_ORDER } from '../constants.js';

// Human-readable terminal report. No colour codes by default so the output is
// clean when piped; pass { color:true } for ANSI.
export function renderTerminal(report, { color = false, raw = false } = {}) {
  const c = color ? ansi : plain;
  const lines = [];

  lines.push('');
  lines.push(c.bold(`vantage report — ${report.domain}`));
  lines.push(`scanned ${report.scanned_at}`);
  lines.push('');

  if (report.score === null) {
    lines.push(c.bold('Verdict: NOT EVALUABLE'));
    lines.push('Nothing could be evaluated (the domain did not resolve, or every probe failed).');
    lines.push('');
  } else {
    const v = report.verdict;
    lines.push(c.bold(`Verdict: ${v.grade}  (${v.label})`));
    lines.push(`Posture score: ${report.score} / 100`);
    lines.push(bar(report.score));
    lines.push('');
  }

  // Surface discovery as its own line with an explicit state.
  if (report.discovery) {
    const d = report.discovery;
    if (d.evaluable) {
      lines.push(`Surface discovery (${d.source}): ${d.discovered} name(s) found${d.truncated ? ' (truncated)' : ''}`);
    } else {
      lines.push(`Surface discovery (${d.source}): NOT EVALUABLE — ${d.error || 'unavailable'}`);
    }
  }

  const s = report.summary;
  const st = s.checks_by_state || {};
  // The three states, counted separately — never collapsed into one another.
  lines.push(`Checks — finding:${st.finding || 0}  clean:${st.clean || 0}  not-evaluable:${st.not_evaluable || 0}   points: ${s.points.earned}/${s.points.possible}`);
  const sev = s.findings_by_severity;
  lines.push(
    `Findings — critical:${sev.critical} high:${sev.high} medium:${sev.medium} low:${sev.low} info:${sev.info}`
  );
  lines.push('');

  // Findings, worst first.
  if (report.findings.length) {
    lines.push(c.bold('Findings (each one is a rule you can argue with):'));
    for (const f of report.findings) {
      lines.push(`  [${f.severity.toUpperCase()}] ${f.rule_id}  (${f.check})`);
      lines.push(`      ${f.message}`);
      lines.push(`      fix: ${f.remediation}`);
    }
    lines.push('');
  }

  // Per-check ledger, so the score is fully traceable.
  lines.push(c.bold('Check ledger:'));
  for (const chk of report.checks) {
    if (chk.state === 'not_evaluable') {
      lines.push(`  - ${pad(chk.id, 12)} not evaluable  — ${chk.reason || ''}`);
    } else {
      lines.push(`  - ${pad(chk.id, 12)} ${chk.state === 'clean' ? 'clean ' : 'finding'}  ${chk.earned}/${chk.weight}`);
    }
  }
  lines.push('');

  // --raw / --all: dump everything found, unsummarised. Nothing hides behind
  // the score.
  if (raw && report.raw) lines.push(renderRaw(report.raw));

  return lines.join('\n');
}

function renderRaw(ev) {
  const out = ['', '=== RAW EVIDENCE (everything found, unsummarised) ==='];

  const recs = (label, arr) => {
    out.push(`${label}: ${arr && arr.length ? '' : '(none)'}`);
    for (const r of arr || []) out.push(`    ${r}`);
  };

  recs('SPF', ev.spf);
  recs('DMARC', ev.dmarc);
  recs('TLS-RPT', ev.tlsrpt);
  recs('BIMI', ev.bimi);
  out.push(`DKIM selectors found: ${Object.keys(ev.dkim || {}).join(', ') || '(none)'}`);
  out.push(`MX present: ${ev.mx && ev.mx.present}  records: ${JSON.stringify((ev.mx && ev.mx.records) || [])}`);
  out.push(`NS: ${(ev.ns || []).join(', ') || '(none)'}`);
  out.push(`CAA records: ${JSON.stringify((ev.caa && ev.caa.records) || [])}`);
  out.push(`DNSSEC: ${JSON.stringify(ev.dnssec || {})}`);
  out.push(`MTA-STS record: ${JSON.stringify((ev.mtasts && ev.mtasts.record) || [])}  policy: ${JSON.stringify((ev.mtasts && ev.mtasts.policy) || {})}`);
  out.push(`TLS: ${JSON.stringify(ev.tls || {})}`);

  const root = (ev.http && ev.http.root) || {};
  out.push(`HTTP root: status ${root.status} ok ${root.ok}${root.error ? ' error ' + root.error : ''}`);
  out.push('  response headers:');
  for (const [k, v] of Object.entries(root.headers || {})) out.push(`    ${k}: ${v}`);

  const disc = ev.discovery || {};
  out.push(`Discovery (${disc.source}): evaluable=${disc.evaluable} total=${disc.total}${disc.error ? ' error=' + disc.error : ''}`);
  const names = disc.names || [];
  out.push(`  discovered names (${names.length}):`);
  for (const n of names) out.push(`    ${n}`);

  const subs = ev.subdomains || { probed: [], entries: {} };
  out.push(`Probed hosts (${(subs.probed || []).length}):`);
  for (const host of subs.probed || []) {
    const e = (subs.entries || {})[host];
    if (e) out.push(`    ${host}  ->  CNAME ${e.cname}  (target resolves: ${e.targetResolves})`);
    else out.push(`    ${host}  ->  no CNAME`);
  }
  out.push('');
  return out.join('\n');
}

function bar(score) {
  const width = 20;
  const filled = Math.round((score / 100) * width);
  return `[${'#'.repeat(filled)}${'.'.repeat(width - filled)}] ${score}/100`;
}

function pad(s, n) {
  s = String(s);
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}

// Ensure the imported ordering constant is referenced (keeps severities aligned
// with the shared source of truth if it ever changes).
export const SEVERITIES = SEVERITY_ORDER;

const plain = { bold: (s) => s };
const ansi = { bold: (s) => `[1m${s}[0m` };
