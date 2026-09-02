// Markdown report — the same content as the terminal view, formatted for a PR
// comment or an issue.
export function renderMarkdown(report) {
  const out = [];
  out.push(`# vantage report — \`${report.domain}\``);
  out.push('');
  out.push(`_scanned ${report.scanned_at}_`);
  out.push('');

  if (report.score === null) {
    out.push('## Verdict: **NOT EVALUABLE**');
    out.push('');
    out.push('Nothing could be evaluated. The domain did not resolve, or every probe failed.');
  } else {
    out.push(`## Verdict: **${report.verdict.grade}** — ${report.verdict.label}`);
    out.push('');
    out.push(`**Posture score: ${report.score} / 100**`);
    out.push('');
    out.push('```');
    out.push(bar(report.score));
    out.push('```');
  }
  out.push('');

  if (report.discovery) {
    const d = report.discovery;
    out.push(
      d.evaluable
        ? `Surface discovery (${d.source}): **${d.discovered}** name(s) found${d.truncated ? ' (truncated)' : ''}.`
        : `Surface discovery (${d.source}): **NOT EVALUABLE** — ${d.error || 'unavailable'}.`
    );
    out.push('');
  }

  const st = report.summary.checks_by_state || {};
  const sev = report.summary.findings_by_severity;
  out.push(
    `Checks — finding: **${st.finding || 0}**, clean: **${st.clean || 0}**, not-evaluable: **${st.not_evaluable || 0}**, points: **${report.summary.points.earned}/${report.summary.points.possible}**.`
  );
  out.push('');
  out.push(
    `Findings — critical: ${sev.critical}, high: ${sev.high}, medium: ${sev.medium}, low: ${sev.low}, info: ${sev.info}.`
  );
  out.push('');

  if (report.findings.length) {
    out.push('## Findings');
    out.push('');
    out.push('| Severity | Rule | Check | What | Fix |');
    out.push('|----------|------|-------|------|-----|');
    for (const f of report.findings) {
      out.push(
        `| ${f.severity} | \`${f.rule_id}\` | ${f.check} | ${md(f.message)} | ${md(f.remediation)} |`
      );
    }
    out.push('');
  }

  out.push('## Check ledger');
  out.push('');
  out.push('| Check | State | Points |');
  out.push('|-------|-------|--------|');
  for (const chk of report.checks) {
    if (chk.state === 'not_evaluable') {
      out.push(`| ${chk.id} | not evaluable | — |`);
    } else {
      out.push(`| ${chk.id} | ${chk.state} | ${chk.earned}/${chk.weight} |`);
    }
  }
  out.push('');

  return out.join('\n');
}

function bar(score) {
  const width = 20;
  const filled = Math.round((score / 100) * width);
  return `[${'#'.repeat(filled)}${'.'.repeat(width - filled)}] ${score}/100`;
}

function md(s) {
  return String(s).replace(/\|/g, '\\|');
}
