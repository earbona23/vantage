// Self-contained HTML report (PRO). No external assets, no scripts, no network
// — the file opens offline and styling is inline. Suits emailing a stakeholder
// or archiving a point-in-time posture snapshot.
export function renderHtml(report) {
  const gradeColor = {
    A: '#2f855a',
    B: '#38a169',
    C: '#d69e2e',
    D: '#dd6b20',
    F: '#c53030',
  };
  const grade = report.verdict ? report.verdict.grade : '—';
  const color = gradeColor[grade] || '#4a5568';

  const rows = report.findings
    .map(
      (f) => `<tr>
      <td><span class="sev sev-${f.severity}">${f.severity}</span></td>
      <td><code>${esc(f.rule_id)}</code></td>
      <td>${esc(f.check)}</td>
      <td>${esc(f.message)}</td>
      <td>${esc(f.remediation)}</td>
    </tr>`
    )
    .join('\n');

  const ledger = report.checks
    .map((c) => {
      const state = c.state === 'not_evaluable' ? 'not evaluable' : c.state;
      const pts = c.state === 'not_evaluable' ? '—' : `${c.earned}/${c.weight}`;
      return `<tr><td>${esc(c.id)}</td><td>${esc(state)}</td><td>${pts}</td><td>${esc(c.reason || '')}</td></tr>`;
    })
    .join('\n');

  const sev = report.summary.findings_by_severity;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vantage — ${esc(report.domain)}</title>
<style>
  body { font: 15px/1.5 -apple-system, system-ui, Segoe UI, Roboto, sans-serif; color: #1a202c; margin: 0; padding: 2rem; background: #f7fafc; }
  .wrap { max-width: 960px; margin: 0 auto; }
  h1 { font-size: 1.4rem; margin: 0 0 .25rem; }
  .meta { color: #718096; margin-bottom: 1.5rem; }
  .score { display: flex; align-items: center; gap: 1rem; margin-bottom: 1.5rem; }
  .grade { font-size: 2.5rem; font-weight: 700; color: ${color}; width: 3rem; text-align: center; }
  .bar { flex: 1; background: #e2e8f0; border-radius: 6px; height: 14px; overflow: hidden; }
  .fill { height: 100%; background: ${color}; width: ${report.score === null ? 0 : report.score}%; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 2rem; background: #fff; }
  th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid #edf2f7; vertical-align: top; font-size: 13px; }
  th { background: #edf2f7; }
  code { background: #edf2f7; padding: 1px 4px; border-radius: 3px; font-size: 12px; }
  .sev { font-weight: 600; text-transform: uppercase; font-size: 11px; }
  .sev-critical { color: #c53030; } .sev-high { color: #dd6b20; } .sev-medium { color: #d69e2e; }
  .sev-low { color: #3182ce; } .sev-info { color: #718096; }
  .counts span { margin-right: 1rem; }
</style>
</head>
<body>
<div class="wrap">
  <h1>vantage report — ${esc(report.domain)}</h1>
  <div class="meta">scanned ${esc(report.scanned_at)}</div>
  <div class="score">
    <div class="grade">${grade}</div>
    <div style="flex:1">
      <div><strong>${report.score === null ? 'not evaluable' : report.score + ' / 100'}</strong> — ${esc(report.verdict ? report.verdict.label : 'nothing evaluable')}</div>
      <div class="bar"><div class="fill"></div></div>
    </div>
  </div>
  <div class="counts">
    <span>critical: ${sev.critical}</span><span>high: ${sev.high}</span><span>medium: ${sev.medium}</span><span>low: ${sev.low}</span><span>info: ${sev.info}</span>
  </div>
  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Check</th><th>What</th><th>Fix</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="5">No findings.</td></tr>'}</tbody>
  </table>
  <h2>Check ledger</h2>
  <table>
    <thead><tr><th>Check</th><th>State</th><th>Points</th><th>Note</th></tr></thead>
    <tbody>${ledger}</tbody>
  </table>
</div>
</body>
</html>`;
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
