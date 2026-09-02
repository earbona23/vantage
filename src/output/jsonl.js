// JSONL export (PRO) — one report per line. Useful for shipping a portfolio
// scan into a log pipeline or a webhook body. Each line is a complete report.
export function renderJsonl(reports) {
  const list = Array.isArray(reports) ? reports : [reports];
  return list.map((r) => JSON.stringify(r)).join('\n');
}
