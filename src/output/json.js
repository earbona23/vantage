// The report object IS the JSON contract. This just serialises it stably.
// The shape (schema field, score, verdict, summary, checks, findings) is the
// documented stable contract other tools can depend on.
export function renderJson(report) {
  return JSON.stringify(report, null, 2);
}
