import { STATE, VERDICT_BANDS, SEVERITY_ORDER } from './constants.js';

// Aggregate check results into a score and verdict.
//
// The rule is the whole philosophy of the tool:
//   - Only checks we could actually evaluate contribute to the score.
//   - A not_evaluable check is excluded from BOTH numerator and denominator.
//     We never award points for what we could not measure, and never punish
//     the domain for our own inability to look.
//   - score = round(100 * sum(earned) / sum(weight)) over evaluable checks.
export function score(results) {
  let earned = 0;
  let weight = 0;
  let evaluated = 0;
  let notEvaluable = 0;

  for (const r of results) {
    if (r.state === STATE.NOT_EVALUABLE) {
      notEvaluable += 1;
      continue;
    }
    earned += r.earned;
    weight += r.weight;
    evaluated += 1;
  }

  const value = weight > 0 ? Math.round((100 * earned) / weight) : null;

  return {
    value, // 0..100, or null when nothing was evaluable
    earned,
    weight,
    evaluated,
    notEvaluable,
    verdict: value === null ? null : verdictFor(value),
  };
}

export function verdictFor(value) {
  for (const band of VERDICT_BANDS) {
    if (value >= band.min && value <= band.max) {
      return { grade: band.grade, label: band.label };
    }
  }
  // Should be unreachable given the bands cover 0..100.
  return { grade: 'F', label: 'poor public posture' };
}

// Flatten and sort every finding across all checks, worst severity first.
export function collectFindings(results) {
  const all = [];
  for (const r of results) {
    for (const f of r.findings || []) {
      all.push({ ...f, check: r.id, category: r.category });
    }
  }
  all.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  return all;
}

export function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity] += 1;
  }
  return counts;
}
