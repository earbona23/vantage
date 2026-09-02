import { STATE } from '../constants.js';

// Helpers to build a uniform check result. A check result is:
//   { id, title, category, state, weight, earned, findings[], evidence }
// where a finding is { rule_id, severity, message, remediation }.
//
// weight  = max points this check can add to the score
// earned  = points actually earned (0..weight); ignored when not_evaluable
// A not_evaluable check is excluded from the score denominator entirely.

export function finding(rule_id, severity, message, remediation) {
  return { rule_id, severity, message, remediation };
}

export function result({ id, title, category, weight, earned, findings = [], evidence = {} }) {
  const hasFinding = findings.length > 0;
  return {
    id,
    title,
    category,
    state: hasFinding ? STATE.FINDING : STATE.CLEAN,
    weight,
    earned: clamp(earned, 0, weight),
    findings,
    evidence,
  };
}

// Build a not_evaluable result. It carries a reason and never touches the score.
export function notEvaluable({ id, title, category, reason, evidence = {} }) {
  return {
    id,
    title,
    category,
    state: STATE.NOT_EVALUABLE,
    weight: 0,
    earned: 0,
    findings: [],
    reason,
    evidence,
  };
}

function clamp(n, lo, hi) {
  if (!Number.isFinite(n)) return lo;
  return Math.max(lo, Math.min(hi, n));
}
