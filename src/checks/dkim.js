import { result, finding, notEvaluable } from './_result.js';

const ID = 'dkim';
const TITLE = 'DKIM (common selectors)';
const CATEGORY = 'email-auth';
const WEIGHT = 4;

// evidence.dkim: { [selector]: string[] } — TXT records at <selector>._domainkey
// Only common selectors are probed, so a miss is inconclusive, never a failure.
export function checkDkim(evidence) {
  if (evidence.zoneResolves === false) {
    return notEvaluable({ id: ID, title: TITLE, category: CATEGORY, reason: 'The domain did not resolve, so DKIM selectors cannot be probed.' });
  }
  const map = evidence.dkim || {};
  const found = Object.entries(map)
    .filter(([, records]) => (records || []).some((r) => /(^|;)\s*v\s*=\s*dkim1/i.test(r) || /p\s*=/.test(r)))
    .map(([selector]) => selector);

  if (found.length > 0) {
    return result({
      id: ID,
      title: TITLE,
      category: CATEGORY,
      weight: WEIGHT,
      earned: WEIGHT,
      findings: [],
      evidence: { selectors_found: found },
    });
  }

  // No common selector answered. We deliberately do NOT call this a failure —
  // the domain may sign with a custom selector we did not probe. It is an
  // informational note that lowers confidence slightly, not a penalty for a
  // real defect.
  return result({
    id: ID,
    title: TITLE,
    category: CATEGORY,
    weight: WEIGHT,
    earned: 2,
    findings: [
      finding(
        'dkim.no_common_selector',
        'info',
        'No DKIM key found at any common selector. The domain may still sign with a custom selector this scan does not probe — this is inconclusive, not a confirmed gap.',
        'Confirm your provider’s DKIM selector and verify a key is published there.'
      ),
    ],
    evidence: { selectors_probed: Object.keys(map) },
  });
}
