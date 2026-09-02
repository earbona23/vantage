import { result, finding, notEvaluable } from './_result.js';

const ID = 'mx';
const TITLE = 'MX (mail exchangers)';
const CATEGORY = 'transport';
const WEIGHT = 3;

// evidence.mx: { present: bool, records: [{exchange, priority}], evaluable: bool }
// Whether a domain receives mail is not itself a security failing. This check
// records the fact (other transport checks depend on it) and only flags the
// combination "publishes SPF/DMARC but has no MX" as a minor smell.
export function checkMx(evidence) {
  if (evidence.zoneResolves === false || (evidence.mx && evidence.mx.evaluable === false)) {
    return notEvaluable({ id: ID, title: TITLE, category: CATEGORY, reason: 'The domain did not resolve, so MX records cannot be judged.' });
  }
  const mx = evidence.mx || { present: false, records: [], evaluable: true };

  if (mx.present) {
    return result({
      id: ID,
      title: TITLE,
      category: CATEGORY,
      weight: WEIGHT,
      earned: WEIGHT,
      findings: [],
      evidence: { present: true, count: (mx.records || []).length },
    });
  }

  // No MX. Clean by default (many domains do not receive mail), but if the
  // domain advertises inbound mail intent via email-auth records, note it.
  const advertisesMail = (evidence.spf || []).length > 0 || (evidence.dmarc || []).length > 0;
  if (advertisesMail) {
    return result({
      id: ID,
      title: TITLE,
      category: CATEGORY,
      weight: WEIGHT,
      earned: 2,
      findings: [
        finding(
          'mx.absent_but_email_auth',
          'info',
          'No MX records, yet SPF/DMARC are published. Fine if this domain is send-only, but worth confirming it is intentional.',
          'If the domain should not receive mail, this is expected. Otherwise publish MX records.'
        ),
      ],
      evidence: { present: false, advertisesMail: true },
    });
  }

  return result({
    id: ID,
    title: TITLE,
    category: CATEGORY,
    weight: WEIGHT,
    earned: WEIGHT,
    findings: [],
    evidence: { present: false, advertisesMail: false },
  });
}
