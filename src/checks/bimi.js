import { result, finding, notEvaluable } from './_result.js';
import { parseTagValue } from '../parse.js';

const ID = 'bimi';
const TITLE = 'BIMI (Brand Indicators for Message Identification)';
const CATEGORY = 'email-auth';
const WEIGHT = 2;

// evidence.bimi: string[] — TXT at default._bimi.<domain>
// BIMI is a brand feature that rides on top of DMARC enforcement. Its absence
// is not a security defect, so this check never emits a real finding.
export function checkBimi(evidence) {
  if (evidence.zoneResolves === false) {
    return notEvaluable({ id: ID, title: TITLE, category: CATEGORY, reason: 'The domain did not resolve.' });
  }
  const records = evidence.bimi || [];
  if (records.length === 0) {
    return result({
      id: ID,
      title: TITLE,
      category: CATEGORY,
      weight: WEIGHT,
      earned: 1,
      findings: [
        finding(
          'bimi.absent',
          'info',
          'No BIMI record. Optional; it only takes effect once DMARC is at quarantine/reject.',
          'Optional. Publish a BIMI record with a compliant SVG logo (and VMC, if required by the mailbox provider).'
        ),
      ],
      evidence: { present: false },
    });
  }

  const tags = parseTagValue(records[0], ';');
  return result({
    id: ID,
    title: TITLE,
    category: CATEGORY,
    weight: WEIGHT,
    earned: WEIGHT,
    findings: [],
    evidence: { present: true, l: tags.l, a: tags.a },
  });
}
