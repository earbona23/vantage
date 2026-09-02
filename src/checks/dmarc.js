import { result, finding, notEvaluable } from './_result.js';
import { parseTagValue } from '../parse.js';

const ID = 'dmarc';
const TITLE = 'DMARC (Domain-based Message Authentication)';
const CATEGORY = 'email-auth';
const WEIGHT = 14;

// evidence.dmarc: string[] — TXT records at _dmarc.<domain> starting with v=DMARC1
export function checkDmarc(evidence) {
  if (evidence.zoneResolves === false) {
    return notEvaluable({ id: ID, title: TITLE, category: CATEGORY, reason: 'The domain did not resolve, so its DNS records cannot be judged.' });
  }
  const records = evidence.dmarc || [];
  const findings = [];

  if (records.length === 0) {
    findings.push(
      finding(
        'dmarc.missing',
        'high',
        'No DMARC record. Even with SPF and DKIM, receivers have no policy telling them what to do with mail that fails authentication.',
        'Publish "v=DMARC1; p=none; rua=mailto:dmarc@<domain>" at _dmarc, then tighten to quarantine/reject.'
      )
    );
    return result({ id: ID, title: TITLE, category: CATEGORY, weight: WEIGHT, earned: 0, findings, evidence: { records } });
  }

  const tags = parseTagValue(records[0], ';');
  const policy = (tags.p || '').toLowerCase();
  let earned;

  if (policy === 'reject') {
    earned = WEIGHT;
  } else if (policy === 'quarantine') {
    earned = 11;
    findings.push(
      finding(
        'dmarc.policy_quarantine',
        'low',
        'DMARC policy is quarantine. Failing mail is sent to spam rather than rejected outright.',
        'Move to "p=reject" once reports show no legitimate mail is failing.'
      )
    );
  } else if (policy === 'none') {
    earned = 6;
    findings.push(
      finding(
        'dmarc.policy_none',
        'medium',
        'DMARC policy is "none" (monitor only). Spoofed mail that fails authentication is still delivered.',
        'Progress to "p=quarantine" and then "p=reject".'
      )
    );
  } else {
    earned = 4;
    findings.push(
      finding(
        'dmarc.policy_invalid',
        'high',
        `DMARC record present but its policy tag is missing or invalid (p="${tags.p || ''}"). The record does not enforce anything.`,
        'Set a valid policy: p=none|quarantine|reject.'
      )
    );
  }

  // Aggregate reporting: without rua you get enforcement but no visibility.
  if (!tags.rua) {
    earned -= 1;
    findings.push(
      finding(
        'dmarc.no_rua',
        'low',
        'No aggregate reporting address (rua). You are enforcing a policy blind, with no feedback on what fails.',
        'Add "rua=mailto:dmarc@<domain>".'
      )
    );
  }

  // pct < 100 means the policy only applies to a fraction of mail.
  if (tags.pct !== undefined) {
    const pct = parseInt(tags.pct, 10);
    if (Number.isFinite(pct) && pct < 100) {
      earned -= 2;
      findings.push(
        finding(
          'dmarc.partial_pct',
          'medium',
          `DMARC pct=${pct}: the policy is applied to only ${pct}% of failing mail. The rest is delivered as if there were no policy.`,
          'Remove pct or set pct=100 once you are confident.'
        )
      );
    }
  }

  return result({
    id: ID,
    title: TITLE,
    category: CATEGORY,
    weight: WEIGHT,
    earned,
    findings,
    evidence: { records, policy, sp: tags.sp, rua: tags.rua },
  });
}
