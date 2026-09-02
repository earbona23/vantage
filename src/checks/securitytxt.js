import { result, finding, notEvaluable } from './_result.js';
import { parseSecurityTxt } from '../parse.js';

const ID = 'securitytxt';
const TITLE = 'security.txt (RFC 9116)';
const CATEGORY = 'web';
const WEIGHT = 4;

// evidence.http.securitytxt: { ok, status, body, error, finalUrl }
// evidence.http.root.ok tells us whether the site is reachable at all.
export function checkSecurityTxt(evidence, now = new Date()) {
  const root = (evidence.http && evidence.http.root) || { ok: false };
  const st = (evidence.http && evidence.http.securitytxt) || { ok: false };

  // If the whole site is unreachable, we cannot judge security.txt either.
  if (!root.ok && !st.ok) {
    return notEvaluable({
      id: ID,
      title: TITLE,
      category: CATEGORY,
      reason: 'Site is unreachable, so the presence of security.txt cannot be determined.',
    });
  }

  if (!st.ok) {
    return result({
      id: ID,
      title: TITLE,
      category: CATEGORY,
      weight: WEIGHT,
      earned: 0,
      findings: [
        finding(
          'securitytxt.missing',
          'low',
          'No security.txt at /.well-known/security.txt. Researchers have no advertised, machine-readable way to report a vulnerability.',
          'Publish /.well-known/security.txt with at least a Contact and an Expires field (RFC 9116).'
        ),
      ],
      evidence: { present: false },
    });
  }

  const fields = parseSecurityTxt(st.body || '');
  const findings = [];
  let earned = WEIGHT;

  if (!fields.contact) {
    earned -= 2;
    findings.push(
      finding(
        'securitytxt.no_contact',
        'low',
        'security.txt is present but has no Contact field, which RFC 9116 requires. It is not actionable.',
        'Add a "Contact:" line (mailto: or https:).'
      )
    );
  }

  if (!fields.expires) {
    earned -= 1;
    findings.push(
      finding(
        'securitytxt.no_expires',
        'low',
        'security.txt has no Expires field. RFC 9116 requires it so consumers know the file is current.',
        'Add an "Expires:" line with a future ISO-8601 timestamp.'
      )
    );
  } else {
    const exp = Date.parse(fields.expires[0]);
    if (Number.isFinite(exp) && exp < now.getTime()) {
      earned -= 2;
      findings.push(
        finding(
          'securitytxt.expired',
          'medium',
          `security.txt expired on ${fields.expires[0]}. Consumers are told to treat it as stale.`,
          'Refresh the file and bump the Expires timestamp.'
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
    evidence: { present: true, hasContact: !!fields.contact, hasExpires: !!fields.expires },
  });
}
