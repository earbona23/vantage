import { result, finding, notEvaluable } from './_result.js';

// The MTA-STS policy file (RFC 8461) is a set of "key: value" lines, not the
// "tag=value" grammar the DNS records use. Pull the mode out directly.
function policyMode(body) {
  if (typeof body !== 'string') return '';
  const m = body.match(/^\s*mode\s*:\s*(\S+)/im);
  return m ? m[1].toLowerCase() : '';
}

const ID = 'mtasts';
const TITLE = 'MTA-STS (SMTP MTA Strict Transport Security)';
const CATEGORY = 'transport';
const WEIGHT = 6;

// evidence.mtasts:
//   { record: string[]  (TXT at _mta-sts.<domain>),
//     policy: { fetched: bool, body: string|null, error: string|null } }
// Only meaningful for domains that receive mail — if there is no MX, this is
// not evaluable rather than a failure.
export function checkMtaSts(evidence) {
  const mx = evidence.mx || { present: false };
  if (!mx.present) {
    return notEvaluable({
      id: ID,
      title: TITLE,
      category: CATEGORY,
      reason: 'Domain has no MX records, so inbound SMTP transport security does not apply.',
    });
  }

  const data = evidence.mtasts || {};
  const records = data.record || [];
  const policy = data.policy || { fetched: false, body: null, error: null };
  const findings = [];

  if (records.length === 0) {
    findings.push(
      finding(
        'mtasts.missing',
        'medium',
        'No MTA-STS record. Sending servers cannot know to require TLS for mail to this domain and can be downgraded to cleartext.',
        'Publish "_mta-sts" TXT and a policy at https://mta-sts.<domain>/.well-known/mta-sts.txt with mode: enforce.'
      )
    );
    return result({ id: ID, title: TITLE, category: CATEGORY, weight: WEIGHT, earned: 0, findings, evidence: { record: records } });
  }

  // Record exists — the policy file must be reachable, or the record is a lie.
  if (!policy.fetched) {
    findings.push(
      finding(
        'mtasts.policy_unreachable',
        'medium',
        `MTA-STS DNS record present but the policy file could not be fetched${policy.error ? ` (${policy.error})` : ''}. Senders will ignore MTA-STS entirely.`,
        'Serve a valid policy over HTTPS at https://mta-sts.<domain>/.well-known/mta-sts.txt.'
      )
    );
    return result({ id: ID, title: TITLE, category: CATEGORY, weight: WEIGHT, earned: 2, findings, evidence: { record: records, policyFetched: false } });
  }

  const mode = policyMode(policy.body || '');
  let earned = WEIGHT;

  if (mode === 'enforce') {
    // best case
  } else if (mode === 'testing') {
    earned = 4;
    findings.push(
      finding(
        'mtasts.mode_testing',
        'low',
        'MTA-STS policy is in "testing" mode. Failures are reported but not enforced, so downgrade attacks still succeed.',
        'Move the policy to "mode: enforce" once TLS-RPT shows no legitimate failures.'
      )
    );
  } else {
    earned = 2;
    findings.push(
      finding(
        'mtasts.mode_none',
        'medium',
        `MTA-STS policy mode is "${mode || 'unset'}". The policy provides no protection.`,
        'Set "mode: enforce" in the policy file.'
      )
    );
  }

  return result({
    id: ID,
    title: TITLE,
    category: CATEGORY,
    weight: WEIGHT,
    earned,
    findings,
    evidence: { record: records, mode },
  });
}
