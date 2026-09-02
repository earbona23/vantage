import { result, finding, notEvaluable } from './_result.js';

const ID = 'tlsrpt';
const TITLE = 'TLS-RPT (SMTP TLS Reporting)';
const CATEGORY = 'transport';
const WEIGHT = 3;

// evidence.tlsrpt: string[] — TXT at _smtp._tls.<domain> starting with v=TLSRPTv1
// Only relevant with an MX; otherwise not evaluable.
export function checkTlsRpt(evidence) {
  const mx = evidence.mx || { present: false };
  if (!mx.present) {
    return notEvaluable({
      id: ID,
      title: TITLE,
      category: CATEGORY,
      reason: 'Domain has no MX records, so SMTP TLS reporting does not apply.',
    });
  }

  const records = evidence.tlsrpt || [];
  if (records.length === 0) {
    return result({
      id: ID,
      title: TITLE,
      category: CATEGORY,
      weight: WEIGHT,
      earned: 0,
      findings: [
        finding(
          'tlsrpt.missing',
          'low',
          'No TLS-RPT record. You get no reports when senders fail to establish TLS to your mail servers, so downgrade problems stay invisible.',
          'Publish "_smtp._tls" TXT: "v=TLSRPTv1; rua=mailto:tlsrpt@<domain>".'
        ),
      ],
      evidence: { present: false },
    });
  }

  return result({
    id: ID,
    title: TITLE,
    category: CATEGORY,
    weight: WEIGHT,
    earned: WEIGHT,
    findings: [],
    evidence: { present: true },
  });
}
