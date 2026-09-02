import { result, finding, notEvaluable } from './_result.js';

const ID = 'tls';
const TITLE = 'TLS certificate & protocol';
const CATEGORY = 'web';
const WEIGHT = 8;

// evidence.tls: { evaluable, authorized, protocol, daysToExpiry, error }
export function checkTls(evidence) {
  const t = evidence.tls || { evaluable: false };

  if (!t.evaluable) {
    return notEvaluable({
      id: ID,
      title: TITLE,
      category: CATEGORY,
      reason: `Could not complete a TLS handshake on port 443${t.error ? ` (${t.error})` : ''}.`,
    });
  }

  const findings = [];
  let earned = WEIGHT;

  // Chain validation. A self-signed or untrusted chain is a real problem.
  if (t.authorized === false) {
    earned -= 4;
    findings.push(
      finding(
        'tls.untrusted_chain',
        'high',
        `The presented certificate did not validate against the public trust store${t.authorizationError ? ` (${t.authorizationError})` : ''}.`,
        'Serve a complete, valid certificate chain from a trusted CA.'
      )
    );
  }

  // Expiry proximity.
  if (Number.isFinite(t.daysToExpiry)) {
    if (t.daysToExpiry < 0) {
      earned -= 4;
      findings.push(
        finding(
          'tls.expired',
          'critical',
          `The certificate expired ${Math.abs(t.daysToExpiry)} day(s) ago.`,
          'Renew and deploy a current certificate immediately.'
        )
      );
    } else if (t.daysToExpiry < 15) {
      earned -= 2;
      findings.push(
        finding(
          'tls.expiring_soon',
          'medium',
          `The certificate expires in ${t.daysToExpiry} day(s). Renewal is overdue.`,
          'Renew now and automate renewal so it does not recur.'
        )
      );
    }
  }

  // Obsolete protocol floor.
  const proto = (t.protocol || '').toUpperCase();
  if (proto === 'TLSV1' || proto === 'TLSV1.1' || proto === 'SSLV3') {
    earned -= 3;
    findings.push(
      finding(
        'tls.obsolete_protocol',
        'high',
        `The handshake negotiated ${t.protocol}, a deprecated protocol with known weaknesses.`,
        'Disable everything below TLS 1.2 and prefer TLS 1.3.'
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
    evidence: { protocol: t.protocol, daysToExpiry: t.daysToExpiry, authorized: t.authorized },
  });
}
