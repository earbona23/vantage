import { result, finding, notEvaluable } from './_result.js';

const ID = 'dnssec';
const TITLE = 'DNSSEC';
const CATEGORY = 'dns';
const WEIGHT = 6;

// evidence.dnssec: { evaluable: bool, ad: bool, ds: bool, error: string|null }
//   ad = the authenticated-data flag came back set from a validating resolver
//   ds = a DS record exists at the parent (chain of trust delegated)
export function checkDnssec(evidence) {
  const d = evidence.dnssec || { evaluable: false };

  if (!d.evaluable) {
    return notEvaluable({
      id: ID,
      title: TITLE,
      category: CATEGORY,
      reason: `Could not query DNSSEC state${d.error ? ` (${d.error})` : ''}.`,
    });
  }

  if (d.ds && d.ad) {
    return result({
      id: ID,
      title: TITLE,
      category: CATEGORY,
      weight: WEIGHT,
      earned: WEIGHT,
      findings: [],
      evidence: { signed: true },
    });
  }

  if (d.ds && !d.ad) {
    return result({
      id: ID,
      title: TITLE,
      category: CATEGORY,
      weight: WEIGHT,
      earned: 3,
      findings: [
        finding(
          'dnssec.broken_chain',
          'medium',
          'A DS record is delegated at the parent but the validating resolver did not return authenticated data. The DNSSEC chain looks broken.',
          'Verify DNSKEY/RRSIG at the zone match the DS at the registrar.'
        ),
      ],
      evidence: { signed: false, ds: true, ad: false },
    });
  }

  return result({
    id: ID,
    title: TITLE,
    category: CATEGORY,
    weight: WEIGHT,
    earned: 0,
    findings: [
      finding(
        'dnssec.unsigned',
        'medium',
        'DNSSEC is not enabled. DNS answers for this domain are not cryptographically signed and can be forged in transit.',
        'Enable DNSSEC at your DNS provider and add the DS record at your registrar.'
      ),
    ],
    evidence: { signed: false, ds: false },
  });
}
