import { result, finding, notEvaluable } from './_result.js';

const ID = 'caa';
const TITLE = 'CAA (Certification Authority Authorization)';
const CATEGORY = 'dns';
const WEIGHT = 5;

// evidence.caa: { evaluable: bool, records: [{critical, issue?, issuewild?, iodef?}] }
export function checkCaa(evidence) {
  if (evidence.zoneResolves === false || (evidence.caa && evidence.caa.evaluable === false)) {
    return notEvaluable({ id: ID, title: TITLE, category: CATEGORY, reason: 'CAA records could not be queried (the domain did not resolve or the lookup failed).' });
  }
  const c = evidence.caa || { evaluable: true, records: [] };
  const records = c.records || [];
  const findings = [];

  if (records.length === 0) {
    findings.push(
      finding(
        'caa.absent',
        'low',
        'No CAA record. Any certificate authority is permitted to issue certificates for this domain, widening the mis-issuance surface.',
        'Publish CAA records naming only the CAs you use, e.g. \'0 issue "letsencrypt.org"\'.'
      )
    );
    return result({ id: ID, title: TITLE, category: CATEGORY, weight: WEIGHT, earned: 2, findings, evidence: { present: false } });
  }

  let earned = WEIGHT;
  const hasIssue = records.some((r) => r.issue !== undefined);
  const hasIssueWild = records.some((r) => r.issuewild !== undefined);

  if (hasIssue && !hasIssueWild) {
    // issue restricts leaf certs but wildcards fall through to issue; still,
    // an explicit issuewild ";" (deny) is stronger. Minor deduction only.
    earned -= 1;
    findings.push(
      finding(
        'caa.no_issuewild',
        'info',
        'CAA restricts issuance but sets no explicit issuewild policy. Wildcard issuance follows the general issue rule rather than a dedicated one.',
        'Add an issuewild rule (or \'0 issuewild ";"\' to forbid wildcards) if wildcards are not needed.'
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
    evidence: { present: true, issuers: records.filter((r) => r.issue).map((r) => r.issue) },
  });
}
