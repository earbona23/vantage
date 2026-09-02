import { result, finding, notEvaluable } from './_result.js';
import { parseSpfTerms, spfAllQualifier } from '../parse.js';

const ID = 'spf';
const TITLE = 'SPF (Sender Policy Framework)';
const CATEGORY = 'email-auth';
const WEIGHT = 10;

// evidence.spf: string[] — the TXT records at the apex that start with v=spf1
export function checkSpf(evidence) {
  if (evidence.zoneResolves === false) {
    return notEvaluable({ id: ID, title: TITLE, category: CATEGORY, reason: 'The domain did not resolve (no authoritative nameservers answered), so its DNS records cannot be judged.' });
  }
  const records = evidence.spf || [];
  const findings = [];
  let earned = WEIGHT;

  if (records.length === 0) {
    findings.push(
      finding(
        'spf.missing',
        'high',
        'No SPF record found. Any host can claim to send mail as this domain.',
        'Publish a TXT record at the apex: "v=spf1 include:<provider> -all".'
      )
    );
    return result({ id: ID, title: TITLE, category: CATEGORY, weight: WEIGHT, earned: 0, findings, evidence: { records } });
  }

  if (records.length > 1) {
    // More than one SPF record is invalid per RFC 7208 — receivers get a
    // permerror and SPF effectively stops protecting the domain.
    findings.push(
      finding(
        'spf.multiple',
        'high',
        `${records.length} SPF records published. RFC 7208 requires exactly one; multiple records are a permerror.`,
        'Merge them into a single "v=spf1 ..." record.'
      )
    );
    earned -= 5;
  }

  const terms = parseSpfTerms(records[0]);
  const qualifier = spfAllQualifier(terms);

  if (qualifier === 'pass') {
    findings.push(
      finding(
        'spf.pass_all',
        'critical',
        'SPF ends with "+all", which authorises every host on the internet to send as this domain. This is worse than having no SPF.',
        'Replace "+all" with "-all" (hard fail) once your legitimate senders are listed.'
      )
    );
    earned = 0;
  } else if (qualifier === 'neutral') {
    findings.push(
      finding(
        'spf.neutral_all',
        'medium',
        'SPF ends with "?all" (neutral). Receivers are told to make no judgement, so spoofed mail is not marked.',
        'Move to "~all" (softfail) or "-all" (hardfail).'
      )
    );
    earned -= 4;
  } else if (qualifier === 'softfail') {
    // ~all is acceptable and common; small deduction vs a hard fail.
    earned -= 2;
  } else if (qualifier === 'fail') {
    // -all — the strong choice. Full marks.
  } else {
    findings.push(
      finding(
        'spf.no_all',
        'medium',
        'SPF record has no "all" mechanism, so its default is neutral. Unlisted senders are not rejected.',
        'Terminate the record with "-all" or "~all".'
      )
    );
    earned -= 4;
  }

  return result({
    id: ID,
    title: TITLE,
    category: CATEGORY,
    weight: WEIGHT,
    earned,
    findings,
    evidence: { records, all: qualifier },
  });
}
