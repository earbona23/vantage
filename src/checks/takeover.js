import { result, finding, notEvaluable } from './_result.js';
import { matchTakeover } from '../fingerprints.js';

const ID = 'takeover';
const TITLE = 'Subdomain takeover exposure';
const CATEGORY = 'exposure';
const WEIGHT = 12;

// evidence.subdomains: {
//   evaluable: bool,
//   probed: string[],
//   entries: { [fqdn]: { cname: string|null, targetResolves: bool|null, body: string|null } }
// }
export function checkTakeover(evidence) {
  const s = evidence.subdomains || { evaluable: false, probed: [], entries: {} };

  if (!s.evaluable) {
    return notEvaluable({
      id: ID,
      title: TITLE,
      category: CATEGORY,
      reason: 'Could not resolve subdomains to probe for dangling CNAMEs.',
    });
  }

  const findings = [];
  const dangling = [];

  for (const [fqdn, e] of Object.entries(s.entries || {})) {
    if (!e || !e.cname) continue;
    const fp = matchTakeover(e.cname, e.body, e.targetResolves);
    if (fp) {
      dangling.push({ fqdn, cname: e.cname, service: fp.service });
      findings.push(
        finding(
          'takeover.dangling_cname',
          'critical',
          `${fqdn} points via CNAME to ${e.cname} (${fp.service}), which appears unclaimed. An attacker who registers that resource controls content served from your subdomain.`,
          `Remove the dangling CNAME for ${fqdn}, or re-claim the ${fp.service} resource it points to.`
        )
      );
    }
  }

  if (findings.length === 0) {
    // No dangling CNAME among the hosts we probed. But if the CT-log discovery
    // that enumerates the domain's surface was NOT available, we cannot claim a
    // clean bill — we only checked the seed hosts, not the real surface. That is
    // not-evaluable, not "clean". A confirmed dangling CNAME (above) is reported
    // regardless of discovery state.
    const disc = s.discovery || { evaluable: true };
    if (disc.evaluable === false) {
      return notEvaluable({
        id: ID,
        title: TITLE,
        category: CATEGORY,
        reason: `Probed ${s.probed.length} seed host(s) with no takeover, but subdomain discovery via ${disc.source || 'crt.sh'} was unavailable${disc.error ? ` (${disc.error})` : ''}, so the domain's full surface could not be enumerated.`,
        evidence: { probed: s.probed, discovery: disc },
      });
    }
    return result({
      id: ID,
      title: TITLE,
      category: CATEGORY,
      weight: WEIGHT,
      earned: WEIGHT,
      findings: [],
      evidence: { probed: s.probed, dangling: 0, discovery: disc },
    });
  }

  // Any confirmed dangling CNAME is a takeover. Zero out the check.
  return result({
    id: ID,
    title: TITLE,
    category: CATEGORY,
    weight: WEIGHT,
    earned: 0,
    findings,
    evidence: { probed: s.probed, dangling: dangling.length, entries: dangling },
  });
}
