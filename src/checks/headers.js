import { result, finding, notEvaluable } from './_result.js';
import { parseHsts } from '../parse.js';
import { HSTS_MIN_MAX_AGE } from '../constants.js';

const ID = 'headers';
const TITLE = 'HTTP security headers';
const CATEGORY = 'web';
const WEIGHT = 20;

// evidence.http.root: { ok: bool, status, headers: {lowercased}, finalUrl, error }
export function checkHeaders(evidence) {
  const root = (evidence.http && evidence.http.root) || { ok: false };

  if (!root.ok) {
    return notEvaluable({
      id: ID,
      title: TITLE,
      category: CATEGORY,
      reason: `Could not fetch the site over HTTPS${root.error ? ` (${root.error})` : ''}.`,
      evidence: { status: root.status || null },
    });
  }

  const h = root.headers || {};
  const findings = [];
  let earned = WEIGHT;

  // HSTS — 5 points. Present-and-strong, present-weak, or missing.
  if (h['strict-transport-security']) {
    const hsts = parseHsts(h['strict-transport-security']);
    if (!hsts.maxAge || hsts.maxAge < HSTS_MIN_MAX_AGE) {
      earned -= 3;
      findings.push(
        finding(
          'headers.hsts_weak',
          'medium',
          `HSTS max-age is ${hsts.maxAge ?? 'unset'} — below the recommended ${HSTS_MIN_MAX_AGE} seconds (180 days). Short windows leave users exposed to SSL-stripping.`,
          'Set "max-age=31536000; includeSubDomains; preload".'
        )
      );
    } else if (!hsts.includeSubDomains) {
      earned -= 1;
      findings.push(
        finding(
          'headers.hsts_no_subdomains',
          'low',
          'HSTS is set but without includeSubDomains, leaving sibling subdomains unprotected.',
          'Add "includeSubDomains" (and "preload" if eligible).'
        )
      );
    }
  } else {
    earned -= 5;
    findings.push(
      finding(
        'headers.hsts_missing',
        'high',
        'No Strict-Transport-Security header. A network attacker can strip TLS and serve the site over plain HTTP.',
        'Send "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload".'
      )
    );
  }

  // CSP — 5 points.
  if (!h['content-security-policy']) {
    earned -= 5;
    findings.push(
      finding(
        'headers.csp_missing',
        'medium',
        'No Content-Security-Policy header. The browser has no injected-script or resource-origin restrictions, so XSS has free rein.',
        'Define a Content-Security-Policy, starting restrictive and loosening per resource.'
      )
    );
  }

  // Clickjacking — 4 points. X-Frame-Options OR CSP frame-ancestors satisfies.
  const csp = (h['content-security-policy'] || '').toLowerCase();
  const framingProtected = !!h['x-frame-options'] || csp.includes('frame-ancestors');
  if (!framingProtected) {
    earned -= 4;
    findings.push(
      finding(
        'headers.framing_missing',
        'medium',
        'Neither X-Frame-Options nor a CSP frame-ancestors directive is set. The site can be framed for clickjacking.',
        'Send "X-Frame-Options: DENY" or a CSP "frame-ancestors \'none\'".'
      )
    );
  }

  // X-Content-Type-Options — 2 points.
  if ((h['x-content-type-options'] || '').toLowerCase() !== 'nosniff') {
    earned -= 2;
    findings.push(
      finding(
        'headers.nosniff_missing',
        'low',
        'No "X-Content-Type-Options: nosniff". Browsers may MIME-sniff responses, enabling content-type confusion attacks.',
        'Send "X-Content-Type-Options: nosniff".'
      )
    );
  }

  // Referrer-Policy — 2 points.
  if (!h['referrer-policy']) {
    earned -= 2;
    findings.push(
      finding(
        'headers.referrer_missing',
        'low',
        'No Referrer-Policy header. Full URLs may leak to third parties via the Referer header.',
        'Send "Referrer-Policy: strict-origin-when-cross-origin".'
      )
    );
  }

  // Permissions-Policy — 2 points.
  if (!h['permissions-policy']) {
    earned -= 2;
    findings.push(
      finding(
        'headers.permissions_missing',
        'low',
        'No Permissions-Policy header. Powerful browser features (camera, geolocation, etc.) are not explicitly constrained.',
        'Send a Permissions-Policy denying features the site does not use.'
      )
    );
  }

  // Server/version disclosure — informational, no score impact.
  const disclosed = [];
  if (h['x-powered-by']) disclosed.push(`X-Powered-By: ${h['x-powered-by']}`);
  if (h['server'] && /\d/.test(h['server'])) disclosed.push(`Server: ${h['server']}`);
  if (disclosed.length) {
    findings.push(
      finding(
        'headers.version_disclosure',
        'info',
        `Response discloses software/version details (${disclosed.join('; ')}). Not exploitable alone, but it hands attackers a target list.`,
        'Suppress or genericise Server and remove X-Powered-By.'
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
    evidence: { finalUrl: root.finalUrl, status: root.status },
  });
}
