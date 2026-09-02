// Shared constants. No logic here that a check depends on for a verdict —
// verdict logic lives in the individual checks and in scoring.js.

// Severity ordering, worst first. Used only for sorting and display.
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

// The three states a check can report. This is the whole point of the tool:
// "I could not look" is never folded into "clean".
export const STATE = Object.freeze({
  FINDING: 'finding', // we looked and found something worth fixing
  CLEAN: 'clean', // we looked and it is fine
  NOT_EVALUABLE: 'not_evaluable', // we could not look (timeout, NXDOMAIN, no MX, ...)
});

// Verdict bands over the 0..100 score. Documented in the README.
// A band is [min, max] inclusive.
export const VERDICT_BANDS = [
  { grade: 'A', min: 90, max: 100, label: 'strong public posture' },
  { grade: 'B', min: 75, max: 89, label: 'good, with gaps' },
  { grade: 'C', min: 60, max: 74, label: 'mixed' },
  { grade: 'D', min: 40, max: 59, label: 'weak' },
  { grade: 'F', min: 0, max: 39, label: 'poor public posture' },
];

// Common DKIM selectors. Absence of all of these is inconclusive, not a failure.
export const DKIM_SELECTORS = [
  'default',
  'google',
  'selector1',
  'selector2',
  'k1',
  'k2',
  'mail',
  'dkim',
  's1',
  's2',
  'mandrill',
  'mxvault',
  'zoho',
  'protonmail',
  'sendgrid',
];

// Subdomains probed for dangling-CNAME takeover when the caller gives no list.
export const DEFAULT_SUBDOMAINS = [
  'www',
  'mail',
  'blog',
  'shop',
  'docs',
  'status',
  'cdn',
  'assets',
  'staging',
  'dev',
  'api',
  'app',
  'support',
  'help',
  'portal',
];

// HSTS max-age we treat as "long enough". 180 days.
export const HSTS_MIN_MAX_AGE = 15552000;
