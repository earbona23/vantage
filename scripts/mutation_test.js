#!/usr/bin/env node
// Mutation harness. It introduces one real defect at a time into the source,
// runs the whole test suite, and expects the suite to go RED. A mutant the
// tests still pass on ("survived") is a hole in the suite, not a success —
// the harness exits non-zero if any mutant survives.
//
// Each mutation flips a load-bearing decision: a severity, a threshold, a
// verdict boundary, the three-state exclusion, a fingerprint match. If a test
// does not notice, the corresponding guarantee is not actually being tested.
//
// Usage: node scripts/mutation_test.js
//        node scripts/mutation_test.js --verbose

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const VERBOSE = process.argv.includes('--verbose');

// A mutation = { name, file, find, replace }. `find` must occur exactly once in
// the target file, so a mutation is unambiguous; the harness asserts that.
const MUTATIONS = [
  {
    name: 'SPF +all no longer zeroed (critical downgraded)',
    file: 'src/checks/spf.js',
    find: "if (qualifier === 'pass') {",
    replace: "if (qualifier === 'never_matches_pass') {",
  },
  {
    name: 'SPF missing earns full marks instead of zero',
    file: 'src/checks/spf.js',
    find: 'weight: WEIGHT, earned: 0, findings, evidence: { records } });',
    replace: 'weight: WEIGHT, earned: WEIGHT, findings, evidence: { records } });',
  },
  {
    name: 'DMARC reject scored the same as none',
    file: 'src/checks/dmarc.js',
    find: "if (policy === 'reject') {\n    earned = WEIGHT;",
    replace: "if (policy === 'reject') {\n    earned = 6;",
  },
  {
    name: 'DMARC none treated as clean (no finding)',
    file: 'src/checks/dmarc.js',
    find: "} else if (policy === 'none') {\n    earned = 6;",
    replace: "} else if (policy === 'none') {\n    earned = WEIGHT;",
  },
  {
    name: 'Verdict A boundary lowered to 80',
    file: 'src/constants.js',
    find: "{ grade: 'A', min: 90, max: 100, label: 'strong public posture' },",
    replace: "{ grade: 'A', min: 80, max: 100, label: 'strong public posture' },",
  },
  {
    name: 'not_evaluable folded into the score denominator',
    file: 'src/scoring.js',
    find: 'if (r.state === STATE.NOT_EVALUABLE) {\n      notEvaluable += 1;\n      continue;\n    }',
    replace: 'if (r.state === STATE.NOT_EVALUABLE) {\n      notEvaluable += 1;\n    }',
  },
  {
    name: 'score returns 0 instead of null when nothing is evaluable',
    file: 'src/scoring.js',
    find: 'const value = weight > 0 ? Math.round((100 * earned) / weight) : null;',
    replace: 'const value = weight > 0 ? Math.round((100 * earned) / weight) : 0;',
  },
  {
    name: 'HSTS missing downgraded to no deduction',
    file: 'src/checks/headers.js',
    find: "    earned -= 5;\n    findings.push(\n      finding(\n        'headers.hsts_missing',",
    replace: "    earned -= 0;\n    findings.push(\n      finding(\n        'headers.hsts_missing',",
  },
  {
    name: 'clickjacking protection ignores CSP frame-ancestors',
    file: 'src/checks/headers.js',
    find: "const framingProtected = !!h['x-frame-options'] || csp.includes('frame-ancestors');",
    replace: "const framingProtected = !!h['x-frame-options'];",
  },
  {
    name: 'MTA-STS not-evaluable gate removed (scores a domain with no MX)',
    file: 'src/checks/mtasts.js',
    find: '  if (!mx.present) {\n    return notEvaluable({',
    replace: '  if (false && !mx.present) {\n    return notEvaluable({',
  },
  {
    name: 'takeover dangling CNAME no longer zeroes the check',
    file: 'src/checks/takeover.js',
    find: 'earned: 0,\n    findings,\n    evidence: { probed: s.probed, dangling: dangling.length, entries: dangling },',
    replace: 'earned: WEIGHT,\n    findings,\n    evidence: { probed: s.probed, dangling: dangling.length, entries: dangling },',
  },
  {
    name: 'Shopify takeover fingerprint broken',
    file: 'src/fingerprints.js',
    find: "body: 'Sorry, this shop is currently unavailable',",
    replace: "body: 'this text never appears on the unclaimed page',",
  },
  {
    name: 'security.txt expiry check disabled (expired reads as fine)',
    file: 'src/checks/securitytxt.js',
    find: 'if (Number.isFinite(exp) && exp < now.getTime()) {',
    replace: 'if (Number.isFinite(exp) && exp < 0) {',
  },
  {
    name: 'TLS expired severity downgraded from critical',
    file: 'src/checks/tls.js',
    find: "'tls.expired',\n          'critical',",
    replace: "'tls.expired',\n          'low',",
  },
  {
    name: 'licence expiry no longer enforced',
    file: 'src/license.js',
    find: 'if (Number.isFinite(exp) && exp < now.getTime()) {',
    replace: 'if (Number.isFinite(exp) && exp < 0) {',
  },
  {
    name: 'licence signature check bypassed',
    file: 'src/license.js',
    find: 'if (!ok) return { valid: false, reason: \'bad signature\' };',
    replace: 'if (!ok) ok = true;',
  },
  {
    name: 'zoneResolves gate removed (dead domain scored as SPF-missing)',
    file: 'src/checks/spf.js',
    find: 'if (evidence.zoneResolves === false) {',
    replace: 'if (evidence.zoneResolves === null) {',
  },
  {
    name: 'crt.sh discovery includes the apex/foreign names (surface polluted)',
    file: 'src/discover.js',
    find: "if (name && name !== domain.toLowerCase() && name.endsWith(suffix)) {",
    replace: "if (name) {",
  },
  {
    name: 'crt.sh non-JSON body treated as "no subdomains" instead of not-evaluable',
    file: 'src/discover.js',
    find: "return { evaluable: false, source: 'crt.sh', names: [], total: 0, truncated: false, error: 'crt.sh returned non-JSON' };",
    replace: "return { evaluable: true, source: 'crt.sh', names: [], total: 0, truncated: false, error: null };",
  },
  {
    name: 'takeover reports CLEAN when discovery failed (folds not-evaluable into clean)',
    file: 'src/checks/takeover.js',
    find: 'if (disc.evaluable === false) {',
    replace: 'if (disc.evaluable === null) {',
  },
  {
    name: 'address guard: IPv6 answers no longer checked',
    file: 'src/net/http.js',
    find: "if (net.isIPv6(ip)) return BLOCKED.check(ip, 'ipv6');",
    replace: "if (net.isIPv6(ip)) return false;",
  },
  {
    name: 'address guard: unparseable address allowed instead of refused',
    file: 'src/net/http.js',
    find: 'return true; // unrecognised address shape: refuse',
    replace: 'return false; // unrecognised address shape: refuse',
  },
  {
    name: 'address guard: 6to4 prefix (embeds an IPv4) dropped from the deny-list',
    file: 'src/net/http.js',
    find: "['2002::', 16],",
    replace: "['2002::', 128],",
  },
  {
    name: 'address guard: NAT64 prefix (embeds an IPv4) dropped from the deny-list',
    file: 'src/net/http.js',
    find: "['64:ff9b::', 96],",
    replace: "['64:ff9b::', 128],",
  },
  {
    name: 'address guard: lookup accepts a blocked resolution',
    file: 'src/net/http.js',
    find: "return callback(new Error('blocked: host resolves to a private or reserved address'));",
    replace: "break;",
  },
  {
    name: 'address guard: HTTPS client no longer resolves through the guard',
    file: 'src/net/http.js',
    find: '        lookup: guardedLookup,\n      },\n      (res) => {',
    replace: '      },\n      (res) => {',
  },
  {
    name: 'address guard: TLS probe no longer resolves through the guard',
    file: 'src/net/tls.js',
    find: '        lookup: guardedLookup,',
    replace: '',
  },
];

function runTests() {
  try {
    const testFiles = fs.readdirSync(path.join(ROOT, 'tests'), { recursive: true })
      .filter((f) => String(f).endsWith('.test.js'))
      .map((f) => path.join('tests', String(f)));
    execFileSync('node', ['--test', ...testFiles], { cwd: ROOT, stdio: VERBOSE ? 'inherit' : 'pipe' });
    return true; // suite passed
  } catch {
    return false; // suite failed (a test caught the mutant)
  }
}

function main() {
  // Baseline: the suite must be green before we start breaking things.
  process.stdout.write('baseline: running suite... ');
  if (!runTests()) {
    process.stdout.write('FAILED\n');
    process.stderr.write('Refusing to mutate: the test suite is not green to begin with.\n');
    process.exit(2);
  }
  process.stdout.write('green\n\n');

  let killed = 0;
  const survived = [];

  for (const mut of MUTATIONS) {
    const filePath = path.join(ROOT, mut.file);
    const original = fs.readFileSync(filePath, 'utf8');

    const occurrences = original.split(mut.find).length - 1;
    if (occurrences !== 1) {
      process.stderr.write(`SKIP  ${mut.name}\n      pattern occurs ${occurrences}x in ${mut.file} (need exactly 1)\n`);
      survived.push({ ...mut, reason: `ambiguous pattern (${occurrences} matches)` });
      continue;
    }

    const mutated = original.replace(mut.find, mut.replace);
    fs.writeFileSync(filePath, mutated);
    let suitePassed;
    try {
      suitePassed = runTests();
    } finally {
      fs.writeFileSync(filePath, original); // always restore
    }

    if (suitePassed) {
      // The suite stayed green with a real defect injected: the mutant survived.
      process.stdout.write(`SURVIVED  ${mut.name}\n`);
      survived.push(mut);
    } else {
      process.stdout.write(`killed    ${mut.name}\n`);
      killed += 1;
    }
  }

  process.stdout.write(`\nmutation score: ${killed}/${MUTATIONS.length} killed\n`);
  if (survived.length) {
    process.stdout.write(`${survived.length} survived — the suite does not defend these guarantees.\n`);
    process.exit(1);
  }
  process.stdout.write('all mutants killed.\n');
}

main();
