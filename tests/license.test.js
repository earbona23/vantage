import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyLicense, resolveLicense } from '../src/license.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

function mint(args) {
  return execFileSync('node', [path.join(ROOT, 'scripts', 'mint_license.js'), ...args], {
    cwd: ROOT,
    encoding: 'utf8',
  }).trim();
}

test('mint -> verify round trip succeeds', () => {
  const lic = mint(['--licensee', 'Acme Corp', '--days', '30']);
  const res = verifyLicense(lic);
  assert.equal(res.valid, true);
  assert.equal(res.plan, 'pro');
  assert.equal(res.licensee, 'Acme Corp');
});

test('a tampered payload is rejected', () => {
  const lic = mint(['--licensee', 'Acme', '--days', '30']);
  const [payload, sig] = lic.split('.');
  // Flip a character in the signature.
  const badSig = sig.slice(0, -2) + (sig.slice(-2) === 'AA' ? 'BB' : 'AA');
  const res = verifyLicense(`${payload}.${badSig}`);
  assert.equal(res.valid, false);
});

test('an expired licence is rejected', () => {
  const lic = mint(['--licensee', 'Acme', '--exp', '2000-01-01T00:00:00Z']);
  const res = verifyLicense(lic, { now: new Date('2026-01-01') });
  assert.equal(res.valid, false);
  assert.match(res.reason, /expired/);
});

test('a licence signed with the future/expiry in range is valid', () => {
  const lic = mint(['--licensee', 'Acme', '--exp', '2099-01-01T00:00:00Z']);
  assert.equal(verifyLicense(lic, { now: new Date('2026-01-01') }).valid, true);
});

test('garbage strings are rejected, not treated as valid', () => {
  assert.equal(verifyLicense('not-a-license').valid, false);
  assert.equal(verifyLicense('').valid, false);
  assert.equal(verifyLicense('abc.def').valid, false);
  assert.equal(resolveLicense({ env: {} }).valid, false);
});

test('resolveLicense reads VANTAGE_LICENSE from env', () => {
  const lic = mint(['--licensee', 'EnvCo', '--days', '10']);
  const res = resolveLicense({ env: { VANTAGE_LICENSE: lic } });
  assert.equal(res.valid, true);
  assert.equal(res.licensee, 'EnvCo');
});
