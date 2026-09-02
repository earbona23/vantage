import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

// Zero dependencies is a security property, so it is enforced by a test rather
// than by good intentions. If either of these ever fails, the property is gone.

test('package.json declares no runtime and no dev dependencies', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const deps = Object.keys(pkg.dependencies || {});
  const dev = Object.keys(pkg.devDependencies || {});
  const optional = Object.keys(pkg.optionalDependencies || {});
  const peer = Object.keys(pkg.peerDependencies || {});
  assert.deepEqual(deps, [], `unexpected dependencies: ${deps.join(', ')}`);
  assert.deepEqual(dev, [], `unexpected devDependencies: ${dev.join(', ')}`);
  assert.deepEqual(optional, [], `unexpected optionalDependencies: ${optional.join(', ')}`);
  assert.deepEqual(peer, [], `unexpected peerDependencies: ${peer.join(', ')}`);
});

test('no source file imports a third-party package', () => {
  const files = walk(path.join(ROOT, 'src')).concat(walk(path.join(ROOT, 'scripts')));
  const importRe = /(?:import\s[^'"]*?from\s*|import\s*|require\s*\(\s*)['"]([^'"]+)['"]/g;
  const offenders = [];

  for (const file of files) {
    const code = fs.readFileSync(file, 'utf8');
    let m;
    while ((m = importRe.exec(code)) !== null) {
      const spec = m[1];
      const isRelative = spec.startsWith('.') || spec.startsWith('/');
      const isNodeBuiltin = spec.startsWith('node:');
      if (!isRelative && !isNodeBuiltin) {
        offenders.push(`${path.relative(ROOT, file)} -> ${spec}`);
      }
    }
  }

  assert.deepEqual(offenders, [], `third-party imports found:\n${offenders.join('\n')}`);
});

test('every node builtin is imported with the node: prefix', () => {
  // Belt and suspenders: catches a bare "crypto"/"fs" import that would still
  // resolve but breaks the explicit-builtin discipline the zero-dep claim rests on.
  const files = walk(path.join(ROOT, 'src')).concat(walk(path.join(ROOT, 'scripts')));
  const bareBuiltins = ['fs', 'path', 'crypto', 'https', 'http', 'dns', 'tls', 'url', 'os', 'child_process'];
  const importRe = /(?:from\s*|require\s*\(\s*)['"]([^'"]+)['"]/g;
  const offenders = [];
  for (const file of files) {
    const code = fs.readFileSync(file, 'utf8');
    let m;
    while ((m = importRe.exec(code)) !== null) {
      if (bareBuiltins.includes(m[1])) offenders.push(`${path.relative(ROOT, file)} -> ${m[1]}`);
    }
  }
  assert.deepEqual(offenders, [], `bare builtin imports (use node: prefix):\n${offenders.join('\n')}`);
});

function walk(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(p));
    else if (entry.name.endsWith('.js')) out.push(p);
  }
  return out;
}
