import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs, renderReport, main } from '../src/cli.js';
import { analyzeEvidence } from '../src/analyze.js';
import { weakEvidence } from './fixtures/evidence.js';
import { makeDns, makeHttp, makeTls } from './fixtures/fake-clients.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

function mint(args) {
  return execFileSync('node', [path.join(ROOT, 'scripts', 'mint_license.js'), ...args], { cwd: ROOT, encoding: 'utf8' }).trim();
}

// A tiny fixture deps set for the "scan" command.
function scanDeps(domain = 'cli.test') {
  return {
    dns: makeDns({
      txt: { [domain]: ['v=spf1 -all'], [`_dmarc.${domain}`]: ['v=DMARC1; p=reject; rua=mailto:d@cli.test'] },
      mx: {},
      caa: { [domain]: [{ issue: 'letsencrypt.org' }, { issuewild: ';' }] },
      ns: { [domain]: ['ns1'] },
      cname: {},
      doh: { [`${domain}|DS`]: { Status: 0, AD: true, Answer: [{ type: 43 }] } },
    }),
    http: makeHttp({
      [`https://${domain}/`]: {
        status: 200,
        headers: {
          'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
          'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
          'X-Content-Type-Options': 'nosniff',
          'Referrer-Policy': 'no-referrer',
          'Permissions-Policy': 'geolocation=()',
        },
      },
      [`https://${domain}/.well-known/security.txt`]: { status: 200, body: 'Contact: mailto:s@cli.test\nExpires: 2099-01-01T00:00:00Z' },
    }),
    tls: makeTls({ [domain]: { authorized: true, protocol: 'TLSv1.3', daysToExpiry: 90 } }),
  };
}

test('parseArgs parses command, positional and flags', () => {
  const { command, opts } = parseArgs(['scan', 'example.com', '--format', 'json', '--subdomains', 'a,b', '--color']);
  assert.equal(command, 'scan');
  assert.equal(opts._[0], 'example.com');
  assert.equal(opts.format, 'json');
  assert.deepEqual(opts.subdomains, ['a', 'b']);
  assert.equal(opts.color, true);
});

test('renderReport supports every free format', () => {
  const report = analyzeEvidence(weakEvidence());
  assert.match(renderReport(report, 'json'), /"schema"/);
  assert.match(renderReport(report, 'sarif'), /2\.1\.0/);
  assert.match(renderReport(report, 'md'), /## Findings/);
  assert.match(renderReport(report, undefined), /vantage report/);
  assert.throws(() => renderReport(report, 'bogus'));
});

test('main scan writes a report and returns 0 when no critical findings', async () => {
  let out = '';
  const code = await main(['scan', 'cli.test', '--format', 'json'], { write: (s) => (out += s), deps: scanDeps() });
  assert.equal(code, 0);
  const parsed = JSON.parse(out);
  assert.equal(parsed.domain, 'cli.test');
  assert.equal(parsed.tool, 'vantage');
});

test('main scan without a domain returns exit 2', async () => {
  let err = '';
  const code = await main(['scan'], { err: (s) => (err += s), deps: scanDeps() });
  assert.equal(code, 2);
  assert.match(err, /requires a domain/);
});

test('PRO batch is refused without a valid licence', async () => {
  let err = '';
  const code = await main(['batch', 'domains.txt'], { err: (s) => (err += s), env: {} });
  assert.equal(code, 3);
  assert.match(err, /PRO feature/);
});

test('PRO batch is allowed with a valid licence (env)', async () => {
  const lic = mint(['--licensee', 'CLI Co', '--days', '10']);
  // Point at a domains file that does not exist to keep it offline — the
  // licence gate is what we are testing, and a bad file yields a clean error
  // AFTER the gate passes (exit 2, not the gate's 3).
  let err = '';
  const code = await main(['batch', '/no/such/file.txt'], { err: (s) => (err += s), env: { VANTAGE_LICENSE: lic } });
  assert.notEqual(code, 3); // gate passed
});

test('help and version work', async () => {
  let out = '';
  assert.equal(await main(['help'], { write: (s) => (out += s) }), 0);
  assert.match(out, /USAGE/);
  out = '';
  assert.equal(await main(['version'], { write: (s) => (out += s) }), 0);
  assert.match(out, /\d+\.\d+\.\d+/);
});

// ── Flags de ayuda y version como PRIMER argumento ───────────────────────────
// `vantage --help` respondia `Unknown command: --help` y salia 2: `parseArgs` tomaba el
// primer argumento SIEMPRE como nombre de comando, asi que el flag nunca llegaba al
// manejador que si lo contempla. `vantage scan --help` funcionaba, lo que hacia el defecto
// invisible para cualquiera que ya supiera los comandos — y visible para todo el que no.
test('--help y -h como primer argumento son el comando help', () => {
  for (const flag of ['--help', '-h']) {
    assert.equal(parseArgs([flag]).command, 'help', `${flag} deberia resolver a help`);
  }
});

test('--version y -V como primer argumento son el comando version', () => {
  for (const flag of ['--version', '-V']) {
    assert.equal(parseArgs([flag]).command, 'version', `${flag} deberia resolver a version`);
  }
});

test('sin argumentos sigue resolviendo a help', () => {
  assert.equal(parseArgs([]).command, 'help');
});

test('un comando real no se toca y conserva sus flags', () => {
  const r = parseArgs(['scan', 'example.com', '--format', 'json']);
  assert.equal(r.command, 'scan');
  assert.equal(r.opts.format, 'json');
});

// La direccion inversa, que es la que importa: el arreglo NO debe convertir cualquier cosa
// en help. Un comando inexistente tiene que seguir fallando con salida 2, o se perderia el
// tercer resultado que esta herramienta predica en su propio README.
test('un comando inexistente NO se vuelve help: debe seguir fallando', () => {
  assert.equal(parseArgs(['comando-inexistente']).command, 'comando-inexistente');
});
