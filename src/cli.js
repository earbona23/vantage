import fs from 'node:fs';
import { scanDomain } from './analyze.js';
import { scanBatch, diffReports } from './pro.js';
import { resolveLicense } from './license.js';
import { renderTerminal } from './output/terminal.js';
import { renderJson } from './output/json.js';
import { renderSarif } from './output/sarif.js';
import { renderMarkdown } from './output/markdown.js';
import { renderJsonl } from './output/jsonl.js';
import { renderHtml } from './output/html.js';
import { TOOL_VERSION } from './analyze.js';

const HELP = `vantage — transparent external security-posture scorer

USAGE
  vantage scan <domain> [--format terminal|json|sarif|md] [--subdomains a,b]
                        [--raw] [--no-discover] [--color]
  vantage batch <file>  [--format json|jsonl] [--license <str>]        (PRO)
  vantage diff <domain> --snapshot <file> [--save <file>] [--format json|md] [--license <str>]  (PRO)
  vantage version
  vantage help

FORMATS
  terminal  human-readable (default)
  json      stable JSON contract
  sarif     SARIF 2.1.0 for code-scanning dashboards
  md        Markdown for a PR comment / issue

FLAGS
  --raw / --all   dump EVERYTHING found (every subdomain, record, header) raw,
                  so nothing can hide behind the score
  --no-discover   skip Certificate-Transparency (crt.sh) subdomain discovery
  --subdomains    extra seed hosts to probe, on top of discovery

DISCOVERY
  vantage also FINDS the domain's surface from public Certificate Transparency
  logs (crt.sh) and probes every discovered host for subdomain takeover. If
  crt.sh does not answer, discovery is reported as NOT EVALUABLE — never as
  "nothing found".

PRO features (batch scanning, monitoring diffs, jsonl/html) require a licence,
supplied via --license or the VANTAGE_LICENSE environment variable. The core
scoring is free and never gated.

vantage reads only PUBLIC data (DNS, TLS, HTTP headers, CT logs). It does not
exploit, port-scan, or use proprietary feeds. Every point in the score traces
to a rule you can read and argue with.`;

// Parse argv (already sliced past node + script) into a command descriptor.
// Pure and testable.
export function parseArgs(argv) {
  const args = [...argv];
  // El primer argumento se tomaba SIEMPRE como nombre de comando, asi que `vantage --help`
  // convertia `--help` en el comando y nunca llegaba al manejador de abajo (que si existe y
  // si mira `opts.help`). Resultado: `vantage --help` respondia
  // `Unknown command: --help` con salida 2, mientras `vantage scan --help` funcionaba
  // perfecto — el flag solo se parseaba si venia DESPUES de un comando.
  // `--help` y `-h` sin comando son la convencion universal: si esta herramienta pide que
  // confies en ella para mirar tu superficie expuesta, lo primero que escribe cualquiera
  // tiene que funcionar.
  const first = args[0];
  let command;
  if (first === '--help' || first === '-h') {
    args.shift();
    command = 'help';
  } else if (first === '--version' || first === '-V') {
    args.shift();
    command = 'version';
  } else {
    command = args.shift() || 'help';
  }
  const opts = { _: [] };
  while (args.length) {
    const a = args.shift();
    if (a === '--format') opts.format = args.shift();
    else if (a === '--subdomains') opts.subdomains = (args.shift() || '').split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--snapshot') opts.snapshot = args.shift();
    else if (a === '--save') opts.save = args.shift();
    else if (a === '--license') opts.license = args.shift();
    else if (a === '--color') opts.color = true;
    else if (a === '--raw' || a === '--all') opts.raw = true;
    else if (a === '--no-discover') opts.discover = false;
    else if (a === '--help' || a === '-h') opts.help = true;
    else opts._.push(a);
  }
  return { command, opts };
}

const FREE_FORMATS = new Set(['terminal', 'json', 'sarif', 'md', undefined]);

// Render a single report in a free-tier format.
export function renderReport(report, format, { raw = false } = {}) {
  switch (format) {
    case 'json':
      return renderJson(report);
    case 'sarif':
      return renderSarif(report);
    case 'md':
      return renderMarkdown(report);
    case 'terminal':
    case undefined:
      return renderTerminal(report, { raw });
    default:
      throw new Error(`Unknown format: ${format}`);
  }
}

// main returns an exit code and writes via the injected writer (defaults to
// console). Deps injectable for tests.
export async function main(argv, { write = (s) => process.stdout.write(s + '\n'), err = (s) => process.stderr.write(s + '\n'), deps, env = process.env } = {}) {
  const { command, opts } = parseArgs(argv);

  if (command === 'help' || opts.help) {
    write(HELP);
    return 0;
  }
  if (command === 'version') {
    write(TOOL_VERSION);
    return 0;
  }

  try {
    if (command === 'scan') {
      const domain = opts._[0];
      if (!domain) {
        err('scan requires a domain. See "vantage help".');
        return 2;
      }
      const report = await scanDomain(domain, {
        deps,
        subdomains: opts.subdomains,
        discover: opts.discover,
        includeRaw: !!opts.raw,
      });
      write(renderReport(report, opts.format, { raw: !!opts.raw }));
      return exitForScore(report);
    }

    if (command === 'batch') {
      const lic = requirePro(opts, env);
      if (!lic.ok) {
        err(lic.message);
        return 3;
      }
      const file = opts._[0];
      if (!file) {
        err('batch requires a file of domains (one per line).');
        return 2;
      }
      const domains = readLines(file);
      const reports = await scanBatch(domains, { deps });
      write(opts.format === 'jsonl' ? renderJsonl(reports) : renderJson(reports));
      return 0;
    }

    if (command === 'diff') {
      const lic = requirePro(opts, env);
      if (!lic.ok) {
        err(lic.message);
        return 3;
      }
      const domain = opts._[0];
      if (!domain || !opts.snapshot) {
        err('diff requires a domain and --snapshot <file>.');
        return 2;
      }
      const previous = JSON.parse(fs.readFileSync(opts.snapshot, 'utf8'));
      const current = await scanDomain(domain, { deps });
      if (opts.save) fs.writeFileSync(opts.save, renderJson(current));
      const d = diffReports(previous, current);
      write(opts.format === 'md' ? renderDiffMarkdown(d) : renderJson(d));
      return d.changed ? 1 : 0;
    }

    err(`Unknown command: ${command}. See "vantage help".`);
    return 2;
  } catch (e) {
    err(`error: ${e.message}`);
    return 2;
  }
}

function requirePro(opts, env) {
  // Guard against a PRO feature being requested with a free-only format leak.
  const lic = resolveLicense({ license: opts.license, env });
  if (!lic.valid) {
    return {
      ok: false,
      message: `This is a PRO feature and requires a valid licence (${lic.reason}). Supply --license or set VANTAGE_LICENSE. The free "scan" command is not gated.`,
    };
  }
  return { ok: true, license: lic };
}

// A scan that finds nothing critical/high exits 0; findings raise the code so
// the tool is usable as a CI gate. Not-evaluable alone never fails CI.
function exitForScore(report) {
  const sev = report.summary.findings_by_severity;
  if (sev.critical > 0) return 1;
  return 0;
}

function readLines(file) {
  return fs
    .readFileSync(file, 'utf8')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
}

function renderDiffMarkdown(d) {
  const out = [`# vantage diff — \`${d.domain}\``, ''];
  out.push(`score: ${fmt(d.score_before)} → ${fmt(d.score_after)} (${d.score_delta >= 0 ? '+' : ''}${d.score_delta})`);
  out.push('');
  if (!d.changed) {
    out.push('No change in findings or check states.');
    return out.join('\n');
  }
  if (d.appeared.length) {
    out.push('## New findings');
    for (const f of d.appeared) out.push(`- **${f.severity}** \`${f.rule_id}\` — ${f.message}`);
    out.push('');
  }
  if (d.resolved.length) {
    out.push('## Resolved');
    for (const f of d.resolved) out.push(`- \`${f.rule_id}\` — ${f.message}`);
    out.push('');
  }
  if (d.state_changes.length) {
    out.push('## Check state changes');
    for (const s of d.state_changes) out.push(`- ${s.check}: ${s.from} → ${s.to}`);
  }
  return out.join('\n');
}

function fmt(v) {
  return v === null || v === undefined ? '—' : v;
}

// Expose FREE_FORMATS and renderHtml for callers/tests that want them.
export { FREE_FORMATS, renderHtml };
