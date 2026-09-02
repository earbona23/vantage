import { TOOL_VERSION } from '../analyze.js';

// SARIF 2.1.0 output so findings can be ingested by code-scanning dashboards.
// Each vantage rule becomes a SARIF rule; each finding becomes a result.
const SEVERITY_TO_LEVEL = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

const SEVERITY_TO_RANK = {
  critical: 100,
  high: 80,
  medium: 60,
  low: 40,
  info: 20,
};

export function renderSarif(report) {
  const ruleIndex = new Map();
  const rules = [];
  const results = [];

  for (const f of report.findings) {
    if (!ruleIndex.has(f.rule_id)) {
      ruleIndex.set(f.rule_id, rules.length);
      rules.push({
        id: f.rule_id,
        name: f.rule_id,
        shortDescription: { text: f.message.slice(0, 120) },
        fullDescription: { text: f.message },
        help: { text: f.remediation },
        defaultConfiguration: { level: SEVERITY_TO_LEVEL[f.severity] || 'note' },
        properties: { category: f.category, 'security-severity': String(SEVERITY_TO_RANK[f.severity] || 0) },
      });
    }
    results.push({
      ruleId: f.rule_id,
      ruleIndex: ruleIndex.get(f.rule_id),
      level: SEVERITY_TO_LEVEL[f.severity] || 'note',
      message: { text: `${f.message} Remediation: ${f.remediation}` },
      properties: { severity: f.severity, check: f.check },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: `dns://${report.domain}` },
          },
          logicalLocations: [{ name: report.domain, kind: 'domain' }],
        },
      ],
    });
  }

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'vantage',
            informationUri: 'https://github.com/earbona23/vantage',
            version: TOOL_VERSION,
            rules,
          },
        },
        results,
        properties: {
          domain: report.domain,
          score: report.score,
          verdict: report.verdict ? report.verdict.grade : null,
          scanned_at: report.scanned_at,
        },
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
