// Subdomain discovery from public Certificate Transparency logs (crt.sh).
//
// This is what makes vantage FIND the domain's surface rather than only scoring
// hosts you hand it: every TLS certificate ever issued for the domain is logged
// publicly, and crt.sh exposes those logs as JSON over HTTPS. We read the names
// out of that log. Still public data, still zero dependencies (node:https via
// the injected HTTP client), still no exploitation.
//
// The HTTP client is injected, so this is tested offline against a recorded
// crt.sh fixture. If crt.sh does not answer, discovery is NOT EVALUABLE — an
// explicit state, never silently "nothing found".

// crt.sh returns a big JSON array; cap how many distinct names we keep so a
// domain with tens of thousands of certs does not turn one scan into a crawl.
const DEFAULT_MAX = 100;

export async function discoverSubdomains(domain, http, { max = DEFAULT_MAX } = {}) {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  // Raise the body cap: crt.sh responses are frequently multi-megabyte, and a
  // truncated body would not parse as JSON.
  const res = await http.get(url, { maxBodyBytes: 8 * 1024 * 1024, timeoutMs: 15000 });

  if (!res || !res.ok || res.status !== 200 || !res.body) {
    return {
      evaluable: false,
      source: 'crt.sh',
      names: [],
      total: 0,
      truncated: false,
      error: res && res.error ? res.error : `crt.sh returned status ${res ? res.status : 0}`,
    };
  }

  let rows;
  try {
    rows = JSON.parse(res.body);
  } catch {
    // A non-JSON body (often a truncated or rate-limited response) is honestly
    // "could not evaluate", not "no subdomains".
    return { evaluable: false, source: 'crt.sh', names: [], total: 0, truncated: false, error: 'crt.sh returned non-JSON' };
  }

  return parseCrtShRows(rows, domain, max);
}

// Pure parser, split out so it is unit-testable without any client at all.
export function parseCrtShRows(rows, domain, max = DEFAULT_MAX) {
  const set = new Set();
  const suffix = `.${domain.toLowerCase()}`;
  for (const row of Array.isArray(rows) ? rows : []) {
    const nv = row && (row.name_value || row.common_name);
    if (!nv) continue;
    for (let name of String(nv).split(/\s+/)) {
      name = name.trim().toLowerCase().replace(/^\*\./, '');
      // Keep only real subdomains of the target: something.<domain>, not the
      // apex itself and not an unrelated name.
      if (name && name !== domain.toLowerCase() && name.endsWith(suffix)) {
        set.add(name);
      }
    }
  }
  const all = [...set].sort();
  const names = all.slice(0, max);
  return {
    evaluable: true,
    source: 'crt.sh',
    names,
    total: all.length,
    truncated: all.length > names.length,
    error: null,
  };
}
