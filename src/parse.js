// Pure parsers for the small DNS/HTTP text formats this tool reads.
// No network, no side effects — trivially testable.

// Split a TXT record made of tag=value pairs (DMARC, MTA-STS record, TLS-RPT,
// BIMI) into a lowercased-key map. Values keep their original case.
// Duplicate keys keep the first occurrence, which matches how resolvers treat
// most of these records.
export function parseTagValue(str, sep = ';') {
  const out = {};
  if (typeof str !== 'string') return out;
  for (const part of str.split(sep)) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim().toLowerCase();
    const value = trimmed.slice(eq + 1).trim();
    if (key && !(key in out)) out[key] = value;
  }
  return out;
}

// SPF is a space-separated list of mechanisms/modifiers, not tag=value.
// Returns the raw terms lowercased for matching.
export function parseSpfTerms(record) {
  if (typeof record !== 'string') return [];
  return record
    .trim()
    .split(/\s+/)
    .map((t) => t.toLowerCase())
    .filter(Boolean);
}

// Given a set of TXT records (each an array of strings joined per record),
// return the ones that start with a given prefix, case-insensitive.
export function recordsWithPrefix(records, prefix) {
  const p = prefix.toLowerCase();
  return (records || [])
    .map(joinTxtChunks)
    .filter((r) => r.toLowerCase().startsWith(p));
}

// node:dns returns TXT records as arrays of string chunks (a single record can
// be split into 255-byte chunks). Join them back with no separator, per RFC.
export function joinTxtChunks(record) {
  if (Array.isArray(record)) return record.join('');
  return typeof record === 'string' ? record : '';
}

// Parse an SPF "all" mechanism qualifier. Returns one of:
//   'pass' (+all), 'fail' (-all), 'softfail' (~all), 'neutral' (?all), null
export function spfAllQualifier(terms) {
  for (const term of terms) {
    if (term === 'all' || term === '+all') return 'pass';
    if (term === '-all') return 'fail';
    if (term === '~all') return 'softfail';
    if (term === '?all') return 'neutral';
  }
  return null;
}

// Parse an HSTS header value into { maxAge, includeSubDomains, preload }.
export function parseHsts(value) {
  const out = { maxAge: null, includeSubDomains: false, preload: false };
  if (typeof value !== 'string') return out;
  for (const part of value.split(';')) {
    const t = part.trim().toLowerCase();
    if (t.startsWith('max-age=')) {
      const n = parseInt(t.slice('max-age='.length), 10);
      if (Number.isFinite(n)) out.maxAge = n;
    } else if (t === 'includesubdomains') {
      out.includeSubDomains = true;
    } else if (t === 'preload') {
      out.preload = true;
    }
  }
  return out;
}

// Parse a security.txt body (RFC 9116) into a case-insensitive field map.
// Multi-valued fields (Contact) collect into arrays. Comments (#) ignored.
export function parseSecurityTxt(body) {
  const fields = {};
  if (typeof body !== 'string') return fields;
  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (!key || !value) continue;
    if (fields[key]) fields[key].push(value);
    else fields[key] = [value];
  }
  return fields;
}

// Normalise a domain: strip scheme, path, trailing dot, lowercase.
export function normaliseDomain(input) {
  if (typeof input !== 'string') return '';
  let d = input.trim().toLowerCase();
  d = d.replace(/^[a-z]+:\/\//, '');
  d = d.replace(/\/.*$/, '');
  d = d.replace(/\.$/, '');
  return d;
}
