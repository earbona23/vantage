import { joinTxtChunks, recordsWithPrefix } from './parse.js';
import { DKIM_SELECTORS, DEFAULT_SUBDOMAINS } from './constants.js';
import { discoverSubdomains } from './discover.js';

// Cap how many distinct hosts we resolve/probe for takeover in one scan, so a
// domain with a huge CT-log footprint stays bounded.
const MAX_PROBE_HOSTS = 60;

// Gather all raw public evidence for a domain using injected clients.
// This is the ONLY module that talks to the network. Every check downstream is
// a pure function over the object this returns, which is why the checks are
// trivially offline-testable and this module is tested with fake clients.
//
// deps = { dns, http, tls }
export async function collect(domain, deps, { subdomains = DEFAULT_SUBDOMAINS, selectors = DKIM_SELECTORS, discover = true } = {}) {
  const { dns, http, tls } = deps;
  const evidence = { domain };

  // --- Apex TXT: SPF ---
  evidence.spf = await safe(
    async () => recordsWithPrefix(await dns.resolveTxt(domain), 'v=spf1'),
    []
  );

  // --- DMARC / MTA-STS record / TLS-RPT / BIMI (subdomain TXT) ---
  evidence.dmarc = await safe(
    async () => recordsWithPrefix(await dns.resolveTxt(`_dmarc.${domain}`), 'v=dmarc1'),
    []
  );
  const mtastsRecord = await safe(
    async () => recordsWithPrefix(await dns.resolveTxt(`_mta-sts.${domain}`), 'v=stsv1'),
    []
  );
  evidence.tlsrpt = await safe(
    async () => recordsWithPrefix(await dns.resolveTxt(`_smtp._tls.${domain}`), 'v=tlsrptv1'),
    []
  );
  evidence.bimi = await safe(
    async () => recordsWithPrefix(await dns.resolveTxt(`default._bimi.${domain}`), 'v=bimi1'),
    []
  );

  // --- DKIM common selectors ---
  evidence.dkim = {};
  for (const sel of selectors) {
    const recs = await safe(async () => {
      const raw = await dns.resolveTxt(`${sel}._domainkey.${domain}`);
      return raw.map(joinTxtChunks);
    }, null);
    if (recs && recs.length) evidence.dkim[sel] = recs;
  }

  // --- MX ---
  evidence.mx = await safe(
    async () => {
      const recs = await dns.resolveMx(domain);
      return { present: recs.length > 0, records: recs, evaluable: true };
    },
    { present: false, records: [], evaluable: false }
  );

  // --- CAA ---
  evidence.caa = await safe(
    async () => {
      const recs = await dns.resolveCaa(domain);
      return { evaluable: true, records: recs };
    },
    { evaluable: false, records: [] }
  );

  // --- NS (informational, and used to confirm the zone resolves at all) ---
  evidence.ns = await safe(async () => dns.resolveNs(domain), []);

  // Does the apex zone resolve at all? If nothing answered — no NS, no records,
  // no MX — the domain looks like NXDOMAIN and the DNS-based checks must report
  // "not evaluable" rather than a false "record missing". This flag is what the
  // spf/dmarc/dkim/bimi/mx/caa checks read to make that call.
  evidence.zoneResolves =
    evidence.ns.length > 0 ||
    evidence.spf.length > 0 ||
    evidence.dmarc.length > 0 ||
    evidence.mx.present ||
    (evidence.caa.records && evidence.caa.records.length > 0);

  // --- DNSSEC via DoH (AD flag + DS presence) ---
  evidence.dnssec = await safe(
    async () => {
      const ans = await dns.doh(domain, 'DS');
      const ds = Array.isArray(ans.Answer) && ans.Answer.some((a) => a.type === 43);
      return { evaluable: true, ad: ans.AD === true, ds, error: null };
    },
    { evaluable: false, ad: false, ds: false, error: 'DoH query failed' }
  );

  // --- HTTP: root + security.txt + MTA-STS policy ---
  const rootRes = await http.get(`https://${domain}/`);
  const stRes = await http.get(`https://${domain}/.well-known/security.txt`);
  const mtastsPolicyRes = mtastsRecord.length
    ? await http.get(`https://mta-sts.${domain}/.well-known/mta-sts.txt`)
    : { ok: false, error: 'no record' };

  evidence.http = {
    root: rootRes,
    securitytxt: normaliseSecurityTxt(stRes),
  };
  evidence.mtasts = {
    record: mtastsRecord,
    policy: {
      fetched: !!(mtastsPolicyRes && mtastsPolicyRes.ok && mtastsPolicyRes.status === 200),
      body: mtastsPolicyRes && mtastsPolicyRes.ok ? mtastsPolicyRes.body : null,
      error: mtastsPolicyRes && mtastsPolicyRes.error ? mtastsPolicyRes.error : null,
    },
  };

  // --- TLS certificate ---
  evidence.tls = await tls.getCertificate(domain);

  // --- Discover the domain surface via Certificate Transparency, then probe
  //     every discovered host (plus the explicit/default seed labels) for a
  //     dangling-CNAME takeover. Discovery failing is its own explicit state. ---
  const discovery = discover
    ? await safe(() => discoverSubdomains(domain, http), { evaluable: false, source: 'crt.sh', names: [], total: 0, truncated: false, error: 'discovery threw' })
    : { evaluable: false, source: 'disabled', names: [], total: 0, truncated: false, error: 'discovery disabled' };
  evidence.discovery = discovery;

  const seedFqdns = (subdomains || []).map((label) => `${label}.${domain}`);
  const candidateFqdns = uniq([...seedFqdns, ...discovery.names]).slice(0, MAX_PROBE_HOSTS);
  evidence.subdomains = await probeHosts(candidateFqdns, dns, http, discovery);

  return evidence;
}

// A security.txt that returns anything other than a 200 with a body is treated
// as "not present" rather than a fetch we can parse.
function normaliseSecurityTxt(res) {
  if (res && res.ok && res.status === 200 && typeof res.body === 'string' && res.body.trim()) {
    return { ok: true, status: res.status, body: res.body, finalUrl: res.finalUrl, error: null };
  }
  return { ok: false, status: res ? res.status : 0, body: null, error: res ? res.error : 'unreachable' };
}

async function probeHosts(fqdns, dns, http, discovery) {
  const entries = {};
  const probed = [];
  let anyResolved = false;

  for (const fqdn of fqdns) {
    probed.push(fqdn);
    const cnames = await safe(async () => dns.resolveCname(fqdn), null);
    if (!cnames || cnames.length === 0) continue;

    anyResolved = true;
    const target = cnames[0];

    // Does the CNAME target itself resolve? NXDOMAIN of the target is a
    // takeover signal for some services.
    const targetResolves = await safe(
      async () => {
        const a = await dns.resolveCname(target).catch(() => null);
        if (a && a.length) return true;
        // Fall back to an A lookup via DoH to decide "resolves at all".
        const ans = await dns.doh(target, 'A');
        return Array.isArray(ans.Answer) && ans.Answer.length > 0;
      },
      null
    );

    // Fetch the target's page so a body fingerprint can match.
    let body = null;
    const res = await http.get(`https://${fqdn}/`);
    if (res && res.ok) body = res.body;

    entries[fqdn] = { cname: target, targetResolves, body };
  }

  return {
    evaluable: probed.length > 0,
    probed,
    entries,
    discovery: { source: discovery.source, evaluable: discovery.evaluable, discovered: discovery.total, error: discovery.error },
  };
}

function uniq(list) {
  return [...new Set(list)];
}

// Run a producer; on any thrown error return the fallback. Used to turn a hard
// DNS failure (timeout/servfail) into an evidence shape the checks can read as
// "not evaluable", while genuine empty answers already come back as [].
async function safe(fn, fallback) {
  try {
    return await fn();
  } catch {
    return fallback;
  }
}
