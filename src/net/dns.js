import { Resolver } from 'node:dns/promises';
import https from 'node:https';

// Real DNS client. Every method returns a promise. The client distinguishes
// two failure modes that matter to the three-state model:
//   - "no such record" (ENODATA / ENOTFOUND / NXDOMAIN) -> resolves to an empty
//     result. That is a fact about the domain, not a failure to look.
//   - anything else (timeout, SERVFAIL, refused) -> throws. The collector turns
//     that into "not evaluable".
//
// The client is injectable: analyze.js accepts any object with this shape, so
// tests pass a fake backed by fixtures and never touch the network.

const EMPTY_CODES = new Set(['ENODATA', 'ENOTFOUND', 'ENOTIMP', 'NXDOMAIN']);

function emptyOnMissing(promise, empty = []) {
  return promise.catch((err) => {
    if (err && EMPTY_CODES.has(err.code)) return empty;
    throw err;
  });
}

export function createDnsClient({ timeoutMs = 5000, servers } = {}) {
  const resolver = new Resolver({ timeout: timeoutMs, tries: 2 });
  if (Array.isArray(servers) && servers.length) resolver.setServers(servers);

  return {
    resolveTxt: (name) => emptyOnMissing(resolver.resolveTxt(name)),
    resolveMx: (name) => emptyOnMissing(resolver.resolveMx(name)),
    resolveCaa: (name) => emptyOnMissing(resolver.resolveCaa(name)),
    resolveNs: (name) => emptyOnMissing(resolver.resolveNs(name)),
    resolveCname: (name) => emptyOnMissing(resolver.resolveCname(name)),

    // DNS-over-HTTPS JSON query, used only for DNSSEC state (the AD flag and DS
    // presence), which node:dns does not expose. Cloudflare's resolver is a
    // validating resolver, so a set AD flag means the chain validated.
    doh: (name, type) => dohQuery(name, type, timeoutMs),
  };
}

function dohQuery(name, type, timeoutMs) {
  return new Promise((resolve, reject) => {
    const url = `https://1.1.1.1/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}&do=1`;
    const req = https.get(
      url,
      {
        headers: { accept: 'application/dns-json', 'user-agent': 'vantage' },
        servername: 'cloudflare-dns.com',
        timeout: timeoutMs,
      },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (c) => {
          body += c;
          if (body.length > 65536) req.destroy(new Error('DoH response too large'));
        });
        res.on('end', () => {
          try {
            resolve(JSON.parse(body));
          } catch {
            reject(new Error('DoH returned non-JSON'));
          }
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('DoH timeout')));
    req.on('error', reject);
  });
}
