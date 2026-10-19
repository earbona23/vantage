import https from 'node:https';
import net from 'node:net';
import dns from 'node:dns';

// Outbound address guard. vantage is also embedded as a library behind public
// endpoints, where the domain is chosen by a visitor. A domain whose A/AAAA
// record (or a redirect target) points at loopback, a private range or a cloud
// metadata address would otherwise make the host connect inward. Every outbound
// connection resolves through guardedLookup, so the check runs on the ACTUAL
// resolved address and DNS rebinding cannot slip past a string check on the
// hostname.
//
// The deny-list is a net.BlockList rather than string matching: Node parses
// and normalises each address before comparing, so every textual form of the
// same address (compressed or expanded IPv6, IPv4-mapped in dotted or hex
// notation) lands on the same rule, and IPv4-mapped addresses are checked
// against the IPv4 rules. Transition prefixes that embed an IPv4 address
// (NAT64, 6to4) are denied as whole prefixes.
const BLOCKED = new net.BlockList();
for (const [a, p] of [
  ['0.0.0.0', 8],        // this host
  ['10.0.0.0', 8],       // private
  ['100.64.0.0', 10],    // CGNAT
  ['127.0.0.0', 8],      // loopback
  ['169.254.0.0', 16],   // link-local, cloud metadata
  ['172.16.0.0', 12],    // private
  ['192.0.0.0', 24],     // IETF protocol assignments
  ['192.0.2.0', 24],     // documentation
  ['192.168.0.0', 16],   // private
  ['198.18.0.0', 15],    // benchmarking
  ['198.51.100.0', 24],  // documentation
  ['203.0.113.0', 24],   // documentation
  ['224.0.0.0', 3],      // multicast, reserved, broadcast
]) BLOCKED.addSubnet(a, p, 'ipv4');
for (const [a, p] of [
  ['::', 96],            // unspecified, loopback, IPv4-compatible
  ['64:ff9b::', 96],     // NAT64 well-known prefix (embeds an IPv4)
  ['64:ff9b:1::', 48],   // NAT64 local-use
  ['100::', 64],         // discard-only
  ['2001:db8::', 32],    // documentation
  ['2002::', 16],        // 6to4 (embeds an IPv4)
  ['fc00::', 7],         // unique-local
  ['fe80::', 10],        // link-local
  ['fec0::', 10],        // site-local (deprecated, still routed in places)
  ['ff00::', 8],         // multicast
]) BLOCKED.addSubnet(a, p, 'ipv6');

export function isBlockedIp(ip) {
  if (net.isIPv4(ip)) return BLOCKED.check(ip, 'ipv4');
  if (net.isIPv6(ip)) return BLOCKED.check(ip, 'ipv6');
  return true; // unrecognised address shape: refuse
}

// A DNS lookup that resolves normally but refuses any private/reserved result.
// Passed as the `lookup` option to the HTTPS client (initial request and every
// redirect) and to the TLS certificate probe.
export function guardedLookup(hostname, options, callback) {
  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return callback(err);
    const list = Array.isArray(address) ? address : [{ address, family }];
    for (const a of list) {
      if (isBlockedIp(a.address)) {
        return callback(new Error('blocked: host resolves to a private or reserved address'));
      }
    }
    callback(null, address, family);
  });
}

// Real HTTPS client. GET only, with a hard cap on redirects and body size.
// Returns { ok, status, headers (lowercased), body, finalUrl, error }.
// It never throws to the caller: a network failure becomes { ok:false, error }.
// Injectable — tests pass a fake with the same get(url) contract.

export function createHttpClient({ timeoutMs = 8000, maxRedirects = 5, maxBodyBytes = 262144 } = {}) {
  return {
    // Per-call overrides let a body-heavy fetch (e.g. crt.sh JSON, which can be
    // several MB) raise its own cap without bloating every other request.
    get: (url, callOpts = {}) => getWithRedirects(url, { timeoutMs, maxRedirects, maxBodyBytes, ...callOpts }),
  };
}

function getWithRedirects(url, opts, redirectsLeft) {
  const remaining = redirectsLeft === undefined ? opts.maxRedirects : redirectsLeft;
  return getOnce(url, opts).then((res) => {
    if (res.ok && res.status >= 300 && res.status < 400 && res.headers.location && remaining > 0) {
      let next;
      try {
        next = new URL(res.headers.location, url).toString();
      } catch {
        return res;
      }
      // Only follow HTTPS redirects; a downgrade to HTTP is itself a signal we
      // do not want to chase silently.
      if (!next.startsWith('https://')) return res;
      return getWithRedirects(next, opts, remaining - 1);
    }
    return res;
  });
}

function getOnce(url, opts) {
  return new Promise((resolve) => {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      resolve({ ok: false, status: 0, headers: {}, body: '', finalUrl: url, error: 'invalid url' });
      return;
    }

    let settled = false;
    const finish = (v) => {
      if (settled) return;
      settled = true;
      resolve(v);
    };

    const req = https.get(
      url,
      {
        timeout: opts.timeoutMs,
        headers: { 'user-agent': 'vantage', accept: '*/*' },
        // We validate the chain in the dedicated TLS check; here we still want
        // headers/body even from a site with a broken chain, so do not reject.
        rejectUnauthorized: false,
        // Refuse private/reserved destinations, on this request and on every
        // redirect that reaches this function.
        lookup: guardedLookup,
      },
      (res) => {
        let body = '';
        let bytes = 0;
        const done = () =>
          finish({
            ok: true,
            status: res.statusCode,
            headers: lowerKeys(res.headers),
            body,
            finalUrl: url,
            error: null,
          });

        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          bytes += Buffer.byteLength(chunk);
          if (bytes <= opts.maxBodyBytes) {
            body += chunk;
          } else {
            // We have the headers and enough body; stop reading. destroy() fires
            // 'close' (not 'end'), so we resolve here rather than wait for 'end'.
            res.destroy();
            done();
          }
        });
        res.on('end', done);
        // 'close' is the backstop: it always fires, even on an aborted stream.
        res.on('close', done);
        res.on('error', (err) => finish({ ok: false, status: 0, headers: {}, body: '', finalUrl: url, error: err.message }));
      }
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (err) => finish({ ok: false, status: 0, headers: {}, body: '', finalUrl: url, error: err.message }));
  });
}

function lowerKeys(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    out[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
  }
  return out;
}
