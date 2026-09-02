// Hand-built evidence objects used by the pure-check tests. Building evidence by
// hand (rather than mocking the network) is exactly what makes the checks easy
// to test: each check is a pure function of this shape.

// A strong posture: reject DMARC, hard-fail SPF, DNSSEC signed, all headers.
export function strongEvidence(domain = 'strong.example') {
  return {
    domain,
    zoneResolves: true,
    spf: ['v=spf1 include:_spf.google.com -all'],
    dmarc: ['v=DMARC1; p=reject; rua=mailto:dmarc@strong.example; sp=reject'],
    dkim: { google: ['v=DKIM1; k=rsa; p=MIIBpublic'] },
    bimi: ['v=BIMI1; l=https://strong.example/logo.svg'],
    mx: { present: true, records: [{ exchange: 'aspmx.l.google.com', priority: 1 }], evaluable: true },
    tlsrpt: ['v=TLSRPTv1; rua=mailto:tlsrpt@strong.example'],
    caa: { evaluable: true, records: [{ critical: 0, issue: 'letsencrypt.org' }, { critical: 0, issuewild: ';' }] },
    ns: ['ns1.example', 'ns2.example'],
    dnssec: { evaluable: true, ad: true, ds: true, error: null },
    mtasts: {
      record: ['v=STSv1; id=20260101'],
      policy: { fetched: true, body: 'version: STSv1\nmode: enforce\nmx: aspmx.l.google.com\nmax_age: 604800', error: null },
    },
    tls: { evaluable: true, authorized: true, protocol: 'TLSv1.3', daysToExpiry: 60, subject: domain, issuer: "Let's Encrypt" },
    http: {
      root: {
        ok: true,
        status: 200,
        finalUrl: `https://${domain}/`,
        headers: {
          'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
          'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
          'x-content-type-options': 'nosniff',
          'x-frame-options': 'DENY',
          'referrer-policy': 'strict-origin-when-cross-origin',
          'permissions-policy': 'geolocation=()',
        },
      },
      securitytxt: {
        ok: true,
        status: 200,
        body: 'Contact: mailto:security@strong.example\nExpires: 2099-01-01T00:00:00Z',
      },
    },
    subdomains: { evaluable: true, probed: [`www.${domain}`], entries: {} },
  };
}

// A weak posture: no SPF, no DMARC, no DNSSEC, missing headers, dangling CNAME.
export function weakEvidence(domain = 'weak.example') {
  return {
    domain,
    zoneResolves: true,
    spf: [],
    dmarc: [],
    dkim: {},
    bimi: [],
    mx: { present: true, records: [{ exchange: 'mail.weak.example', priority: 10 }], evaluable: true },
    tlsrpt: [],
    caa: { evaluable: true, records: [] },
    ns: ['ns1.weak.example'],
    dnssec: { evaluable: true, ad: false, ds: false, error: null },
    mtasts: { record: [], policy: { fetched: false, body: null, error: null } },
    tls: { evaluable: true, authorized: true, protocol: 'TLSv1.2', daysToExpiry: 200 },
    http: {
      root: { ok: true, status: 200, finalUrl: `https://${domain}/`, headers: { server: 'nginx/1.18.0', 'x-powered-by': 'PHP/7.2' } },
      securitytxt: { ok: false, status: 404, body: null, error: null },
    },
    subdomains: {
      evaluable: true,
      probed: [`www.${domain}`, `shop.${domain}`],
      entries: {
        [`shop.${domain}`]: { cname: 'weak-shop.myshopify.com', targetResolves: true, body: 'Sorry, this shop is currently unavailable' },
      },
    },
  };
}

// An unreachable domain: DNS/HTTP/TLS all failed. Everything not evaluable.
export function unreachableEvidence(domain = 'gone.example') {
  return {
    domain,
    zoneResolves: false,
    spf: [],
    dmarc: [],
    dkim: {},
    bimi: [],
    mx: { present: false, records: [], evaluable: false },
    tlsrpt: [],
    caa: { evaluable: false, records: [] },
    ns: [],
    dnssec: { evaluable: false, ad: false, ds: false, error: 'DoH query failed' },
    mtasts: { record: [], policy: { fetched: false, body: null, error: null } },
    tls: { evaluable: false, error: 'timeout' },
    http: {
      root: { ok: false, status: 0, headers: {}, body: '', error: 'ENOTFOUND' },
      securitytxt: { ok: false, status: 0, body: null, error: 'ENOTFOUND' },
    },
    subdomains: { evaluable: false, probed: [], entries: {} },
  };
}
