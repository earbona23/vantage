// Fake DNS / HTTP / TLS clients backed by in-memory fixtures. These let the
// collector and CLI run fully offline and deterministically. They implement the
// same contracts as src/net/*.js.

class MissingRecord extends Error {
  constructor() {
    super('ENODATA');
    this.code = 'ENODATA';
  }
}

// spec.txt: { name: [ [chunk,...] | 'string' ] }  (node returns arrays of chunks)
// spec.mx / caa / ns / cname: { name: [...] }
// spec.doh: { 'name|TYPE': { Status, AD, Answer } }
// A name present with value null throws (simulates SERVFAIL / not evaluable).
export function makeDns(spec = {}) {
  const get = (bucket, name) => {
    const b = spec[bucket] || {};
    if (name in b) {
      if (b[name] === null) return Promise.reject(new Error('SERVFAIL'));
      return Promise.resolve(b[name]);
    }
    // Absence = no such record (empty), matching the real client's mapping.
    return Promise.reject(new MissingRecord());
  };
  return {
    resolveTxt: (name) => get('txt', name).then(normTxt),
    resolveMx: (name) => get('mx', name),
    resolveCaa: (name) => get('caa', name),
    resolveNs: (name) => get('ns', name),
    resolveCname: (name) => get('cname', name),
    doh: (name, type) => {
      const key = `${name}|${type}`;
      const b = spec.doh || {};
      if (key in b) {
        if (b[key] === null) return Promise.reject(new Error('DoH failed'));
        return Promise.resolve(b[key]);
      }
      return Promise.reject(new Error('DoH: no fixture'));
    },
  };
}

function normTxt(records) {
  // Accept either ['string'] or [['chunk','chunk']]; return arrays of chunks
  // like node:dns does.
  return records.map((r) => (Array.isArray(r) ? r : [r]));
}

// spec: { url: { ok, status, headers, body } }  or { url: null } for failure
export function makeHttp(spec = {}) {
  return {
    get: (url) => {
      if (url in spec) {
        const v = spec[url];
        if (v === null) return Promise.resolve({ ok: false, status: 0, headers: {}, body: '', finalUrl: url, error: 'unreachable' });
        return Promise.resolve({
          ok: v.ok !== undefined ? v.ok : true,
          status: v.status !== undefined ? v.status : 200,
          headers: lower(v.headers || {}),
          body: v.body || '',
          finalUrl: url,
          error: null,
        });
      }
      return Promise.resolve({ ok: false, status: 0, headers: {}, body: '', finalUrl: url, error: 'unreachable' });
    },
  };
}

// spec: { host: certObject }  or { host: null } for handshake failure
export function makeTls(spec = {}) {
  return {
    getCertificate: (host) => {
      if (host in spec) {
        const v = spec[host];
        if (v === null) return Promise.resolve({ evaluable: false, error: 'timeout' });
        return Promise.resolve({ evaluable: true, error: null, ...v });
      }
      return Promise.resolve({ evaluable: false, error: 'no fixture' });
    },
  };
}

function lower(h) {
  const o = {};
  for (const [k, v] of Object.entries(h)) o[k.toLowerCase()] = v;
  return o;
}
