import https from 'node:https';

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
