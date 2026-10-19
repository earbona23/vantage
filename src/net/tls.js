import tls from 'node:tls';
import { guardedLookup } from './http.js';

// Real TLS client. Opens a handshake to :443, reads the leaf certificate and
// negotiated protocol, and reports whether the chain validated against the
// public trust store. Returns a plain evidence object; never throws.
// Injectable — tests pass a fake with the same getCertificate(host) contract.

export function createTlsClient({ timeoutMs = 8000, port = 443 } = {}) {
  return {
    getCertificate: (host) => handshake(host, port, timeoutMs),
  };
}

function handshake(host, port, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => {
      if (settled) return;
      settled = true;
      resolve(v);
    };

    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        // We WANT to know when the chain is invalid rather than aborting, so we
        // do not reject; socket.authorized carries the verdict.
        rejectUnauthorized: false,
        timeout: timeoutMs,
        // Same outbound address guard as the HTTPS client.
        lookup: guardedLookup,
      },
      () => {
        const cert = socket.getPeerCertificate(false);
        const protocol = socket.getProtocol();
        const authorized = socket.authorized;
        const authorizationError = socket.authorizationError
          ? String(socket.authorizationError)
          : null;

        let daysToExpiry = null;
        if (cert && cert.valid_to) {
          const exp = Date.parse(cert.valid_to);
          if (Number.isFinite(exp)) {
            daysToExpiry = Math.floor((exp - Date.now()) / 86400000);
          }
        }

        socket.end();
        done({
          evaluable: true,
          authorized,
          authorizationError,
          protocol,
          daysToExpiry,
          subject: cert && cert.subject ? cert.subject.CN : null,
          issuer: cert && cert.issuer ? cert.issuer.O : null,
          error: null,
        });
      }
    );

    socket.on('timeout', () => {
      socket.destroy();
      done({ evaluable: false, error: 'timeout' });
    });
    socket.on('error', (err) => {
      done({ evaluable: false, error: err.message });
    });
  });
}
