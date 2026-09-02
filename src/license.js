import crypto from 'node:crypto';

// Offline licence verification for the PRO tier.
//
// A licence is a compact string:  <base64url(payload)>.<base64url(signature)>
// where payload is JSON { plan, licensee, exp, features } and signature is an
// Ed25519 signature over the exact payload bytes.
//
// Verification is fully local. There is no phone-home, no licence server, no
// network of any kind. The public key below verifies signatures; the matching
// private key lives only on the maintainer's machine (in .secrets/, git-ignored)
// and is used by scripts/mint_license.js. The FREE tier never calls any of this.

// SPKI DER (base64) of the Ed25519 public key that signs valid licences.
const PUBLIC_KEY_SPKI_B64 = 'MCowBQYDK2VwAyEA6Y3eI5V3EnZNO+/F0TLY/JsTeGhnVe28atP0kaMeD04=';

function publicKey() {
  return crypto.createPublicKey({
    key: Buffer.from(PUBLIC_KEY_SPKI_B64, 'base64'),
    format: 'der',
    type: 'spki',
  });
}

function b64urlToBuf(s) {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

export function bufToB64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Verify a licence string. Returns:
//   { valid:true, plan, licensee, exp, features }
//   { valid:false, reason }
// A malformed, tampered, wrong-key or expired licence is invalid — never
// silently treated as valid.
export function verifyLicense(licenseString, { now = new Date() } = {}) {
  if (typeof licenseString !== 'string' || !licenseString.includes('.')) {
    return { valid: false, reason: 'malformed licence' };
  }
  const [payloadB64, sigB64] = licenseString.trim().split('.');
  if (!payloadB64 || !sigB64) return { valid: false, reason: 'malformed licence' };

  let payloadBuf;
  let sigBuf;
  try {
    payloadBuf = b64urlToBuf(payloadB64);
    sigBuf = b64urlToBuf(sigB64);
  } catch {
    return { valid: false, reason: 'malformed licence encoding' };
  }

  let ok;
  try {
    ok = crypto.verify(null, payloadBuf, publicKey(), sigBuf);
  } catch {
    return { valid: false, reason: 'signature verification failed' };
  }
  if (!ok) return { valid: false, reason: 'bad signature' };

  let payload;
  try {
    payload = JSON.parse(payloadBuf.toString('utf8'));
  } catch {
    return { valid: false, reason: 'unreadable payload' };
  }

  if (payload.plan !== 'pro') return { valid: false, reason: 'not a pro licence' };

  if (payload.exp) {
    const exp = typeof payload.exp === 'number' ? payload.exp : Date.parse(payload.exp);
    if (Number.isFinite(exp) && exp < now.getTime()) {
      return { valid: false, reason: `licence expired (${payload.exp})` };
    }
  }

  return {
    valid: true,
    plan: payload.plan,
    licensee: payload.licensee || null,
    exp: payload.exp || null,
    features: Array.isArray(payload.features) ? payload.features : [],
  };
}

// Resolve a licence from an explicit string or the VANTAGE_LICENSE env var.
export function resolveLicense({ license, env = process.env, now = new Date() } = {}) {
  const str = license || env.VANTAGE_LICENSE;
  if (!str) return { valid: false, reason: 'no licence provided' };
  return verifyLicense(str, { now });
}
