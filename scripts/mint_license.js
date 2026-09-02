#!/usr/bin/env node
// Mint a PRO licence by signing a payload with the Ed25519 private key.
// The private key lives in .secrets/ (git-ignored) and never leaves this
// machine. The matching public key is embedded in src/license.js and verifies
// licences fully offline.
//
// Usage:
//   node scripts/mint_license.js --licensee "Acme Corp" --days 365
//   node scripts/mint_license.js --licensee "Acme" --exp 2027-01-01 --features batch,diff
//
// Prints the licence string to stdout. Ship that string to the customer; they
// pass it via --license or VANTAGE_LICENSE.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { bufToB64url } from '../src/license.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const KEY_PATH = path.join(__dirname, '..', '.secrets', 'vantage_license_ed25519.key');

function parse(argv) {
  const o = { features: [] };
  const a = [...argv];
  while (a.length) {
    const k = a.shift();
    if (k === '--licensee') o.licensee = a.shift();
    else if (k === '--days') o.days = parseInt(a.shift(), 10);
    else if (k === '--exp') o.exp = a.shift();
    else if (k === '--features') o.features = (a.shift() || '').split(',').map((s) => s.trim()).filter(Boolean);
  }
  return o;
}

function main() {
  const o = parse(process.argv.slice(2));
  if (!o.licensee) {
    process.stderr.write('error: --licensee is required\n');
    process.exit(2);
  }
  if (!fs.existsSync(KEY_PATH)) {
    process.stderr.write(`error: signing key not found at ${KEY_PATH}\n`);
    process.stderr.write('Generate one with:\n');
    process.stderr.write('  node -e \'const c=require("node:crypto"),f=require("node:fs");const{publicKey,privateKey}=c.generateKeyPairSync("ed25519");f.writeFileSync(".secrets/vantage_license_ed25519.key",privateKey.export({type:"pkcs8",format:"pem"}));console.log(publicKey.export({type:"spki",format:"der"}).toString("base64"))\'\n');
    process.stderr.write('...then paste the printed base64 into PUBLIC_KEY_SPKI_B64 in src/license.js\n');
    process.exit(2);
  }

  let exp = null;
  if (o.exp) exp = o.exp;
  else if (o.days) exp = new Date(Date.now() + o.days * 86400000).toISOString();

  const payload = { plan: 'pro', licensee: o.licensee, exp, features: o.features };
  const payloadBuf = Buffer.from(JSON.stringify(payload), 'utf8');

  const privateKey = crypto.createPrivateKey(fs.readFileSync(KEY_PATH, 'utf8'));
  const sig = crypto.sign(null, payloadBuf, privateKey);

  const license = `${bufToB64url(payloadBuf)}.${bufToB64url(sig)}`;
  process.stdout.write(license + '\n');
}

main();
