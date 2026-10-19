import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isBlockedIp, guardedLookup } from '../src/net/http.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const read = (rel) => fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');

// Every IPv6 spelling of one IPv4 address that a resolver could hand back.
// The guard must give the same answer for all of them as for the IPv4 itself.
function ipv6Forms(v4) {
  const [a, b, c, d] = v4.split('.').map(Number);
  const hi = ((a << 8) | b).toString(16);
  const lo = ((c << 8) | d).toString(16);
  return [
    `::ffff:${v4}`,              // IPv4-mapped, dotted
    `::ffff:${hi}:${lo}`,        // IPv4-mapped, hex
    `0:0:0:0:0:ffff:${hi}:${lo}`, // IPv4-mapped, expanded
  ];
}

// Representative address inside each IPv4 range the guard must refuse.
const INTERNAL_V4 = ['0.0.0.1', '10.1.2.3', '100.64.0.1', '127.0.0.1', '169.254.1.1',
  '172.16.0.1', '192.0.0.1', '192.168.1.1', '198.18.0.1', '224.0.0.1', '255.255.255.255'];
const PUBLIC_V4 = ['8.8.8.8', '1.1.1.1', '9.9.9.9'];

test('isBlockedIp refuses internal IPv4 and every IPv4-mapped spelling of it', () => {
  for (const v4 of INTERNAL_V4) {
    assert.equal(isBlockedIp(v4), true, `${v4} must be blocked`);
    for (const f of ipv6Forms(v4)) assert.equal(isBlockedIp(f), true, `${f} (${v4}) must be blocked`);
  }
});

test('isBlockedIp allows public IPv4 in every spelling (no over-blocking)', () => {
  for (const v4 of PUBLIC_V4) {
    assert.equal(isBlockedIp(v4), false, `${v4} must be allowed`);
    for (const f of ipv6Forms(v4)) assert.equal(isBlockedIp(f), false, `${f} (${v4}) must be allowed`);
  }
  assert.equal(isBlockedIp('2606:4700:4700::1111'), false);
  assert.equal(isBlockedIp('2001:4860:4860::8888'), false);
});

test('isBlockedIp refuses IPv6 prefixes that embed an IPv4 or are not globally routable', () => {
  // One sample per denied prefix: unspecified, loopback, IPv4-compatible,
  // NAT64 (well-known + local-use), discard, documentation, 6to4, ULA,
  // link-local, site-local, multicast.
  for (const ip of ['::', '::1', '::a00:1', '64:ff9b::a00:1', '64:ff9b:1::1', '100::1',
    '2001:db8::1', '2002:a00:1::1', 'fd12:3456::1', 'fe80::1', 'fec0::1', 'ff02::1']) {
    assert.equal(isBlockedIp(ip), true, `${ip} must be blocked`);
  }
  // Case and zero-padding do not change the verdict.
  assert.equal(isBlockedIp('FE80:0000:0000:0000:0000:0000:0000:0001'), true);
});

test('isBlockedIp refuses anything that is not a parseable address', () => {
  for (const s of ['', 'localhost', '127.1', 'not-an-ip', '1.2.3.4.5']) {
    assert.equal(isBlockedIp(s), true, `${JSON.stringify(s)} must be refused`);
  }
});

test('guardedLookup fails closed when a name resolves to loopback', async () => {
  const err = await new Promise((resolve) => {
    guardedLookup('localhost', { all: true }, (e) => resolve(e));
  });
  assert.ok(err instanceof Error, 'localhost must not resolve through the guard');
  assert.match(err.message, /blocked/);
});

test('the HTTPS client and the TLS probe both connect through guardedLookup', () => {
  const httpSrc = read('src/net/http.js');
  const tlsSrc = read('src/net/tls.js');
  assert.match(httpSrc, /https\.get\([\s\S]*lookup:\s*guardedLookup/, 'https.get must be given lookup: guardedLookup');
  assert.match(tlsSrc, /import\s*\{\s*guardedLookup\s*\}\s*from\s*'\.\/http\.js'/, 'tls.js must import guardedLookup');
  assert.match(tlsSrc, /tls\.connect\([\s\S]*lookup:\s*guardedLookup/, 'tls.connect must be given lookup: guardedLookup');
});
