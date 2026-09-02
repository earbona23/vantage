import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseTagValue,
  parseSpfTerms,
  spfAllQualifier,
  parseHsts,
  parseSecurityTxt,
  normaliseDomain,
  recordsWithPrefix,
  joinTxtChunks,
} from '../src/parse.js';

test('parseTagValue splits semicolon key=value with lowercased keys', () => {
  const t = parseTagValue('v=DMARC1; p=reject; RUA=mailto:x@y.com', ';');
  assert.equal(t.v, 'DMARC1');
  assert.equal(t.p, 'reject');
  assert.equal(t.rua, 'mailto:x@y.com');
});

test('parseTagValue keeps the first occurrence of a duplicate key', () => {
  const t = parseTagValue('p=none; p=reject', ';');
  assert.equal(t.p, 'none');
});

test('spfAllQualifier detects every qualifier', () => {
  assert.equal(spfAllQualifier(parseSpfTerms('v=spf1 -all')), 'fail');
  assert.equal(spfAllQualifier(parseSpfTerms('v=spf1 ~all')), 'softfail');
  assert.equal(spfAllQualifier(parseSpfTerms('v=spf1 ?all')), 'neutral');
  assert.equal(spfAllQualifier(parseSpfTerms('v=spf1 +all')), 'pass');
  assert.equal(spfAllQualifier(parseSpfTerms('v=spf1 include:x.com all')), 'pass');
  assert.equal(spfAllQualifier(parseSpfTerms('v=spf1 include:x.com')), null);
});

test('parseHsts reads max-age and flags', () => {
  const h = parseHsts('max-age=31536000; includeSubDomains; preload');
  assert.equal(h.maxAge, 31536000);
  assert.equal(h.includeSubDomains, true);
  assert.equal(h.preload, true);
  assert.equal(parseHsts('max-age=0').includeSubDomains, false);
});

test('parseSecurityTxt collects fields and ignores comments', () => {
  const f = parseSecurityTxt('# a comment\nContact: mailto:s@x.com\nExpires: 2099-01-01T00:00:00Z\n');
  assert.deepEqual(f.contact, ['mailto:s@x.com']);
  assert.deepEqual(f.expires, ['2099-01-01T00:00:00Z']);
});

test('normaliseDomain strips scheme, path and trailing dot', () => {
  assert.equal(normaliseDomain('HTTPS://Example.com/foo/bar'), 'example.com');
  assert.equal(normaliseDomain('example.com.'), 'example.com');
  assert.equal(normaliseDomain(''), '');
});

test('recordsWithPrefix filters and joins chunked TXT', () => {
  const recs = recordsWithPrefix([['v=spf1 ', 'include:x -all'], ['unrelated']], 'v=spf1');
  assert.deepEqual(recs, ['v=spf1 include:x -all']);
});

test('joinTxtChunks joins arrays and passes strings through', () => {
  assert.equal(joinTxtChunks(['a', 'b']), 'ab');
  assert.equal(joinTxtChunks('c'), 'c');
});
