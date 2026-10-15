import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { extract, scan, normalize, refang, formatMisp, formatOpenIoc, DEFAULT_BENIGN_IPS } from '../src/index.js';
import * as ds from 'defang-sentinel';

const BIN = new URL('../bin/ioc-sentinel.js', import.meta.url).pathname;

test('refanging is delegated to defang-sentinel (no second implementation)', () => {
  const src = readFileSync(new URL('../src/extract.js', import.meta.url), 'utf8');
  assert.match(src, /from 'defang-sentinel'/);
  for (const s of ['hxxps://evil[.]com/a', 'HXXP(:)//a(.)b', 'u[@]x[dot]org']) assert.equal(refang(s), ds.refang(s));
  const pj = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.match(pj.dependencies['defang-sentinel'], /^\^1\./);
});

test('normalize: case, trailing dot, ipv6 compression, default ports, leading-zero octets', () => {
  assert.equal(normalize('domain', 'EVIL.Com.'), 'evil.com');
  assert.equal(normalize('ipv6', '2001:0db8:0000:0000:0000:0000:0000:0001'), '2001:db8::1');
  assert.equal(normalize('url', 'HTTPS://Evil.COM:443/Path'), 'https://evil.com/Path');
  assert.equal(normalize('ipv4', '010.1.1.1'), '10.1.1.1');
  assert.equal(normalize('sha256', 'AB'.repeat(32)), 'ab'.repeat(32));
});

test('dedupe across case/defang variants and benign IP + extended noise filtering', () => {
  const r = extract('evil.com EVIL.COM evil[.]com\n8.8.8.8 1.1.1.1 45.9.148.3\nsee microsoft.com');
  assert.deepEqual(r.filter((i) => i.type === 'domain').map((i) => i.value), ['evil.com', 'microsoft.com']);
  assert.deepEqual(r.filter((i) => i.type === 'ipv4').map((i) => i.value), ['45.9.148.3']);
  assert.ok(DEFAULT_BENIGN_IPS.includes('1.1.1.1'));
  assert.equal(extract('8.8.8.8', { benignIps: [] }).length, 1);
  assert.ok(!extract('see microsoft.com', { noise: 'extended' }).some((i) => i.value === 'microsoft.com'));
  // a watchlisted resolver IP is never dropped as noise
  const w = scan([{ name: 'x', text: 'dns 8.8.8.8' }], { watchlist: '8.8.8.8 suspicious-dns' });
  assert.equal(w.findings[0].rule, 'watchlist-match');
});

test('source tracking: line, column and offset (mapped back through defanging)', () => {
  const text = 'first line\n  C2 hxxp://bad[.]ru/x and 45.9.148.3';
  const r = extract(text);
  const url = r.find((i) => i.type === 'url'); const ip = r.find((i) => i.type === 'ipv4');
  assert.equal(url.line, 2); assert.equal(url.column, 6); assert.equal(text.slice(url.offset, url.offset + 4), 'hxxp');
  assert.equal(text.slice(ip.offset, ip.offset + ip.value.length), '45.9.148.3');
  const rep = scan([{ name: 'a.txt', text }]);
  const agg = rep.iocs.find((i) => i.type === 'ipv4');
  assert.deepEqual(agg.occurrences[0], { file: 'a.txt', line: 2, column: ip.column, offset: ip.offset });
  assert.match(rep.findings.find((f) => f.iocType === 'ipv4').location, /^a\.txt:2:\d+$/);
});

test('MISP event JSON export', () => {
  const rep = scan([{ name: 'r', text: 'hxxp://bad[.]ru/x 45.9.148.3 CVE-2024-3400 T1059 ' + 'a'.repeat(31) + 'b' }]);
  const ev = JSON.parse(formatMisp(rep, { now: '2026-10-15T00:00:00Z', info: 'case 1' })).Event;
  assert.equal(ev.info, 'case 1'); assert.equal(ev.date, '2026-10-15');
  const by = Object.fromEntries(ev.Attribute.map((a) => [a.type + ':' + a.value, a]));
  assert.equal(by['url:http://bad.ru/x'].to_ids, true);
  assert.equal(by['ip-dst:45.9.148.3'].category, 'Network activity');
  assert.equal(by['vulnerability:CVE-2024-3400'].to_ids, false);
  assert.ok(by['md5:' + 'a'.repeat(31) + 'b']);
  assert.ok(ev.Attribute.every((a) => /^[0-9a-f-]{36}$/.test(a.uuid)));
});

test('OpenIOC 1.1 XML export with escaping', () => {
  const rep = scan([{ name: 'r', text: 'http://bad.ru/a?x=1&y=<2> 45.9.148.3' }]);
  const x = formatOpenIoc(rep, { now: '2026-10-15T00:00:00Z' });
  assert.match(x, /^<\?xml/); assert.match(x, /xmlns="http:\/\/schemas\.mandiant\.com\/2010\/ioc"/);
  assert.match(x, /search="PortItem\/remoteIP" type="mir"\/>\s*<Content type="IP">45\.9\.148\.3</);
  assert.match(x, /x=1&amp;y=/);
});

test('CLI: --format misp / openioc and --noise', () => {
  const run = (args, input) => spawnSync(process.execPath, [BIN, ...args], { input, encoding: 'utf8' });
  assert.ok(JSON.parse(run(['-', '-f', 'misp'], 'bad[.]ru').stdout).Event.Attribute.length >= 1);
  assert.match(run(['-', '-f', 'openioc'], 'bad[.]ru').stdout, /DnsEntryItem\/Host/);
  assert.doesNotMatch(run(['-', '-f', 'list', '--noise', 'extended'], 'microsoft.com bad.ru').stdout, /microsoft/);
});
