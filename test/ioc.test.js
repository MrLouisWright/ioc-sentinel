import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { extract, refang, defang, scan, parseWatchlist, formatCsv, formatStix, formatList, ipv4Class, ipv6Class, btcValid, strings, exitCode } from '../src/index.js';

const vals = (arr, t) => arr.filter((i) => i.type === t).map((i) => i.value);
const BIN = new URL('../bin/ioc-sentinel.js', import.meta.url).pathname;
const run = (args, input) => spawnSync(process.execPath, [BIN, ...args], { input, encoding: 'utf8' });

test('refang handles common styles', () => {
  assert.equal(refang('hxxps://evil[.]com/a'), 'https://evil.com/a');
  assert.equal(refang('hXXp[:]//a(.)b{.}c[dot]d'), 'http://a.b.c.d');
  assert.equal(refang('user[@]x[.]org and user(at)y(dot)org'), 'user@x.org and user@y.org');
  assert.equal(refang('fxp://files[.]bad[.]ru'), 'ftp://files.bad.ru');
  assert.equal(refang('1.2.3\\.4'), '1.2.3.4');
  assert.equal(defang('https://evil.com/x'), 'hxxps[://]evil[.]com/x');
});

test('extracts URLs, domains, emails with defang detection', () => {
  const r = extract('see hxxps://evil[.]co[.]uk/path?q=1). and mail admin@corp-mail.net, visit www.bad-site.xyz.');
  assert.deepEqual(vals(r, 'url'), ['https://evil.co.uk/path?q=1']);
  assert.ok(r.find((i) => i.type === 'url').defanged);
  assert.deepEqual(vals(r, 'domain').sort(), ['corp-mail.net', 'evil.co.uk', 'www.bad-site.xyz']);
  assert.deepEqual(vals(r, 'email'), ['admin@corp-mail.net']);
});

test('drops file names, invalid TLDs and benign domains', () => {
  const r = extract('ran setup.py and readme.md; foo.notatld is not a domain; xmlns http://www.w3.org/2000/svg example.com sub.example.org');
  assert.deepEqual(vals(r, 'domain'), []);
  assert.deepEqual(vals(r, 'url'), []);
  assert.deepEqual(vals(extract('setup.py', { fileNameDomains: true }), 'domain'), ['setup.py']);
  assert.deepEqual(vals(extract('payload at evil[.]zip'), 'domain'), ['evil.zip']);
  assert.deepEqual(vals(extract('example.com', { benignDomains: [] }), 'domain'), ['example.com']);
});

test('IPv4/IPv6 with private filtering and no version-number false positives', () => {
  const r = extract('8.8.8.8 10.1.2.3 192.168.0.1 203.0.113.5 version 1.2.3.4.5 at 12:30:45 mac 00:1a:2b:3c:4d:5e 2606:4700:4700::1111 fe80::1 ::1');
  assert.deepEqual(vals(r, 'ipv4'), ['8.8.8.8']);
  assert.deepEqual(vals(r, 'ipv6'), ['2606:4700:4700::1111']);
  const p = extract('10.1.2.3 fe80::1', { includePrivate: true });
  assert.deepEqual(vals(p, 'ipv4'), ['10.1.2.3']);
  assert.equal(p.find((i) => i.type === 'ipv4').class, 'private');
  assert.equal(ipv4Class('100.64.0.1'), 'cgnat'); assert.equal(ipv4Class('224.0.0.1'), 'multicast'); assert.equal(ipv4Class('1.1.1.1'), 'public');
  assert.equal(ipv6Class('2001:db8::1'), 'documentation'); assert.equal(ipv6Class('fd00::1'), 'private');
  assert.deepEqual(vals(extract('256.1.1.1 1.2.3'), 'ipv4'), []);
});

test('hashes by length, ignoring repetitive and ETH addresses', () => {
  const md5 = '44d88612fea8a8f36de82e1278abb02f'; const sha1 = '3395856ce81f2b7382dee72602f798b642f14140';
  const sha256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
  const r = extract(`${md5} ${sha1.toUpperCase()} ${sha256} ${'a'.repeat(128).replace(/^a/, 'b')} ${'0'.repeat(64)}`);
  assert.deepEqual(vals(r, 'md5'), [md5]); assert.deepEqual(vals(r, 'sha1'), [sha1]); assert.deepEqual(vals(r, 'sha256'), [sha256]);
  assert.equal(vals(r, 'sha512').length, 1);
  assert.deepEqual(vals(extract('0x52908400098527886E0F7030069857D2E4169EE7'), 'sha1'), []);
});

test('CVE, ATT&CK, wallets, registry and file names', () => {
  const r = extract('cve-2021-44228 used T1190 and TA0001 by G0016\nBTC 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq bogus 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb\nHKCU\\Software\\Run\\x C:\\Users\\a\\AppData\\stage2.dll');
  assert.deepEqual(vals(r, 'cve'), ['CVE-2021-44228']);
  assert.deepEqual(vals(r, 'attack').sort(), ['G0016', 'T1190', 'TA0001']);
  assert.deepEqual(vals(r, 'btc'), ['1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq']);
  assert.equal(btcValid('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb'), false);
  assert.deepEqual(vals(r, 'registry'), ['HKCU\\Software\\Run\\x']);
  assert.deepEqual(vals(r, 'filename'), ['stage2.dll']);
});

test('type filter and dedupe', () => {
  const r = extract('8.8.8.8 8.8.8.8 hxxp://a.evil.com', { types: ['ip'] });
  assert.deepEqual(r.map((i) => i.type), ['ipv4']);
  assert.throws(() => scan([{ name: 'x', text: '' }], { types: ['nope'] }), /Unknown IOC type/);
});

test('watchlist: exact, CIDR, parent domain and URL prefix', () => {
  const wl = parseWatchlist('# bad stuff\n185.220.101.0/24 tor-exit\nevil[.]com\nhttps://cdn.x.org/payload,stage\n44D88612FEA8A8F36DE82E1278ABB02F eicar\n');
  assert.equal(wl.length, 4);
  const rep = scan([{ name: 'log', text: 'conn 185.220.101.77\nget https://dl.evil.com/a\nhttps://cdn.x.org/payload/1.bin\n44d88612fea8a8f36de82e1278abb02f\n9.9.9.9' }], { watchlist: wl, now: '2026-10-14' });
  const hits = rep.findings.filter((f) => f.rule === 'watchlist-match');
  assert.ok(hits.length >= 4, JSON.stringify(hits.map((h) => h.message)));
  assert.ok(hits.some((h) => /tor-exit/.test(h.message)));
  assert.equal(exitCode(rep, 'critical'), 1);
  assert.ok(rep.iocs.find((i) => i.value === '185.220.101.77').watchlist);
  assert.ok(!rep.iocs.find((i) => i.value === '9.9.9.9').watchlist);
});

test('allowlist suppresses an IOC value; expired entry reports', () => {
  const rep = scan([{ name: 'n', text: '8.8.8.8 1.1.1.1' }], { allow: [{ rule: 'ioc-ipv4', match: '8.8.8.8', reason: 'Google DNS' }], now: '2026-10-14' });
  assert.deepEqual(rep.iocs.map((i) => i.value), ['1.1.1.1']);
  const exp = scan([{ name: 'n', text: '8.8.8.8' }], { allow: [{ rule: 'ioc-*', reason: 'old', expires: '2025-01-01' }], now: '2026-10-14' });
  assert.ok(exp.findings.some((f) => f.rule === 'allow-expired'));
});

test('exports: CSV, list, STIX 2.1', () => {
  const rep = scan([{ name: 'n', text: 'hxxp://evil[.]com/x 44d88612fea8a8f36de82e1278abb02f CVE-2024-3400 T1059' }], { now: '2026-10-14' });
  const csv = formatCsv(rep, { defanged: true });
  assert.match(csv, /^type,value,count,sources,watchlist\n/); assert.match(csv, /hxxp\[:\/\/\]evil\[\.\]com\/x/);
  assert.match(formatList(rep), /^http:\/\/evil\.com\/x$/m);
  const b = JSON.parse(formatStix(rep));
  assert.equal(b.type, 'bundle');
  const pats = b.objects.filter((o) => o.type === 'indicator').map((o) => o.pattern);
  assert.ok(pats.includes("[url:value = 'http://evil.com/x']"));
  assert.ok(pats.includes("[file:hashes.MD5 = '44d88612fea8a8f36de82e1278abb02f']"));
  assert.ok(b.objects.some((o) => o.type === 'vulnerability' && o.name === 'CVE-2024-3400'));
  assert.ok(b.objects.some((o) => o.type === 'attack-pattern'));
  for (const o of b.objects) assert.match(o.id, /^[a-z-]+--[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test('directories, binary strings (static), missing paths', () => {
  const d = mkdtempSync(join(tmpdir(), 'ioc-')); mkdirSync(join(d, 'node_modules'));
  writeFileSync(join(d, 'a.log'), 'beacon to 45.9.148.3');
  writeFileSync(join(d, 'node_modules', 'x.txt'), '9.9.9.9');
  writeFileSync(join(d, 'sample.bin'), Buffer.concat([Buffer.alloc(200), Buffer.from('http://c2.badhost.ru/gate\0'), Buffer.from('h\0t\0t\0p\0:\0/\0/\0w\0i\0d\0e\0.\0r\0u\0/\0', 'latin1'), Buffer.alloc(200)]));
  const rep = scan([d]);
  const v = rep.iocs.map((i) => i.value);
  assert.ok(v.includes('45.9.148.3')); assert.ok(!v.includes('9.9.9.9'));
  assert.ok(v.includes('http://c2.badhost.ru/gate')); assert.ok(v.includes('http://wide.ru/'));
  assert.match(strings(Buffer.from('\0\0abcdefg\0hi\0')), /^abcdefg$/);
  assert.ok(!scan([d], { binaryStrings: false }).iocs.some((i) => i.value.includes('badhost')));
  const bad = scan([join(d, 'missing')]);
  assert.equal(exitCode(bad, 'none'), 2);
});

test('CLI: stdin, formats and exit codes', () => {
  let r = run(['-', '-f', 'csv', '--defang'], 'go to hxxp://evil[.]com now\n');
  assert.equal(r.status, 0); assert.match(r.stdout, /url,hxxp\[:\/\/\]evil\[\.\]com/);
  const d = mkdtempSync(join(tmpdir(), 'iocw-')); writeFileSync(join(d, 'w.txt'), 'evil.com\n');
  r = run(['-', '-w', join(d, 'w.txt')], 'hxxp://evil[.]com\n');
  assert.equal(r.status, 1); assert.match(r.stdout, /matches watchlist/);
  r = run(['-', '-f', 'sarif', '--fail-on', 'medium'], 'http://a.evil.com/x\n');
  assert.equal(r.status, 1); assert.equal(JSON.parse(r.stdout).runs[0].results[0].ruleId, 'ioc-url');
  r = run(['-', '-f', 'markdown'], '1.1.1.1\n'); assert.match(r.stdout, /## 🔎 ioc-sentinel/);
  assert.equal(run(['-f', 'nope', '-'], '').status, 2);
  assert.equal(run([]).status, 2);
  assert.equal(run(['--types', 'bogus', '-'], 'x').status, 2);
  assert.match(run(['--help']).stdout, /Usage: ioc-sentinel/);
  assert.match(run(['--list-rules']).stdout, /watchlist-match/);
  writeFileSync(join(d, 'c.json'), JSON.stringify({ severity: { 'ioc-url': 'critical' } }));
  assert.equal(run(['-', '-c', join(d, 'c.json')], 'http://a.evil.com/x\n').status, 1);
  writeFileSync(join(d, 'bad.json'), JSON.stringify({ allow: [{ rule: 'x' }] }));
  assert.equal(run(['-', '-c', join(d, 'bad.json')], 'x').status, 2);
});
