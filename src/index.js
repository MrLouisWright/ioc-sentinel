import { readFileSync, statSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';
import { createHash } from 'node:crypto';
import { buildReport, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError, validateConfig } from './core.js';
import { RULES } from './rules.js';
import { extract, refang, defang, TYPES, TYPE_RULE, ipv4Class, ipv6Class, DEFAULT_BENIGN, btcValid } from './extract.js';

export { extract, refang, defang, TYPES, RULES, ipv4Class, ipv6Class, DEFAULT_BENIGN, btcValid, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError };
export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
export const TOOL = { name: 'ioc-sentinel', version: VERSION, rules: RULES, title: 'ioc-sentinel', emoji: '🔎', defaultFailOn: 'critical' };

const SKIP_DIRS = new Set(['.git', 'node_modules', '.hg', '.svn']);
const MAX_FILE = 50 * 1024 * 1024;

/** Recursively list files (skips .git/node_modules and files over 50 MB). */
export function listFiles(p, out = []) {
  const st = statSync(p);
  if (st.isDirectory()) { for (const e of readdirSync(p).sort()) if (!SKIP_DIRS.has(e)) listFiles(join(p, e), out); }
  else if (st.isFile() && st.size <= MAX_FILE) out.push(p);
  return out;
}
function isBinary(buf) { const n = Math.min(buf.length, 8000); let z = 0; for (let i = 0; i < n; i++) if (buf[i] === 0) z++; return z > n / 10; }
/** Printable strings (>= 6 chars) of a binary, like strings(1). Static only. */
export function strings(buf, min = 6) {
  const out = []; let cur = '';
  for (const b of buf) { if (b >= 0x20 && b < 0x7f) cur += String.fromCharCode(b); else { if (cur.length >= min) out.push(cur); cur = ''; } }
  if (cur.length >= min) out.push(cur);
  // UTF-16LE strings
  for (const start of [0, 1]) {
    let w = '';
    for (let i = start; i + 1 < buf.length; i += 2) { if (buf[i + 1] === 0 && buf[i] >= 0x20 && buf[i] < 0x7f) w += String.fromCharCode(buf[i]); else { if (w.length >= min) out.push(w); w = ''; } }
    if (w.length >= min) out.push(w);
  }
  return out.join('\n');
}

// ---------- watchlist ----------
function cidrMatch(ip, cidr) {
  const [net, bits] = cidr.split('/'); const n = Number(bits);
  const toInt = (x) => x.split('.').reduce((a, o) => (a << 8n) + BigInt(Number(o)), 0n);
  const mask = n === 0 ? 0n : ((1n << 32n) - 1n) ^ ((1n << BigInt(32 - n)) - 1n);
  return (toInt(ip) & mask) === (toInt(net) & mask);
}
/** Parse a watchlist (one IOC per line, # comments, defanged ok, CIDR and *.domain supported). */
export function parseWatchlist(text) {
  const entries = [];
  for (let line of String(text).split(/\r?\n/)) {
    line = refang(line.replace(/\s+#.*$/, '').trim());
    if (!line || line.startsWith('#')) continue;
    const [value, ...label] = line.split(/[\s,]+/);
    entries.push({ value: value.trim().toLowerCase(), label: label.join(' ').trim() || undefined });
  }
  return entries;
}
export function watchHit(ioc, watch) {
  const v = ioc.value.toLowerCase();
  const host = (ioc.host || (ioc.type === 'domain' ? v : ioc.type === 'email' ? v.split('@')[1] : '')).toLowerCase();
  for (const w of watch) {
    if (w.value === v) return w;
    if (/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(w.value) && ioc.type === 'ipv4' && cidrMatch(v, w.value)) return w;
    if (/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(w.value) && ioc.host && /^[\d.]+$/.test(ioc.host) && cidrMatch(ioc.host, w.value)) return w;
    const d = w.value.replace(/^\*\./, '');
    if (host && /[a-z]/.test(d) && !d.includes('/') && (host === d || host.endsWith('.' + d))) return w;
    if (ioc.type === 'url' && w.value.includes('/') && v.startsWith(w.value)) return w;
  }
  return null;
}

const label = { url: 'URL', domain: 'Domain', ipv4: 'IPv4', ipv6: 'IPv6', email: 'Email', md5: 'MD5', sha1: 'SHA1', sha256: 'SHA256', sha512: 'SHA512', cve: 'CVE', attack: 'ATT&CK ID', btc: 'Bitcoin address', eth: 'Ethereum address', xmr: 'Monero address', registry: 'Registry key', filename: 'File name' };

/**
 * Scan inputs for IOCs.
 * @param {(string|{name:string,text:string})[]} inputs  file/dir paths or in-memory texts
 * @param {object} opts  types, includePrivate, benignDomains, watchlist (entries or text), refang, binaryStrings, allow, severity, now
 */
export function scan(inputs, opts = {}) {
  validateConfig({ allow: opts.allow, severity: opts.severity });
  const watch = Array.isArray(opts.watchlist) ? opts.watchlist : opts.watchlist ? parseWatchlist(opts.watchlist) : [];
  const unknown = (opts.types || []).filter((t) => ![...TYPES, 'hash', 'ip', 'wallet'].includes(t));
  if (unknown.length) throw new ConfigError(`Unknown IOC type(s): ${unknown.join(', ')} (have ${TYPES.join(', ')}, hash, ip, wallet)`);
  const results = [];
  for (const inp of inputs) {
    if (typeof inp === 'object') { results.push(one(inp.name, inp.text)); continue; }
    let files;
    try { files = listFiles(inp); } catch (e) { results.push({ target: inp, fatal: true, raw: [], errors: [`Cannot read ${inp}: ${e.code || e.message}`] }); continue; }
    for (const f of files) {
      const buf = readFileSync(f);
      const bin = isBinary(buf);
      if (bin && opts.binaryStrings === false) continue;
      const r = one(relative(process.cwd(), f) || f, bin ? strings(buf) : buf.toString('utf8'), bin);
      results.push(r);
    }
  }
  function one(name, text, bin = false) {
    const iocs = extract(text, { ...opts, file: name });
    const raw = iocs.map((i) => {
      const hit = watch.length ? watchHit(i, watch) : null;
      if (hit) i.watchlist = hit.label || hit.value;
      return { rule: hit ? 'watchlist-match' : TYPE_RULE[i.type], target: name, file: name, line: bin ? undefined : i.line, location: bin ? `${name} (strings)` : `${name}:${i.line}`, message: hit ? `${label[i.type]} ${defang(i.value)} matches watchlist${hit.label ? ` (${hit.label})` : ''}` : `${label[i.type]}: ${defang(i.value)}`, value: i.value, iocType: i.type, ...(hit ? { fix: 'Treat as a confirmed indicator: block it, hunt for it across your estate and open an incident.' } : {}) };
    });
    const byType = {}; for (const i of iocs) byType[i.type] = (byType[i.type] || 0) + 1;
    return { target: name, summary: { iocs: iocs.length, ...byType, ...(bin ? { mode: 'binary strings' } : {}) }, data: iocs, raw, errors: [] };
  }
  const report = buildReport(TOOL, results, { ...opts, meta: { watchlistEntries: watch.length } });
  report.iocs = dedupe(report.targets.flatMap((t) => t.data || []));
  // drop iocs whose findings were allow-listed
  const sup = new Set(report.suppressed.map((f) => `${f.iocType}\0${f.value}`));
  report.iocs = report.iocs.filter((i) => !sup.has(`${i.type}\0${i.value}`));
  return report;
}
function dedupe(list) {
  const m = new Map();
  for (const i of list) {
    const k = `${i.type}\0${i.value}`;
    if (!m.has(k)) m.set(k, { type: i.type, value: i.value, defanged: defang(i.value), count: 0, sources: [], ...(i.class ? { class: i.class } : {}), ...(i.watchlist ? { watchlist: i.watchlist } : {}) });
    const e = m.get(k); e.count++; if (i.file && !e.sources.includes(`${i.file}:${i.line}`)) e.sources.push(`${i.file}:${i.line}`);
  }
  return [...m.values()].sort((a, b) => TYPES.indexOf(a.type) - TYPES.indexOf(b.type) || a.value.localeCompare(b.value));
}

// ---------- exports ----------
const csvq = (s) => (/[",\n]/.test(String(s)) ? `"${String(s).replace(/"/g, '""')}"` : String(s));
export function formatCsv(report, { defanged = false } = {}) {
  return ['type,value,count,sources,watchlist', ...report.iocs.map((i) => [i.type, defanged ? i.defanged : i.value, i.count, i.sources.join(' '), i.watchlist || ''].map(csvq).join(','))].join('\n') + '\n';
}
export function formatList(report, { defanged = false } = {}) { return report.iocs.map((i) => (defanged ? i.defanged : i.value)).join('\n') + (report.iocs.length ? '\n' : ''); }
function uuid5ish(s) { const h = createHash('sha1').update(s).digest('hex'); return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${((parseInt(h[16], 16) & 3) | 8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`; }
const sq = (s) => String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
export function stixPattern(i) {
  switch (i.type) {
    case 'url': return `[url:value = '${sq(i.value)}']`;
    case 'domain': return `[domain-name:value = '${sq(i.value)}']`;
    case 'ipv4': return `[ipv4-addr:value = '${i.value}']`;
    case 'ipv6': return `[ipv6-addr:value = '${i.value}']`;
    case 'email': return `[email-addr:value = '${sq(i.value)}']`;
    case 'md5': return `[file:hashes.MD5 = '${i.value}']`;
    case 'sha1': return `[file:hashes.'SHA-1' = '${i.value}']`;
    case 'sha256': return `[file:hashes.'SHA-256' = '${i.value}']`;
    case 'sha512': return `[file:hashes.'SHA-512' = '${i.value}']`;
    case 'registry': return `[windows-registry-key:key = '${sq(i.value)}']`;
    case 'filename': return `[file:name = '${sq(i.value)}']`;
    case 'btc': case 'eth': case 'xmr': return `[x-crypto-wallet:value = '${sq(i.value)}']`;
    default: return null;
  }
}
/** STIX 2.1 bundle of indicators (CVE/ATT&CK IDs become vulnerability / external references). */
export function formatStix(report, { name = 'ioc-sentinel extraction', now } = {}) {
  const ts = (now ? new Date(now) : new Date(report.generatedAt)).toISOString();
  const identity = { type: 'identity', spec_version: '2.1', id: `identity--${uuid5ish('ioc-sentinel')}`, created: ts, modified: ts, name: 'ioc-sentinel', identity_class: 'system' };
  const objs = [identity];
  for (const i of report.iocs) {
    if (i.type === 'cve') { objs.push({ type: 'vulnerability', spec_version: '2.1', id: `vulnerability--${uuid5ish(i.value)}`, created: ts, modified: ts, created_by_ref: identity.id, name: i.value, external_references: [{ source_name: 'cve', external_id: i.value }] }); continue; }
    if (i.type === 'attack') { objs.push({ type: 'attack-pattern', spec_version: '2.1', id: `attack-pattern--${uuid5ish(i.value)}`, created: ts, modified: ts, created_by_ref: identity.id, name: i.value, external_references: [{ source_name: 'mitre-attack', external_id: i.value }] }); continue; }
    const pattern = stixPattern(i); if (!pattern) continue;
    objs.push({ type: 'indicator', spec_version: '2.1', id: `indicator--${uuid5ish(i.type + i.value)}`, created: ts, modified: ts, created_by_ref: identity.id, name: `${i.type}: ${i.defanged}`, indicator_types: [i.watchlist ? 'malicious-activity' : 'unknown'], pattern, pattern_type: 'stix', valid_from: ts, labels: [i.type, ...(i.watchlist ? ['watchlist'] : [])], description: `Seen ${i.count}x in ${i.sources.slice(0, 5).join(', ')}` });
  }
  return JSON.stringify({ type: 'bundle', id: `bundle--${uuid5ish(name + ts)}`, objects: objs }, null, 2) + '\n';
}
