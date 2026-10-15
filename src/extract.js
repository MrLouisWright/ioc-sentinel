import { TLDS, FILE_EXT } from './tlds.js';

import { refang as dsRefang, defangValue } from 'defang-sentinel';

// Refanging/defanging lives in defang-sentinel; these wrappers keep the 1.0 API working.
/** Undo defanging (delegates to defang-sentinel, plus legacy "punto"/"sftx" spellings). */
export function refang(s) {
  return dsRefang(String(s).replace(/\s?[[({<]\s?punto\s?[\])}>]\s?/g, '.').replace(/\bsftx\b/gi, 'sftp'));
}

const OCT = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const IPV4 = new RegExp(`(?<![\\w.])${OCT}(?:\\.${OCT}){3}(?![\\w]|\\.\\d)`, 'g');
const IPV6 = /(?<![\w:.])(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}|:(?::[0-9a-f]{1,4}){1,7})(?![\w:])/gi;
const URL_RE = /(?:https?|ftp|sftp|ftps|wss?|tcp|udp|smb|rdp|ldap|file):\/\/[^\s"'<>`)\]}|\\^]+/gi;
const DOMAIN = /(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,24})(?![\w-]|\.[a-z0-9])/gi;
const EMAIL = /(?<![\w.+-])[a-z0-9._%+-]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
const HASH = /(?<![0-9a-f])(?:[0-9a-f]{128}|[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])/gi;
const CVE = /\bCVE-(?:19|20)\d{2}-\d{4,7}\b/gi;
const ATTACK = /\b(?:T[0-9]{4}(?:\.[0-9]{3})?|TA[0-9]{4}|G[0-9]{4}|S[0-9]{4})\b/g;
const BTC = /\b(?:bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g;
const ETH = /\b0x[a-fA-F0-9]{40}\b/g;
const XMR = /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g;
const REG = /\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU)\\[^\s"'<>|]+(?:\\[^\s"'<>|]+)*/g;
const FILENAME = /(?<![\w.-])[\w-][\w.-]{0,80}?\.(?:exe|dll|scr|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|msi|jar|iso|img|one|docm|xlsm|sys|elf|so)(?![\w])/gi;

export const TYPES = ['url', 'domain', 'ipv4', 'ipv6', 'email', 'md5', 'sha1', 'sha256', 'sha512', 'cve', 'attack', 'btc', 'eth', 'xmr', 'registry', 'filename'];
export const TYPE_RULE = { url: 'ioc-url', domain: 'ioc-domain', ipv4: 'ioc-ipv4', ipv6: 'ioc-ipv6', email: 'ioc-email', md5: 'ioc-hash', sha1: 'ioc-hash', sha256: 'ioc-hash', sha512: 'ioc-hash', cve: 'ioc-cve', attack: 'ioc-attack-technique', btc: 'ioc-crypto-wallet', eth: 'ioc-crypto-wallet', xmr: 'ioc-crypto-wallet', registry: 'ioc-registry-key', filename: 'ioc-file-name' };

/** Reserved / non-routable IPv4 ranges (RFC 1918, 6598, 5737, loopback, link-local, multicast...). */
export function ipv4Class(ip) {
  const [a, b, c] = ip.split('.').map(Number);
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private';
  if (a === 127) return 'loopback';
  if (a === 0) return 'unspecified';
  if (a === 169 && b === 254) return 'link-local';
  if (a === 100 && b >= 64 && b <= 127) return 'cgnat';
  if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) return 'documentation';
  if (a === 198 && (b === 18 || b === 19)) return 'benchmark';
  if (a >= 224 && a <= 239) return 'multicast';
  if (a >= 240) return 'reserved';
  return 'public';
}
export function ipv6Class(ip) {
  const s = ip.toLowerCase();
  if (s === '::' ) return 'unspecified';
  if (s === '::1') return 'loopback';
  if (/^fe[89ab]/.test(s)) return 'link-local';
  if (/^f[cd]/.test(s)) return 'private';
  if (/^ff/.test(s)) return 'multicast';
  if (/^2001:0?db8:/.test(s)) return 'documentation';
  return 'public';
}

// Domains that are noise in nearly every report. Overridable with { benignDomains: [] }.
export const DEFAULT_BENIGN = ['example.com', 'example.org', 'example.net', '*.example.com', '*.example.org', '*.example.net', 'localhost', 'schemas.microsoft.com', 'schemas.openxmlformats.org', 'www.w3.org', 'w3.org', 'purl.org', 'ns.adobe.com', 'schema.org', 'json-schema.org', 'xmlns.com'];

// Infrastructure IPs that are almost always noise (public resolvers etc.). Overridable with { benignIps: [] }.
export const DEFAULT_BENIGN_IPS = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220', '2001:4860:4860::8888', '2001:4860:4860::8844', '2606:4700:4700::1111', '2606:4700:4700::1001'];
/** Extended noise list (opt-in via { noise: 'extended' }): big-vendor domains common in sandbox and report text. */
export const EXTENDED_BENIGN = ['microsoft.com', '*.microsoft.com', 'windowsupdate.com', '*.windowsupdate.com', 'google.com', 'www.google.com', 'gstatic.com', '*.gstatic.com', 'apple.com', '*.apple.com', 'mozilla.org', '*.mozilla.org', 'digicert.com', '*.digicert.com', 'verisign.com', 'letsencrypt.org', '*.letsencrypt.org', 'adobe.com', 'cloudflare.com', 'akamai.net', '*.akamaiedge.net'];

/**
 * Normalise an IOC value for dedupe: lowercase hosts/domains/emails/hashes, strip trailing dots,
 * compress IPv6, drop default ports and lowercase URL scheme+host (path case is kept).
 */
export function normalize(type, value) {
  const v = String(value).trim();
  switch (type) {
    case 'domain': return v.toLowerCase().replace(/\.+$/, '');
    case 'email': return v.toLowerCase();
    case 'md5': case 'sha1': case 'sha256': case 'sha512': case 'eth': return v.toLowerCase();
    case 'ipv4': return v.split('.').map((o) => String(Number(o))).join('.');
    case 'ipv6': try { return new URL(`http://[${v}]/`).hostname.slice(1, -1); } catch { return v.toLowerCase(); }
    case 'url': {
      const m = v.match(/^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(.*)$/is); if (!m) return v;
      let [, sch, auth, rest] = m; sch = sch.toLowerCase(); auth = auth.toLowerCase().replace(/\.(?=$|:)/, '');
      if ((sch === 'http' && auth.endsWith(':80')) || (sch === 'https' && auth.endsWith(':443'))) auth = auth.replace(/:\d+$/, '');
      return `${sch}://${auth}${rest}`;
    }
    default: return v;
  }
}

const dglob = (g) => new RegExp('^' + g.toLowerCase().replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');

function hashType(h) { return { 32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512' }[h.length]; }
function isRepetitive(h) { return /^(.)\1+$/.test(h) || /^(?:0123456789abcdef)+/i.test(h); }
function trimUrl(u) {
  let s = u.replace(/[.,;:!?]+$/, '');
  // balance a trailing ) that was not opened in the URL
  while (s.endsWith(')') && (s.match(/\(/g) || []).length < (s.match(/\)/g) || []).length) s = s.slice(0, -1);
  return s.replace(/[.,;:!?]+$/, '');
}
function validDomain(d) {
  const labels = d.split('.');
  const tld = labels[labels.length - 1].toLowerCase();
  if (labels.length < 2 || labels.some((l) => !l.length || l.length > 63)) return false;
  if (tld.startsWith('xn--')) return true;
  return TLDS.has(tld);
}

/**
 * Extract IOCs from text.
 * @param {string} text
 * @param {{ types?: string[], refang?: boolean, includePrivate?: boolean, benignDomains?: string[], file?: string, fileNameDomains?: boolean }} opts
 * @returns {{type:string,value:string,line:number,defanged:boolean,context:string,file?:string,class?:string}[]}
 */
export function extract(text, opts = {}) {
  const want = new Set(opts.types?.length ? opts.types.flatMap((t) => (t === 'hash' ? ['md5', 'sha1', 'sha256', 'sha512'] : t === 'ip' ? ['ipv4', 'ipv6'] : t === 'wallet' ? ['btc', 'eth', 'xmr'] : [t])) : TYPES);
  const benign = (opts.benignDomains ?? [...DEFAULT_BENIGN, ...(opts.noise === 'extended' ? EXTENDED_BENIGN : [])]).map(dglob);
  const benignIps = new Set((opts.benignIps ?? DEFAULT_BENIGN_IPS).map((x) => normalize(x.includes(':') ? 'ipv6' : 'ipv4', x)));
  const isBenign = (d) => benign.some((r) => r.test(d.toLowerCase()));
  const out = []; const seen = new Set();
  let pos = 0; let lineStart = 0; let line = ''; let orig = ''; let wasDefanged = false;
  // map a column in the refanged line back to the original (defanged) line
  const origCol = (c) => { if (!wasDefanged) return c; for (let k = 0; k <= orig.length; k++) if (refang(orig.slice(0, k)).length >= c) return k; return orig.length; };
  const add = (type, value, ln, raw, ctx, extra = {}) => {
    value = normalize(type, value);
    if ((type === 'ipv4' || type === 'ipv6') && benignIps.has(value)) return;
    const key = `${type}\0${type === 'url' || type === 'filename' || type === 'registry' ? value : value.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    const column = origCol(pos) + 1;
    out.push({ type, value, line: ln, column, offset: lineStart + column - 1, defanged: /\(defanged\)$/.test(raw), context: ctx.trim().slice(0, 200), ...(opts.file ? { file: opts.file } : {}), ...extra });
  };
  const lines = String(text).split(/\n/);
  lines.forEach((rawLine, i) => {
    if (i > 0) lineStart += lines[i - 1].length + 1;
    orig = rawLine.replace(/\r$/, '');
    const ln = i + 1;
    line = opts.refang === false ? orig : refang(orig);
    wasDefanged = line !== orig;
    const consumed = []; // spans already claimed by URL/email so we don't double count hosts
    const claim = (m) => consumed.push([m.index, m.index + m[0].length]);
    const inClaimed = (idx) => consumed.some(([a, b]) => idx >= a && idx < b);
    const rawOf = (v) => (wasDefanged ? `${v} (defanged)` : v);
    for (const m of line.matchAll(URL_RE)) {
      const u = trimUrl(m[0]); claim({ index: m.index, 0: u });
      let host = ''; try { host = new URL(u).hostname.replace(/^\[|\]$/g, ''); } catch { continue; }
      if (want.has('url') && !isBenign(host)) (pos = m.index, add)('url', u, ln, rawOf(u), orig, { host });
      if (host && /^[\d.]+$/.test(host)) { if (want.has('ipv4') && (opts.includePrivate || ipv4Class(host) === 'public')) (pos = m.index, add)('ipv4', host, ln, rawOf(host), orig, { class: ipv4Class(host) }); }
      else if (host && host.includes(':')) { if (want.has('ipv6') && (opts.includePrivate || ipv6Class(host) === 'public')) (pos = m.index, add)('ipv6', host, ln, rawOf(host), orig, { class: ipv6Class(host) }); }
      else if (host && want.has('domain') && validDomain(host) && !isBenign(host)) (pos = m.index, add)('domain', host.toLowerCase(), ln, rawOf(host), orig);
    }
    for (const m of line.matchAll(EMAIL)) {
      if (inClaimed(m.index)) continue; claim(m);
      if (want.has('email') && !isBenign(m[0].split('@')[1])) (pos = m.index, add)('email', m[0].toLowerCase(), ln, rawOf(m[0]), orig);
      const d = m[0].split('@')[1].toLowerCase();
      if (want.has('domain') && validDomain(d) && !isBenign(d)) (pos = m.index, add)('domain', d, ln, rawOf(d), orig);
    }
    for (const m of line.matchAll(REG)) { claim(m); if (want.has('registry')) (pos = m.index, add)('registry', m[0].replace(/[.,;:]+$/, ''), ln, m[0], orig); }
    for (const m of line.matchAll(IPV4)) {
      if (inClaimed(m.index) || !want.has('ipv4')) continue;
      const c = ipv4Class(m[0]);
      if (opts.includePrivate || c === 'public') (pos = m.index, add)('ipv4', m[0], ln, rawOf(m[0]), orig, { class: c });
    }
    for (const m of line.matchAll(IPV6)) {
      if (inClaimed(m.index) || !want.has('ipv6')) continue;
      const v = m[0];
      if (!v.includes('::') && v.split(':').length < 8) continue;
      if (/^\d+:\d+(:\d+)?$/.test(v) || /^[0-9a-f]{1,2}(:[0-9a-f]{1,2}){5}$/i.test(v)) continue; // times, MAC addresses
      if ((v.match(/:/g) || []).length < 2) continue;
      const c = ipv6Class(v);
      if (opts.includePrivate || c === 'public') (pos = m.index, add)('ipv6', v.toLowerCase(), ln, rawOf(v), orig, { class: c });
    }
    for (const m of line.matchAll(FILENAME)) { if (want.has('filename') && !inClaimed(m.index)) (pos = m.index, add)('filename', m[0].trim(), ln, m[0], orig); }
    for (const m of line.matchAll(DOMAIN)) {
      if (inClaimed(m.index) || !want.has('domain')) continue;
      const d = m[0].toLowerCase(); const tld = d.split('.').pop();
      if (!validDomain(d) || isBenign(d)) continue;
      if (/^\d+(\.\d+)+$/.test(d)) continue;
      // "invoice.exe" / "setup.py": file names, not domains, unless the line was defanged (analyst marked it)
      if (FILE_EXT.has(tld) && !wasDefanged && !opts.fileNameDomains) continue;
      (pos = m.index, add)('domain', d, ln, rawOf(d), orig);
    }
    for (const m of line.matchAll(HASH)) {
      const t = hashType(m[0]);
      if (!want.has(t) || isRepetitive(m[0])) continue;
      if (t === 'sha1' && line.slice(Math.max(0, m.index - 2), m.index) === '0x') continue; // ETH address
      add(t, m[0].toLowerCase(), ln, m[0], orig);
    }
    if (want.has('cve')) for (const m of line.matchAll(CVE)) (pos = m.index, add)('cve', m[0].toUpperCase(), ln, m[0], orig);
    if (want.has('attack')) for (const m of line.matchAll(ATTACK)) if (/att&?ck|mitre|technique|tactic|T1\d{3}|TA0|group|software/i.test(line) || m[0].startsWith('T1') || m[0].startsWith('TA0')) (pos = m.index, add)('attack', m[0], ln, m[0], orig);
    if (want.has('btc')) for (const m of line.matchAll(BTC)) if (btcValid(m[0])) (pos = m.index, add)('btc', m[0], ln, m[0], orig);
    if (want.has('eth')) for (const m of line.matchAll(ETH)) (pos = m.index, add)('eth', m[0].toLowerCase(), ln, m[0], orig);
    if (want.has('xmr')) for (const m of line.matchAll(XMR)) (pos = m.index, add)('xmr', m[0], ln, m[0], orig);
  });
  return out;
}

// Base58Check validation for legacy BTC addresses (cuts random-word false positives); bech32 by charset only.
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
import { createHash } from 'node:crypto';
export function btcValid(a) {
  if (a.startsWith('bc1')) return /^bc1[ac-hj-np-z02-9]{25,62}$/.test(a);
  let n = 0n; for (const ch of a) { const i = B58.indexOf(ch); if (i < 0) return false; n = n * 58n + BigInt(i); }
  let hex = n.toString(16); if (hex.length % 2) hex = '0' + hex;
  let bytes = Buffer.from(hex, 'hex'); const lead = a.match(/^1*/)[0].length;
  bytes = Buffer.concat([Buffer.alloc(lead), bytes]);
  if (bytes.length !== 25) return false;
  const sum = createHash('sha256').update(createHash('sha256').update(bytes.subarray(0, 21)).digest()).digest().subarray(0, 4);
  return sum.equals(bytes.subarray(21));
}

/** Defang a value for safe sharing (delegates to defang-sentinel, "full" style). */
export function defang(v) {
  const str = String(v);
  const type = /^[a-z][a-z0-9+.-]*:\/\//i.test(str) ? 'url' : str.includes('@') ? 'email' : /^[0-9a-f:]+$/i.test(str) && str.includes(':') ? 'ipv6' : 'domain';
  return type === 'url' || type === 'email' || /\./.test(str) ? defangValue(str, type, 'full') : str;
}
