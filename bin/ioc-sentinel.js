#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { runCli, list } from '../src/cli-core.js';
import { scan, TOOL, TYPES, formatCsv, formatList, formatStix, formatMisp, formatOpenIoc } from '../src/index.js';

const HELP = `ioc-sentinel {VERSION} — extract indicators of compromise from text, logs, reports and binaries

Usage: ioc-sentinel <file|dir|-> [...] [options]

Extraction
  -t, --types <list>         ${TYPES.join(', ')} (also: hash, ip, wallet). Default: all
      --include-private      Keep private/loopback/documentation IPs (dropped by default)
      --benign <list>        Domains to ignore (globs ok); replaces the built-in noise list
      --no-benign            Do not drop example.com, w3.org, schemas.microsoft.com, 8.8.8.8, 1.1.1.1 etc.
      --benign-ip <list>     IPs to ignore; replaces the built-in resolver list
      --noise <level>        default | extended (also drop microsoft.com, google.com, CDNs, CAs...)
      --no-refang            Do not refang hxxp://, [.] and friends before matching
      --no-binary            Skip binary files (default: extract printable strings statically)
      --file-name-domains    Treat names like "setup.py"/"invoice.zip" as domains too
  -w, --watchlist <file>     Known-bad IOCs (one per line; CIDR and *.domain ok). Hits are critical
Export
  -f, --format <fmt>         text | json | sarif | markdown | csv | stix | misp | openioc | list
      --defang               Defang values in csv/list output
      --csv <file>           Also write CSV;  --stix <file> also write a STIX 2.1 bundle
      --misp <file>          Also write a MISP event JSON;  --openioc <file> also write OpenIOC 1.1 XML
{COMMON}

Default --fail-on is critical, so only watchlist matches fail the run.
Examples:
  ioc-sentinel report.txt --format csv --defang
  cat alert.log | ioc-sentinel - -w known-bad.txt --stix iocs.stix.json`;

process.exitCode = await runCli(TOOL, {
  help: HELP,
  formats: ['csv', 'stix', 'misp', 'openioc', 'list'],
  options: {
    types: { type: 'string', short: 't' }, 'include-private': { type: 'boolean' }, benign: { type: 'string' }, 'no-benign': { type: 'boolean' },
    'no-refang': { type: 'boolean' }, 'no-binary': { type: 'boolean' }, 'file-name-domains': { type: 'boolean' }, watchlist: { type: 'string', short: 'w' },
    defang: { type: 'boolean' }, csv: { type: 'string' }, stix: { type: 'string' }, misp: { type: 'string' }, openioc: { type: 'string' }, 'benign-ip': { type: 'string' }, noise: { type: 'string' },
  },
  run(o, pos, cfg, ctx) {
    const inputs = pos.length ? pos : cfg.paths || [];
    if (!inputs.length) throw Object.assign(new Error('No input given (use - for stdin)'), { usage: true });
    const resolved = inputs.map((p) => (p === '-' ? { name: 'stdin', text: readFileSync(0, 'utf8') } : p));
    let watchlist = cfg.watchlist;
    const wl = o.watchlist || cfg.watchlistFile;
    if (wl) { try { watchlist = readFileSync(wl, 'utf8'); } catch (e) { throw Object.assign(new Error(`Cannot read watchlist ${wl}: ${e.code}`), { usage: true }); } }
    const report = scan(resolved, {
      types: o.types ? list(o.types) : cfg.types, includePrivate: o['include-private'] ?? cfg.includePrivate,
      benignDomains: o['no-benign'] ? [] : o.benign ? list(o.benign) : cfg.benignDomains, benignIps: o['no-benign'] ? [] : o['benign-ip'] ? list(o['benign-ip']) : cfg.benignIps, noise: o.noise ?? cfg.noise, refang: o['no-refang'] ? false : cfg.refang,
      binaryStrings: o['no-binary'] ? false : cfg.binaryStrings, fileNameDomains: o['file-name-domains'] ?? cfg.fileNameDomains,
      watchlist, allow: cfg.allow, severity: cfg.severity,
    });
    const d = { defanged: !!(o.defang ?? cfg.defang) };
    if (o.csv) writeFileSync(o.csv, formatCsv(report, d));
    if (o.stix) writeFileSync(o.stix, formatStix(report));
    if (o.misp) writeFileSync(o.misp, formatMisp(report));
    if (o.openioc) writeFileSync(o.openioc, formatOpenIoc(report));
    const custom = { csv: () => formatCsv(report, d), stix: () => formatStix(report), misp: () => formatMisp(report), openioc: () => formatOpenIoc(report), list: () => formatList(report, d) }[ctx.format];
    return custom ? { report, output: custom() } : report;
  },
});
