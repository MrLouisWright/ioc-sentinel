# ioc-sentinel

[![npm version](https://img.shields.io/npm/v/ioc-sentinel.svg)](https://www.npmjs.com/package/ioc-sentinel) [![CI](https://github.com/MrLouisWright/ioc-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/MrLouisWright/ioc-sentinel/actions/workflows/ci.yml) [![Node](https://img.shields.io/node/v/ioc-sentinel.svg)](https://nodejs.org) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Extract indicators of compromise from threat reports, logs, emails and binaries, then export them as CSV, STIX 2.1, JSON or SARIF.

`ioc-sentinel` pulls IOCs out of any text: URLs, domains, IPv4/IPv6 addresses, email addresses, MD5/SHA1/SHA256/SHA512 hashes, CVE IDs, MITRE ATT&CK IDs, Bitcoin/Ethereum/Monero wallets, Windows registry keys and suspicious file names. It **refangs** defanged indicators (`hxxps://evil[.]com`, `user[@]domain(dot)ru`) before matching, removes the usual noise (private IPs, `example.com`, XML namespaces, `setup.py`-style file names) and can **fail a pipeline when an IOC matches your watchlist**.

CLI, library and GitHub Action. Node.js 18+, **zero runtime dependencies**. Binaries are never executed: printable ASCII and UTF-16LE strings are read statically.

## Features

- **16 IOC types**: `url`, `domain`, `ipv4`, `ipv6`, `email`, `md5`, `sha1`, `sha256`, `sha512`, `cve`, `attack`, `btc`, `eth`, `xmr`, `registry`, `filename` (shortcuts: `hash`, `ip`, `wallet`).
- **Refanging**: `hxxp`, `hXXps`, `fxp`, `[.]`, `(.)`, `{.}`, `[dot]`, `\.`, `[:]`, `[://]`, `[@]`, `(at)`.
- **Noise reduction**: domains are checked against the gTLD/ccTLD list. Names ending in file extensions (`.exe`, `.py`, `.md`, `.zip`...) count as file names unless the analyst defanged them. Private, loopback, CGNAT, documentation, multicast and reserved IPs are dropped unless you pass `--include-private`. Repetitive hashes (`000…`) are ignored, Ethereum addresses aren't mistaken for SHA1, and legacy Bitcoin addresses are Base58Check-validated. A built-in benign-domain list can be replaced (`--benign`) or disabled (`--no-benign`).
- **Watchlist** (`-w known-bad.txt`): one IOC per line, defanged values accepted, with an optional label after a space, tab or comma. Supports IPv4 CIDR ranges, parent domains (`evil.com` also matches `cdn.evil.com` and URLs on it) and URL prefixes. Hits produce `watchlist-match` (critical), so the default `--fail-on critical` fails only on known-bad indicators.
- **Inputs**: files, whole directories (skips `.git` and `node_modules`), or stdin (`-`). Binary files are scanned via static string extraction.
- **Exports**: `--format csv|stix|list` or `--csv`/`--stix <file>`, with `--defang` to make CSV/list output safe to paste. The STIX 2.1 bundle contains indicators with proper patterns (`[file:hashes.'SHA-256' = '…']`), plus vulnerability and attack-pattern objects for CVEs and ATT&CK IDs, using deterministic IDs. The JSON report has a deduplicated `iocs` array with counts and `file:line` sources.

## Rules

| Rule | Default | Meaning |
|---|---|---|
| `watchlist-match` | critical | IOC matches the watchlist |
| `ioc-url` | medium | URL |
| `ioc-hash` | medium | MD5/SHA1/SHA256/SHA512 |
| `ioc-crypto-wallet` | medium | BTC/ETH/XMR address |
| `ioc-domain`, `ioc-ipv4`, `ioc-ipv6`, `ioc-email`, `ioc-registry-key` | low | Network and host indicators |
| `ioc-file-name`, `ioc-cve`, `ioc-attack-technique` | info | Context |

Use per-rule severity to tune what fails a build, e.g. make `ioc-crypto-wallet` critical in a repository that should never contain wallets.

## Install and run

```bash
npx ioc-sentinel report.pdf.txt                       # human-readable list, grouped by file
npx ioc-sentinel ./case-42/ --format csv --defang > iocs.csv
cat alert.eml | npx ioc-sentinel - -w known-bad.txt   # exit 1 on a watchlist hit
npx ioc-sentinel logs/ --types url,domain,ip --stix iocs.stix.json --sarif iocs.sarif
```

## Library

```js
import { extract, refang, defang, scan, formatStix } from 'ioc-sentinel';

extract('C2: hxxp://evil[.]com/gate 185.220.101[.]4');
// [{ type: 'url', value: 'http://evil.com/gate', defanged: true, line: 1, ... }, { type: 'domain', ... }, { type: 'ipv4', ... }]

const report = scan(['./incident'], { watchlist: 'evil.com\n185.220.101.0/24' });
report.iocs;              // deduplicated, with counts and sources
formatStix(report);       // STIX 2.1 bundle
```

## Configuration

Put a `.ioc-sentinel.json` in the working directory (or pass `--config <file>`). Every key is optional; CLI flags override the file.

```json
{
  "failOn": "critical",
  "severity": { "ioc-ipv4": "high" },
  "allow": [
    { "rule": "ioc-ipv4", "match": "8.8.8.8", "reason": "Accepted risk, ticket SEC-123", "expires": "2027-03-31" }
  ]
}
```

- **`severity`** changes the severity of any rule, or turns it `off`.
- **`allow`** suppresses findings. Each entry needs a `rule` (globs such as `ioc-*` work) and a `reason`, and can be narrowed with `target` and `match` (a glob tested against the target, location and value). Suppressed findings are listed in the JSON report. When `expires` (YYYY-MM-DD) has passed, the finding comes back together with an `allow-expired` finding, so exceptions can't be forgotten. Entries that match nothing are reported as `allow-unused` (info).

## Output and exit codes

- `--format text|json|sarif|markdown` for stdout, plus `--json`, `--sarif` and `--markdown <file>` to write extra copies in one run. SARIF 2.1.0 works with GitHub code scanning.
- `--fail-on critical|high|medium|low|info|none` (default `critical`).
- Exit code **0**: passed. **1**: at least one finding at or above `--fail-on`. **2**: usage or config error, or a target could not be checked.
- `--list-rules` prints every rule with its default severity.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # only for the SARIF upload
steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
    with: { persist-credentials: false }
  - uses: MrLouisWright/ioc-sentinel@v1
    with:
      targets: 'reports/'
      fail-on: critical
      sarif: ioc-sentinel.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with: { sarif_file: ioc-sentinel.sarif }
```

Inputs: `targets`, `fail-on`, `config`, `sarif`, `json`, `job-summary` (Markdown report in the job summary, default `true`), `args` (extra CLI flags), `watchlist`, `types`, `stix`, `csv`. Outputs: `markdown-file`, `exit-code`.

## Requirements

Node.js 18 or newer. No runtime dependencies.

## Support

If this project is useful to you, you can support its development with a donation: [Buy me a coffee](https://donate.stripe.com/aFa00lek3cvX4Ds2Fk9EI0b). It helps keep these tools maintained, documented and free for everyone.

## License

MIT © Louis Wright ([Louis Wright](https://github.com/MrLouisWright))
