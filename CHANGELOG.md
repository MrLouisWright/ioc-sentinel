# Changelog

## 1.1.0 (2026-10-15)

- **Refanging now comes from [defang-sentinel](https://www.npmjs.com/package/defang-sentinel)** (`^1.1.0`), the single home of defang/refang. `refang`/`defang` exports remain as thin wrappers for compatibility; ioc-sentinel no longer carries its own implementation.
- **Normalisation and dedupe:** `normalize()` lowercases hosts/hashes, strips trailing dots, compresses IPv6, drops default ports; duplicates across case and defang variants collapse into one IOC.
- **Noise filtering:** public resolver IPs (8.8.8.8, 1.1.1.1, 9.9.9.9, OpenDNS…) are dropped by default (`DEFAULT_BENIGN_IPS`, `--benign-ip`, `--no-benign`), and `--noise extended` also drops big-vendor/CDN/CA domains. Watchlisted values are never dropped. *Behaviour change:* those resolver IPs no longer appear in output unless you pass `--no-benign`.
- **MISP event JSON** (`--format misp`, `--misp <file>`, `formatMisp`) and **OpenIOC 1.1 XML** (`--format openioc`, `--openioc <file>`, `formatOpenIoc`) exports alongside STIX 2.1.
- **Source tracking:** every IOC has `line`, `column` and byte `offset` (mapped back through defanging); aggregated IOCs list all `occurrences`; finding locations are `file:line:col`.
- Dual ESM + CJS build, generated `.d.ts`, require/import CI checks.

## 1.0.0 (2026-10-14)

First release, by Louis Wright.

- Extraction of URLs, domains, IPv4/IPv6, emails, MD5/SHA1/SHA256/SHA512, CVE and ATT&CK IDs, BTC/ETH/XMR wallets, registry keys and suspicious file names.
- Refanging of common defang styles; TLD validation, file-name and benign-domain filtering, private/reserved IP filtering, Base58Check validation.
- Watchlists with CIDR, parent-domain and URL-prefix matching (`watchlist-match`, critical).
- Static string extraction (ASCII + UTF-16LE) for binary files; directory and stdin input.
- CSV, plain list, STIX 2.1, JSON, SARIF 2.1.0 and Markdown output; allowlist with expiry, per-rule severity, `--fail-on` and exit codes 0/1/2; composite GitHub Action.
