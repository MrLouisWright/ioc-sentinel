# Changelog

## 1.0.0 (2026-10-14)

First release, by Louis Wright.

- Extraction of URLs, domains, IPv4/IPv6, emails, MD5/SHA1/SHA256/SHA512, CVE and ATT&CK IDs, BTC/ETH/XMR wallets, registry keys and suspicious file names.
- Refanging of common defang styles; TLD validation, file-name and benign-domain filtering, private/reserved IP filtering, Base58Check validation.
- Watchlists with CIDR, parent-domain and URL-prefix matching (`watchlist-match`, critical).
- Static string extraction (ASCII + UTF-16LE) for binary files; directory and stdin input.
- CSV, plain list, STIX 2.1, JSON, SARIF 2.1.0 and Markdown output; allowlist with expiry, per-rule severity, `--fail-on` and exit codes 0/1/2; composite GitHub Action.
