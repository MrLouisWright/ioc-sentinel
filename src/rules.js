export const RULES = {
  'watchlist-match': { severity: 'critical', title: 'IOC matches a known-bad watchlist entry', group: 'watchlist' },
  'ioc-url': { severity: 'medium', title: 'URL indicator', group: 'network' },
  'ioc-domain': { severity: 'low', title: 'Domain indicator', group: 'network' },
  'ioc-ipv4': { severity: 'low', title: 'Public IPv4 indicator', group: 'network' },
  'ioc-ipv6': { severity: 'low', title: 'Public IPv6 indicator', group: 'network' },
  'ioc-email': { severity: 'low', title: 'Email address indicator', group: 'network' },
  'ioc-hash': { severity: 'medium', title: 'File hash indicator (MD5/SHA1/SHA256/SHA512)', group: 'file' },
  'ioc-crypto-wallet': { severity: 'medium', title: 'Cryptocurrency wallet address (BTC/ETH/XMR)', group: 'financial' },
  'ioc-registry-key': { severity: 'low', title: 'Windows registry key', group: 'host' },
  'ioc-file-name': { severity: 'info', title: 'Suspicious executable/script file name', group: 'host' },
  'ioc-cve': { severity: 'info', title: 'CVE identifier', group: 'context' },
  'ioc-attack-technique': { severity: 'info', title: 'MITRE ATT&CK technique/tactic/group/software ID', group: 'context' },
};
