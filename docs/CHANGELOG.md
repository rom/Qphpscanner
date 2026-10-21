# Changelog

All notable changes to **qphpscanner** are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

## [1.0.0] - 2026-10-21

First stable release. qphpscanner detects whether network services are backed
by PHP, collects the evidence behind each verdict, fingerprints the stack and
correlates known version-based vulnerabilities — as a CLI and a web GUI. All
probing is passive, read-only fingerprinting; vulnerability results are
informational, version-correlated leads, not confirmed findings. The entire
tool builds from the Go standard library, with no external dependencies.

### Detection & classification

- PHP detection from headers, cookies, response bodies, URL extensions and
  behavioural probes, with a weighted confidence score and verdict tiers
  (confirmed / likely / possible / none).
- Evidence carries full provenance: where it was found, how it matched, the
  literal matcher, the matched snippet (with body line number), the exact
  probe (method + URL) and its HTTP response code; each item has a
  low/medium/high confidence tier.
- Variant detection (PHP, HHVM, Zend Server) and best-effort SAPI inference
  (mod_php, PHP-FPM, LiteSpeed LSAPI, php-cgi, FrankenPHP/RoadRunner/Swoole).
- PHP version from `X-Powered-By`/`Server` banners, exposed `phpinfo()`,
  Apache server signatures, the `expose_php` easter-egg GUIDs, and more.
- Extension/module fingerprinting from `phpinfo()`, loader tokens, `Server`
  modules and exposed OPcache/APCu/PHP-FPM status pages.
- Shodan-style **mmh3 favicon hash** with an extensible product catalogue
  (`--favicon-catalog`).
- Broad application/CMS/addon detection (WordPress, Joomla, Drupal, Magento,
  TYPO3, Laravel, Symfony, Yii, CakePHP, CodeIgniter, Phalcon, phpBB, MediaWiki,
  Moodle, Nextcloud/ownCloud, phpMyAdmin, Adminer, Matomo, Zabbix, GLPI,
  and many more), with core-version extraction for several, and runtime-quirk /
  error-message signatures.
- Non-PHP products are recognised without inflating the PHP score
  (OpenCloud/oCIS, ONLYOFFICE, cPanel, Plesk, LiteSpeed).
- Reverse-proxy / CDN / WAF / load-balancer detection ("origin reply
  concealed"), web-server identification, and HTTP/2 + ALPN (and `h2c`)
  awareness.
- RFC 9116 `security.txt` discovery and parsing.

### Vulnerabilities

- Curated, version-correlated catalogue of PHP-core and famous CMS-core CVEs,
  including the October 2026 **php2shell** RCEs (CVE-2026-109618 /
  CVE-2026-109619) and end-of-life branch flagging.
- External feeds via `--vuln-feed` in the native schema **or standard OSV and
  CSAF 2.0** documents (auto-detected).
- `--fail-on` severity gating for CI.

### Targets, probing & politeness

- Targets: URL, IPv4/IPv6, CIDR, dashed ranges, per-octet and IPv6 wildcards,
  DNS wildcards (`*.domain`, via Certificate Transparency), and target lists
  from a file or stdin.
- Allow/block lists (`--allow` / `--block`; host, CIDR, `*.domain`).
- TLS modes (auto/on/off), detect vs deep depth, DNS enrichment and banner
  grabbing.
- Request shaping: custom headers, Basic/Bearer/cookie auth, vhost, and
  http(s)/SOCKS5 proxy (dependency-free SOCKS5 client).
- Politeness: global rate limiting, per-host and host-level concurrency,
  jitter, and retries with backoff.
- Resume via a checkpoint file.

### Output, reporting & audit

- Machine output: text, JSON, XML, CSV, SARIF, NDJSON (`--oA` writes them all).
- Reports: text, RTF, PDF, HTML (all written by hand, no dependencies).
- Scan diffing (`--diff`).
- Audit trail: a libpcap capture of every HTTP exchange (`--pcap`) and a
  human-readable session log explaining each decision (`--log`).

### Interfaces

- YAML configuration file with **full CLI parity**.
- Shell completions for bash, zsh and fish (`--completion`).
- Web GUI: live-streaming results that survive errors/timeouts/cancellation;
  Results / PHP / Failures sub-tabs with clickable summary-tile filters and a
  scan-order / PHP-first sort; Compare (diff two retained scans or a saved
  JSON/XML file); Statistics with pie and bar charts; an Info findings-explorer
  of clickable framework/addon/vulnerability tags; collapsible history with
  per-scan downloads; bulk target loading from a file; optional HTTP Basic auth;
  and mouse-over help throughout.

[Unreleased]: https://github.com/rom/Qphpscanner/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/rom/Qphpscanner/releases/tag/v1.0.0
