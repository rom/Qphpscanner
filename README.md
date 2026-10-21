# qphpscanner

A command-line and web tool, written in Go, that scans network ports and
HTTP(S) services to determine whether they are **built on PHP**, collects the
supporting **evidence**, and produces **reports**.

It is a passive fingerprinting and reporting tool in the spirit of
WhatWeb / Wappalyzer / httpx, focused specifically on PHP: it reads banners,
headers, cookies and response bodies and reasons about them. In **deep** mode
it also fingerprints the PHP version and variant, enumerates extensions and
server modules, flags end-of-life branches, and correlates **known
version-based vulnerabilities**. It never attempts to exploit anything.

> **Authorised use only.** Scan only hosts and networks you own or have
> explicit permission to test. Port scanning and service fingerprinting may be
> regulated where you operate.

## Features

- **PHP detection** from many signals: `X-Powered-By` / `Server` banners and
  **Apache server-signature footers** (which also leak the version),
  `PHPSESSID` and a large set of framework/app session cookies (TYPO3,
  Roundcube, WooCommerce, osCommerce, Nextcloud, …), `.php`/`.phtml` URL
  extensions, a broad set of **PHP error/stack-trace patterns**, **leaked PHP
  source** (`<?php`), "Powered by …" footers and CMS/framework markers
  (WordPress, Drupal, Joomla, Laravel, Symfony, Magento, TYPO3, phpBB, Discuz,
  Bitrix, MediaWiki, …), **PATH_INFO behaviour** (`index.php/…`), exposed
  `phpinfo()` / Composer artefacts, and the classic `expose_php` easter eggs.
  A best-effort **SAPI** guess (mod_php / php-fpm / php-cgi) is included.
- **Version, variant, extensions, modules & addons** (deep mode): PHP vs HHVM
  vs Zend Server; version from headers, `phpinfo()` or server signatures; an
  extended extension catalogue (OPcache, Xdebug, ionCube, SourceGuardian, APM
  agents like New Relic/Blackfire/Tideways, redis, imagick, …) parsed from
  `phpinfo()`, loader messages and exposed status dashboards
  (`opcache.php`/`apcu.php`); web-server modules from the `Server` banner;
  **addons/tools** (phpMyAdmin, Adminer, Laravel Debugbar, Whoops, Clockwork,
  WooCommerce, …); end-of-life evaluation; a Shodan-style **favicon mmh3
  hash**.
- **CMS core version detection** (deep mode): WordPress / Drupal / Joomla core
  versions from generator tags, `readme.html`, `CHANGELOG.txt` and manifests —
  and their correlated CVEs.
- **Reverse proxy / CDN / WAF / load-balancer detection**: flags when a front
  layer (Cloudflare, Akamai, CloudFront, Fastly, Sucuri, Imperva, Varnish, F5,
  AWS ELB, …) sits in front, so you know the **origin reply is concealed** and
  possibly filtered/protected — with a plain-language note on what that means.
- **Web-server identification**: product, version, OS hint and server-level
  modules (Apache/nginx/IIS/LiteSpeed/OpenResty/Caddy/…; `mod_*`, OpenSSL,
  ASP.NET, WebDAV, mod_pagespeed, …) from `Server` banners, error-page
  signatures and `OPTIONS`.
- **Active identification probes** (deep mode): an `OPTIONS` request, a
  guaranteed-404 to harvest error-page signatures/WAF block pages, and status
  endpoints (`/server-status`, `/nginx_status`, …) to coax the stack into
  identifying itself.
- **Confidence tiers** (low/medium/high) on every signature and evidence item.
- **Evidence provenance**: each evidence item records *where* it was found
  (which header/cookie/body/behaviour), *how* it matched (the technique), the
  literal matcher, the matched snippet with context, the body line number, the
  exact probe (method + URL) and its **HTTP response code** — in every output
  and report.
- **Vulnerability leads** (deep mode): a curated, version-correlated catalogue
  of ~40 PHP-core CVEs plus famous CMS-core CVEs (CVE-2024-4577,
  CVE-2019-11043, CVE-2012-1823, Drupalgeddon2, …), **extensible with external
  feeds** (`--vuln-feed file|URL`) in the native schema **or standard OSV and
  CSAF 2.0** documents (auto-detected). Leads are informational — correlated
  from the detected version, not confirmed by exploitation.
- **Favicon/asset hash catalogue**: matches a site's mmh3 favicon hash against
  a built-in product map (phpMyAdmin, Adminer, WordPress, Joomla, Drupal,
  phpBB, Roundcube, Zabbix, GLPI, …), extensible with `--favicon-catalog`.
- **HTTP/2 + ALPN awareness**: negotiates HTTP/2 via ALPN and records the
  negotiated protocol, plus cleartext-h2c (`Upgrade: h2c`) advertisement.
- **Broad PHP evidence**: ~70 application/framework/addon cookies and headers,
  dozens of PHP runtime-quirk and error-message body signatures, and exposure
  probes (`.env`, Symfony profiler, Laravel Telescope/Horizon, PHP-FPM status,
  Nextcloud status).
- **security.txt** (RFC 9116): discovers and parses `/.well-known/security.txt`
  and surfaces it in every output and report.
- **Flexible targets**: single URL, IPv4/IPv6 literal, CIDR block, dashed
  ranges (`1.2.3.4-9`, `1.2.3.4-1.2.3.9`, IPv6 `a::1-a::ff`), per-octet and
  IPv6 trailing-group wildcards (`1.2.3.*`, `2001:db8::*`), **DNS wildcards**
  (`*.example.com`) enumerated via Certificate Transparency, and target lists
  from a file or stdin (`--targets-file`/`-iL`).
- **Flexible ports**: single, comma lists and ranges, mixable
  (`80,443,8000-8100`).
- **TLS control**: `auto` (infer from port), `on`, or `off`.
- **Two scan depths**: `detect` (is it PHP?) and `deep` (full fingerprint).
- **Enrichment**: forward/reverse **DNS** per host (`--resolve-dns`) and
  **banner grabbing** for open non-HTTP ports (`--banners`).
- **Request shaping**: custom headers, Basic/Bearer/cookie **auth**, **vhost**
  (Host header) scanning, and an http(s)/**SOCKS5** proxy.
- **Politeness**: global **rate limiting** (`--rate`), per-host concurrency,
  **host-level concurrency** (`--host-concurrency`, cap distinct hosts scanned
  at once), jitter, and retries with backoff.
- **Resume**: checkpoint completed services and continue an interrupted scan
  (`--resume`).
- **Audit trail**: save a **libpcap capture** of every HTTP exchange as a TCP
  conversation (`--pcap FILE`, opens in Wireshark/tcpdump), and/or a
  **human-readable session log** (`--log FILE`) that records each request and
  explains, evidence by evidence, how the verdict was decided.
- **Live progress**: a running counter by default (updated in place on a
  terminal) and a `--verbose` mode that reports every host/port outcome;
  the web GUI shows a progress bar and a live feed.
- **Output formats**: **text**, **JSON**, **XML**, **CSV**, **SARIF** (CI
  ingestion) and **NDJSON**; `--oA` writes them all at once.
- **Report formats**: **text**, **RTF**, **PDF**, **HTML** (RTF/PDF/HTML
  written by hand — see below).
- **Scan diffing** (`--diff`) and **severity exit codes** (`--fail-on`) for
  monitoring and CI gating.
- **YAML config file** support with **full CLI parity** — every option
  (politeness, enrichment, auth/headers, feeds, audit trail, …) is settable
  from the config, with flags overriding it.
- **Shell completions** for bash, zsh and fish (`--completion <shell>`).
- **CLI *and* a web GUI** with live progress, a cancel button, optional Basic
  auth, a persistent collapsible history, per-scan downloads, a resizable
  results area, **bulk target loading from a file**, **allow/block** overrides,
  a **Compare** tab (diff any two scans), a **Statistics** tab (top vulns,
  oldest PHP/app, top apps/networks, …) and an **Info** tab that lists every
  framework/addon/vulnerability as a clickable tag.
- **Target allow/block lists** (`--allow`/`--block`, host/CIDR/`*.domain`).
- **Zero external dependencies** — the entire tool builds from the Go standard
  library, including the YAML parser, the RTF/PDF writers, the SOCKS5 client
  and the mmh3 favicon hash.

## Install

```sh
# from source (Go 1.24+)
git clone https://github.com/rom/qphpscanner
cd qphpscanner
make build          # produces bin/qphpscanner
# or install system-wide (binary + man page):
sudo make install
```

## Quick start

```sh
# Is this service PHP?
qphpscanner example.com

# Deep fingerprint a few ports, write a PDF report:
qphpscanner --mode deep --ports 80,443,8080 --report-out report.pdf example.com

# Scan a subnet, force HTTPS, emit JSON to a file:
qphpscanner --tls on --format json --out scan.json 10.0.0.0/28

# Enumerate subdomains of a domain and scan them, with per-host detail:
qphpscanner --verbose '*.example.com'

# Launch the web GUI:
qphpscanner --web           # then open http://127.0.0.1:8088/
```

## Usage overview

```
qphpscanner [options] <target> [target ...]
qphpscanner --web [--listen host:port]
qphpscanner --config scan.yaml
```

| Option | Description |
| --- | --- |
| `--mode detect\|deep` | scan depth (default `detect`) |
| `--ports SPEC` | `80` · `80,443` · `8000-8100` · mixed (default: common web ports) |
| `--tls auto\|on\|off` | TLS handling (default `auto`) |
| `--format text\|json\|xml` | scan output format (default `text`) |
| `--out FILE` | write scan output to a file |
| `--report text\|rtf\|pdf` | also produce a report |
| `--report-out FILE` | report destination (required for rtf/pdf) |
| `--timeout DUR` | per-connection timeout (e.g. `5s`) |
| `--concurrency N` | max concurrent probes (default 50) |
| `--follow` | follow redirects (default true) |
| `--insecure` | skip TLS verification |
| `--security-txt` | fetch security.txt (default true) |
| `--include-closed` | include closed ports in output |
| `--verbose` / `-v` | per-host/port progress detail |
| `--quiet` / `-q` | suppress progress output |
| `--no-dns-enum` | disable `*.domain` subdomain enumeration |
| `--targets-file` / `-iL` | read targets from a file (`-` for stdin) |
| `--resolve-dns` | add forward/reverse DNS per host |
| `--banners` | grab a banner from open non-HTTP ports |
| `--rate N` | max outbound HTTP requests/sec |
| `--per-host-concurrency N` | max concurrent probes per host |
| `--jitter DUR` | random delay before each service probe |
| `--retries N` | retries on transient network errors |
| `--header "K: V"` | extra request header (repeatable) |
| `--cookie` / `--bearer` / `--basic u:p` | authentication |
| `--vhost HOST` | override the Host header (virtual-host scan) |
| `--proxy URL` | http(s):// or socks5:// proxy |
| `--vuln-feed FILE\|URL` | merge an external vulnerability feed (repeatable) |
| `--fail-on LEVEL` | exit non-zero on `low\|medium\|high\|critical\|eol` |
| `--oA BASE` | write json/xml/csv/sarif/txt + HTML report to `BASE.*` |
| `--diff FILE` | diff against a prior JSON scan |
| `--resume FILE` | checkpoint/resume a scan |
| `--pcap FILE` | write a libpcap capture of every HTTP exchange (audit trail) |
| `--log FILE` | write a session log explaining each detection decision |
| `--vuln-feed F\|URL` | merge a native, OSV or CSAF vuln feed (repeatable) |
| `--favicon-catalog F\|URL` | merge a favicon-hash → product catalogue (repeatable) |
| `--host-concurrency N` | cap distinct hosts scanned at once |
| `--completion SHELL` | print a bash/zsh/fish completion script |
| `--config FILE` | load a YAML config (full CLI parity) |
| `--web` / `--listen` / `--web-auth u:p` | run the web GUI / address / Basic auth |
| `--version` | print version |

See [`docs/USAGE.md`](docs/USAGE.md) for the full reference and
[`docs/DESIGN.md`](docs/DESIGN.md) for architecture and detection internals.
A man page is in [`docs/qphpscanner.1`](docs/qphpscanner.1).

## Web GUI

`qphpscanner --web` serves a single-page interface (bound to localhost by
default) for configuring and running scans, browsing per-service results with
colour-coded PHP verdicts, evidence and vulnerability leads, and downloading
the results as JSON/XML/text or a RTF/PDF report. While a scan runs it shows a
**progress bar and a live feed** (the scan endpoint streams NDJSON), and each
completed scan is kept **below the current one as a collapsible entry** so you
can revisit earlier runs. All scan-derived text is inserted into the DOM as
text (never HTML), so hostile response data cannot be reflected into the page.

## Vulnerability data & feeds

Deep mode correlates the detected PHP (and CMS) version against a curated,
built-in catalogue of ~40 PHP-core CVEs plus famous CMS-core CVEs, and
evaluates end-of-life status per release branch. The catalogue is data-driven
and **extensible at runtime**:

```sh
qphpscanner --mode deep --vuln-feed feeds/php-extra.json --vuln-feed https://example.com/feed.json example.com
```

Feeds are JSON, merged on top of the built-in data (EOL dates override by
branch). See [`docs/vuln-feed.example.json`](docs/vuln-feed.example.json) for
the schema. Correlation is informational — a lead means the version is *in an
affected range*, not that the host is exploitable; many issues require a
specific SAPI or configuration (shown in each lead's `match_basis`).

## Output & report formats

- **Scan output** (`--format`): `text`, `json`, `xml`, `csv`, `sarif`,
  `ndjson` — machine-readable records of every probed service. `--oA BASE`
  writes json/xml/csv/sarif/txt plus an HTML report in one go.
- **Report** (`--report` / `--report-out`): `text`, `rtf`, `pdf`, `html` — a
  human-readable write-up with a summary, per-host sections, evidence and
  vulnerability leads. The RTF, PDF and HTML writers are self-contained (no
  external libraries), so reports work in any build environment.

## Development

```sh
make check      # gofmt check + go vet + tests
make test-race  # tests under the race detector
make dist       # cross-compile release binaries into dist/
```

## License

MIT — see [LICENSE](LICENSE).
