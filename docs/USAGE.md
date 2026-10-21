# qphpscanner — Usage

`qphpscanner` detects whether network services are backed by PHP, collects the
evidence behind each verdict, and produces reports. It runs as a one-shot CLI
or as a local web GUI.

> **Authorised use only.** Only scan hosts and networks you own or are
> explicitly permitted to test.

## Contents

- [Synopsis](#synopsis)
- [Targets](#targets)
- [Ports](#ports)
- [TLS](#tls)
- [Scan depth](#scan-depth-detect-vs-deep)
- [Output formats](#output-formats)
- [Report formats](#report-formats)
- [Configuration file](#configuration-file)
- [Web GUI](#web-gui)
- [Resume](#resume)
- [Audit trail (PCAP and session log)](#audit-trail-pcap-and-session-log)
- [Exit status](#exit-status)
- [Examples](#examples)
- [Interpreting results](#interpreting-results)

## Synopsis

```
qphpscanner [options] <target> [target ...]
qphpscanner --web [--listen host:port]
qphpscanner --config scan.yaml
```

Run `qphpscanner --help` for the full flag list.

## Targets

Targets are given as positional arguments (or in the config file / web form).
Each target may be any of:

| Form | Example |
| --- | --- |
| URL | `https://example.com/app.php` |
| IPv4 literal | `203.0.113.10` |
| IPv6 literal | `2001:db8::1` or `[2001:db8::1]` |
| IPv4 CIDR | `10.0.0.0/24` |
| IPv6 CIDR | `2001:db8::/120` |
| Dashed range (last octet) | `192.168.1.10-20` |
| Dashed range (full) | `10.0.0.1-10.0.0.50`, `2001:db8::1-2001:db8::ff` |
| Wildcard | `192.168.1.*`, `10.0.*.*`, `2001:db8::*` (IPv6 trailing group) |
| DNS wildcard | `*.example.com` |
| Hostname | `example.com` |

Targets may also be read from a file or stdin with `--targets-file FILE`
(alias `-iL`), one per line; blank lines and `#` comments are ignored. Use `-`
to read from stdin. File targets are added to any given on the command line.

When a target is a **URL**, its scheme, port and path are honoured: that exact
endpoint is scanned (and `--ports` is ignored for it). All other target forms
are scanned across the selected port set.

A **DNS wildcard** (`*.example.com`) is expanded by querying Certificate
Transparency logs (crt.sh) for names issued under the domain; the discovered
hosts are then scanned across the selected ports. Quote it in a shell
(`'*.example.com'`) so the shell does not glob it. Disable this with
`--no-dns-enum`. If the lookup fails (e.g. the CT service is unreachable), the
spec is skipped with a progress message and the rest of the scan continues.

A single spec is capped at `--max-hosts` (default 65 536) expanded hosts to
guard against an accidental huge range.

## Ports

`--ports` accepts single ports, comma-separated lists, inclusive ranges, and
any mixture:

```
--ports 80
--ports 80,443,8080
--ports 8000-8100
--ports 80,443,8000-8010,9000
```

With no `--ports`, a built-in common-web-port set is used:
`80, 443, 8000, 8008, 8080, 8443, 8888, 3000, 5000, 9000`.

## TLS

`--tls` controls whether services are probed over HTTPS:

- `auto` (default) — infer from the port (443/8443/9443/4443/10443 ⇒ HTTPS),
  and fall back to the other scheme if the first attempt yields no HTTP
  response.
- `on` — force HTTPS.
- `off` — force HTTP.

A URL target's own scheme always wins. Use `--insecure` to probe hosts with
self-signed or otherwise invalid certificates.

## Scan depth: detect vs deep

- `--mode detect` (default) — decide **whether** each service is PHP and record
  the evidence. Fast; one request per service (plus security.txt).
- `--mode deep` — additionally fetch a small set of read-only probe paths
  (`/index.php`, `/info.php`, `/phpinfo.php`, `/composer.json`, framework entry
  points, and the `expose_php` easter-egg endpoints) to fingerprint the
  **version**, **variant**, **extensions/modules**, end-of-life status, and to
  correlate **known version-based vulnerabilities**.

All probes are GET requests; nothing is submitted and nothing is exploited.

## Output formats

`--format` selects the machine-readable scan output, written to stdout or to
`--out FILE`:

- `text` (default) — the same layout as the text report.
- `json` — a structured document (see `docs/DESIGN.md` for the schema).
- `xml` — the same data as XML, rooted at `<scan>`.
- `csv` — one row per service, for spreadsheets and quick triage.
- `sarif` — SARIF 2.1.0, for CI and security-tooling ingestion.
- `ndjson` — one JSON object per service (a leading meta line), for streaming.

If `--out` ends in `.json`/`.xml`/`.txt` the format is inferred from the
extension (unless `--format` is given explicitly).

`--oA BASE` writes every machine output plus an HTML report at once:
`BASE.json`, `BASE.xml`, `BASE.csv`, `BASE.sarif`, `BASE.txt` and `BASE.html`.

## Report formats

A report is a human-readable write-up (summary, per-host sections, evidence,
vulnerability leads, security.txt). Produce one with `--report` and/or
`--report-out`:

- `--report text` — write to stdout (or to `--report-out`).
- `--report rtf --report-out report.rtf` — Rich Text, opens in Word/LibreOffice.
- `--report pdf --report-out report.pdf` — PDF.
- `--report html --report-out report.html` — self-contained HTML.

`rtf`, `pdf` and `html` require `--report-out`. If only `--report-out` is
given, the format is inferred from the file extension.

The scan output (`--format`) and the report (`--report`) are independent — you
can request both in one run.

## Progress and verbosity

By default qphpscanner shows live progress on **stderr** (so it never mixes
with machine output on stdout):

- On a terminal, a single counter line is redrawn in place:
  `scanning… 128/2560 (open 12, php 4)`.
- When stderr is redirected, the counter is emitted as occasional full lines
  instead.
- Subdomain-enumeration steps are printed as `[*] …` lines.

`--verbose` (or `-v`) replaces the counter with one line per service — open
ports, PHP verdicts and versions, and closed/filtered ports — plus the
enumeration steps:

```
[*] enumerating subdomains for example.com via certificate transparency…
[*] found 37 host(s) for example.com
[+] www.example.com:443 open http php=confirmed PHP/8.2.4
[+] api.example.com:80 open http
[-] legacy.example.com:80 closed/filtered
```

`--quiet` (or `-q`) suppresses progress entirely. A one-line summary is always
printed to stderr when the scan finishes.

## Configuration file

`--config FILE` loads settings from a small YAML file. It has **full parity**
with the command line: every option — politeness (including
`host_concurrency`), enrichment, auth/headers (a list or a map), vulnerability
feeds, favicon catalogues, the audit trail (`pcap`/`log`) and `web.auth` — is
settable from the config. See
[`../config.example.yaml`](../config.example.yaml) for the full annotated
schema. Precedence, highest first:

1. Explicit command-line flags.
2. Values in the config file.
3. Built-in defaults.

Positional CLI targets override the config's `targets` list.

## Web GUI

```
qphpscanner --web                       # http://127.0.0.1:8088/
qphpscanner --web --listen 0.0.0.0:9000 # bind elsewhere (use with care)
```

The GUI offers a form (targets, ports, depth, TLS, timeout, concurrency and
toggles), shows a **progress bar and live feed** while scanning (with a
**Cancel** button that aborts the run), renders per-service result cards with
colour-coded PHP verdicts, evidence and vulnerability leads, and keeps
**previous scans below the current one as collapsible, server-persisted
entries** — each with its own download links. Downloads cover JSON, XML, CSV,
SARIF, text, HTML, RTF and PDF, named uniquely with the scan's timestamp.

The targets box supports **bulk loading from a file** ("Load from file…"):
one or more local lists are read in the browser (nothing is uploaded) and
their lines appended, with `#` comments and blanks skipped. An **Allow / block
lists** section lets you override the target list (keep only matching hosts,
or drop matching hosts). The results area is **resizable**, and each result
card shows the **DNS name** and any resolved **A/PTR** records at its top.

The GUI has four tabs:

- **Scan** — configure and run a scan, watch progress, browse results and the
  previous-scan history. Results stream in live and are split into three
  sub-tabs with live counts: **Results** (services that answered), **PHP**
  (only services classified as PHP), and **Failures** (closed or filtered
  ports, connection errors, timeouts, open non-HTTP ports). If a scan errors,
  times out or is **cancelled**, whatever was collected so far stays on
  screen — it is never wiped — and a banner explains what happened. A **sort**
  control orders the Results and PHP tabs by scan order or with PHP services
  (highest confidence first) on top. Most controls have **mouse-over help**.
- **Compare** — pick any two retained scans (or an older one against the
  latest), **or load a previously saved scan file (JSON or XML)** as the
  baseline, and see added/removed services and per-service verdict, version
  and vulnerability changes.
- **Statistics** — figures aggregated across all retained scans, with **pie
  and bar charts**: vulnerability-lead severities and PHP verdicts as pies;
  top vulnerabilities, top applications and top networks as bars; plus
  highest severity, oldest PHP/application version and average scan time.
- **Info** — a findings explorer: every framework, addon/tool and
  vulnerability as a tag; click one to list the scan items that carry it.

Protect the GUI with `--web-auth user:pass` (HTTP Basic auth). It is bound to
localhost by default; exposing it to a network makes a scan trigger available
to anyone who can reach it, so do so only on trusted networks and with auth.

### HTTP API

The GUI is backed by a tiny JSON API you can script against:

- `POST /api/scan` — body is a JSON object with the same fields as the form
  (`targets` array or `targets_text`, `ports`, `mode`, `tls`,
  `timeout_seconds`, `concurrency`, `follow_redirects`, `insecure`,
  `security_txt`, `include_closed`, `no_dns_enum`). The response is a stream of
  newline-delimited JSON (`application/x-ndjson`): zero or more
  `{"type":"progress","event":{…}}` lines followed by a final
  `{"type":"result","result":{…}}` (or `{"type":"error","error":"…"}`).
- `GET /api/download?format=json|xml|csv|sarif|text|html|rtf|pdf[&scan=<id>]` —
  renders the most recent scan result, or a specific one by `scan` id.
- `GET /api/history` — lists retained scans (newest first) with summaries and
  ids.

## Authentication & request shaping

To scan applications behind auth or virtual hosts:

- `--header "Name: value"` — add a request header (repeatable).
- `--cookie "sid=…"` — send a Cookie header.
- `--bearer TOKEN` — send `Authorization: Bearer TOKEN`.
- `--basic user:pass` — HTTP Basic auth.
- `--vhost HOST` — override the Host header on the initial request (name-based
  virtual hosts on a shared IP). It is not carried across redirects.
- `--proxy URL` — route all requests through an `http(s)://` or
  `socks5://[user:pass@]host:port` proxy.

## Politeness & rate limiting

- `--rate N` — cap outbound HTTP requests to N per second across the whole scan.
- `--per-host-concurrency N` — at most N concurrent probes against one host.
- `--jitter DUR` — sleep a random time up to DUR before each service probe.
- `--retries N` — retry transient network failures N times with backoff.

## Enrichment

- `--resolve-dns` — record forward addresses and reverse (PTR) names per host.
- `--banners` — for open ports that do not speak HTTP, read a short service
  banner (SSH/FTP/SMTP announce themselves) so the port is labelled.

Every HTTP service is also checked for a **web server** (product/version/OS/
modules) and for a **reverse proxy / CDN / WAF / load balancer** in front.
When a front layer is found the result is flagged as *concealed* — the real
origin reply may be hidden, cached, filtered or challenged — with a note
explaining the implication. Front-layer detection works from response headers
and cookies even in `detect` mode; **deep** mode adds active identification
probes (an `OPTIONS` request, a guaranteed-404 to harvest error-page
signatures and WAF block pages, and status endpoints such as `/server-status`
and `/nginx_status`). Every signal carries a confidence tier (low/medium/high).

## Vulnerability feeds

Deep mode correlates versions against the built-in catalogue. Merge extra data
with `--vuln-feed FILE|URL` (repeatable); feeds override EOL dates by branch.
Three formats are auto-detected:

- the native `qphpscanner-vuln-feed/1` schema (see
  [`vuln-feed.example.json`](vuln-feed.example.json)),
- **OSV** records (a single object or a JSON array) — e.g. osv.dev / GitHub
  advisory exports for Packagist packages,
- **CSAF 2.0** advisories — vendor security documents (TYPO3, Drupal, …).

PHP-core advisories feed the PHP correlation; everything else is keyed by a
normalised framework/package name (drupal, wordpress, laravel, …).

## Favicon catalogue

In deep mode the site favicon's mmh3 hash is matched against a built-in
product catalogue and, on a hit, attributes the product and adds evidence.
Extend or override it with `--favicon-catalog FILE|URL` (repeatable); the file
is `{"schema":"qphpscanner-favicon-catalog/1","favicons":[{"hash":"…",
"product":"…","framework":"…","php":true}]}`. An unknown hash is simply inert.

## Host and service concurrency

`--concurrency` caps total in-flight service probes; `--per-host-concurrency`
caps probes against one host; `--host-concurrency` caps how many distinct hosts
are worked at once (0 = no host cap). Combine them to sweep large target sets
politely — e.g. `--host-concurrency 10 --per-host-concurrency 2`.

## Shell completions

`--completion bash|zsh|fish` prints a completion script generated from the live
flag set:

```sh
# bash
source <(qphpscanner --completion bash)
# zsh (into a directory on $fpath)
qphpscanner --completion zsh > ~/.zfunc/_qphpscanner
# fish
qphpscanner --completion fish > ~/.config/fish/completions/qphpscanner.fish
```

## Diffing scans

`--diff baseline.json` compares the current scan against a previously saved
JSON result and prints what changed (new/gone services, version and verdict
changes, new/resolved vulnerability leads). `--diff-format` is `text` (default)
or `json`. With `--diff`, scan output is written only to an explicit `--out`.

## Resume

`--resume FILE` records each completed service to FILE as it finishes. Re-run
the same command with the same `--resume FILE` to skip already-scanned
services and continue — useful for large or interrupted sweeps.

## Audit trail (PCAP and session log)

For engagements that must be fully auditable, two optional outputs record
exactly what the tool did and why.

`--pcap FILE` writes a **libpcap capture** of every HTTP exchange the scan
performs. Each request/response is reconstructed as a complete TCP conversation
(SYN / SYN-ACK / ACK handshake, PSH/ACK data segments, graceful teardown) with
valid IPv4/TCP checksums, so the file opens directly in Wireshark, tcpdump or
tshark:

```sh
qphpscanner --mode deep --pcap scan.pcap example.com
tcpdump -nr scan.pcap        # or: wireshark scan.pcap
```

Because probing is passive and HTTPS is terminated locally, the capture holds
the plaintext HTTP that was exchanged (for TLS targets too); packet timing is
approximate and link type is `RAW` (IPv4). Hostnames that are not IP literals
are mapped to stable addresses in `10.0.0.0/8` so the capture stays valid.

`--log FILE` writes a **human-readable session log**. It records each request
and its response headers as they happen, then, per service, a `DECISION` block
that states the web server, any reverse proxy, the PHP verdict and version, and
— evidence by evidence — *where* each signal was found, *how* it matched, the
probe that produced it, the literal matcher and the matched snippet:

```
DECISION  192.0.2.10:443  https://192.0.2.10:443/
  web server: Apache 2.4.41
  PHP verdict: CONFIRMED (confidence 100/100)
  version: 8.1.2 — learned via X-Powered-By header
  reasoning — 5 evidence item(s), highest-weighted first:
    • [high w80] header.x-powered-by — X-Powered-By advertises PHP
        where: response header 'X-Powered-By'
        how:   header substring match
        probe: https://192.0.2.10:443/
        matcher: php
        match: X-Powered-By: PHP/8.1.2
```

Both flags can be combined, and work with any scan mode and target type.

## Exit status

- `0` — the scan completed (regardless of what was found).
- `1` — a fatal error (bad target/port spec, unreadable config/feed, I/O error).
- `2` — the scan completed but a `--fail-on` gate matched (see below).

`--fail-on LEVEL` makes the process exit `2` when a finding meets a threshold:
`low`, `medium`, `high`, `critical` (a vulnerability lead at least that severe)
or `eol` (any end-of-life PHP branch). Output and reports are still written.
This is for CI gating:

```sh
qphpscanner --mode deep --fail-on high --format sarif --out scan.sarif example.com || echo "findings!"
```

A one-line summary is printed to stderr after each scan.

## Examples

```sh
# Minimal: is it PHP?
qphpscanner example.com

# Deep scan with a PDF report
qphpscanner --mode deep --report-out audit.pdf https://example.com

# Subnet sweep, HTTPS only, JSON to file, no closed-port noise
qphpscanner --tls on --format json --out results.json 10.0.0.0/24

# Specific ports and a range, text report to stdout
qphpscanner --ports 80,443,8000-8010 --report text example.com

# IPv6 host, deep, ignore cert errors
qphpscanner --mode deep --insecure https://[2001:db8::1]:8443/

# Drive everything from a config file
qphpscanner --config scan.yaml

# Full audit trail: PCAP capture + decision log
qphpscanner --mode deep --pcap scan.pcap --log scan.log example.com

# Web GUI
qphpscanner --web
```

## Interpreting results

Each service gets a **verdict** derived from a weighted confidence score
(0–100):

| Verdict | Score | Meaning |
| --- | --- | --- |
| `confirmed` | ≥ 70 | strong, usually unambiguous PHP evidence |
| `likely` | 50–69 | multiple corroborating signals |
| `possible` | 25–49 | weak/circumstantial signals |
| `none` | < 25 | no meaningful PHP evidence |

Every contributing signal is listed as **evidence** with its weight, confidence
tier and full provenance — *where* it was found, *how* it matched, the literal
matcher, the matched snippet (with the body line number where applicable) and
the exact probe (method + URL) that produced it — so you can audit *why* a
verdict was reached down to the byte. The same reasoning is written to the
`--log` session log, and every exchange behind it to the `--pcap` capture.

**Vulnerability leads** are correlated from the detected version alone. They
indicate issues that *affect that version*, not that the host is exploitable —
many require a specific SAPI or configuration (noted in `match_basis`). Always
confirm against the live service before acting.
