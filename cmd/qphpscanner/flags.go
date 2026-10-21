package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// stringSlice is a repeatable string flag.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// flags holds the parsed command-line flag values.
type flags struct {
	configPath    string
	ports         string
	mode          string
	tls           string
	timeout       time.Duration
	concurrency   int
	follow        bool
	insecure      bool
	securityTxt   bool
	includeClosed bool
	format        string
	out           string
	report        string
	reportOut     string
	userAgent     string
	maxHosts      int
	web           bool
	listen        string
	showVersion   bool
	completion    string
	verbose       bool
	quiet         bool
	noDNSEnum     bool

	// politeness
	rate          float64
	perHost       int
	hostConc      int
	jitter        time.Duration
	retries       int
	requestBudget int

	// enrichment
	resolveDNS bool
	banners    bool

	// http shaping
	headers   stringSlice
	cookie    string
	bearer    string
	basicAuth string
	vhost     string
	proxy     string
	resolve   stringSlice
	sni       string

	// data / resume / reporting extras
	vulnFeeds        stringSlice
	faviconCatalogs  stringSlice
	signaturePacks   stringSlice
	composerFiles    stringSlice
	allow            stringSlice
	block            stringSlice
	failOn           string
	outAll           string
	diffPath         string
	diffFormat       string
	resume           string
	verifySubdomains bool
	targetsFile      string
	webAuth          string

	// audit trail
	pcapPath string
	logPath  string
}

func newFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("qphpscanner", flag.ContinueOnError)
	fs.Usage = func() {
		w := fs.Output()
		fmt.Fprintf(w, `qphpscanner — detect PHP-backed services, collect evidence, report.

Usage:
  qphpscanner [options] <target> [target ...]
  qphpscanner --web [--listen host:port]
  qphpscanner --config scan.yaml

Targets:
  URL           https://example.com/app.php
  IPv4/IPv6     203.0.113.10        2001:db8::1
  CIDR          10.0.0.0/24         2001:db8::/120
  Range         192.168.1.10-20     10.0.0.1-10.0.0.50
  IP wildcard   192.168.1.*         10.0.*.*
  DNS wildcard  *.example.com       (enumerates subdomains via certificate transparency)

Options:
`)
		fs.PrintDefaults()
		fmt.Fprintf(w, `
Examples:
  qphpscanner example.com
  qphpscanner --mode deep --ports 80,443,8080 --report-out report.pdf example.com
  qphpscanner --tls on --format json --out scan.json 10.0.0.0/28
  qphpscanner --verbose '*.example.com'
  qphpscanner --web --listen 127.0.0.1:8088
`)
	}
	return fs
}

func bindFlags(fs *flag.FlagSet) *flags {
	f := &flags{}
	fs.StringVar(&f.configPath, "config", "", "path to a YAML configuration file")
	fs.StringVar(&f.ports, "ports", "", "ports to check: 80 | 80,443 | 8000-8100 | mix (default: common web ports)")
	fs.StringVar(&f.mode, "mode", "detect", "scan depth: detect (is it PHP?) or deep (version, extensions, vulns)")
	fs.StringVar(&f.tls, "tls", "auto", "TLS handling: auto | on | off")
	fs.DurationVar(&f.timeout, "timeout", 10*time.Second, "per-connection timeout (e.g. 5s, 500ms)")
	fs.IntVar(&f.concurrency, "concurrency", 50, "maximum concurrent service probes")
	fs.BoolVar(&f.follow, "follow", true, "follow HTTP redirects while collecting evidence")
	fs.BoolVar(&f.insecure, "insecure", false, "do not verify TLS certificates")
	fs.BoolVar(&f.securityTxt, "security-txt", true, "look up and parse /.well-known/security.txt")
	fs.BoolVar(&f.includeClosed, "include-closed", false, "include closed/filtered ports in the output")
	fs.StringVar(&f.format, "format", "text", "scan output format: text | json | xml")
	fs.StringVar(&f.out, "out", "", "write scan output to this file instead of stdout")
	fs.StringVar(&f.report, "report", "", "also produce a report: text | rtf | pdf")
	fs.StringVar(&f.reportOut, "report-out", "", "write the report to this file (required for rtf/pdf)")
	fs.StringVar(&f.userAgent, "user-agent", "", "override the HTTP User-Agent header")
	fs.IntVar(&f.maxHosts, "max-hosts", 0, "maximum hosts a single target spec may expand to")
	fs.BoolVar(&f.web, "web", false, "run the web GUI instead of a one-shot scan")
	fs.StringVar(&f.listen, "listen", "127.0.0.1:8088", "web GUI listen address (with --web)")
	fs.BoolVar(&f.showVersion, "version", false, "print version and exit")
	fs.StringVar(&f.completion, "completion", "", "print a shell completion script (bash, zsh or fish) and exit")
	fs.BoolVar(&f.verbose, "verbose", false, "print per-host/service progress detail (open/closed ports, PHP verdicts)")
	fs.BoolVar(&f.verbose, "v", false, "shorthand for --verbose")
	fs.BoolVar(&f.quiet, "quiet", false, "suppress progress output")
	fs.BoolVar(&f.quiet, "q", false, "shorthand for --quiet")
	fs.BoolVar(&f.noDNSEnum, "no-dns-enum", false, "disable '*.domain' subdomain enumeration")
	fs.BoolVar(&f.verifySubdomains, "verify-subdomains", false, "keep only enumerated subdomains that resolve in DNS")

	fs.StringVar(&f.targetsFile, "targets-file", "", "read targets from a file, one per line ('-' for stdin)")
	fs.StringVar(&f.targetsFile, "iL", "", "shorthand for --targets-file")

	// Politeness.
	fs.Float64Var(&f.rate, "rate", 0, "max outbound HTTP requests per second (0 = unlimited)")
	fs.IntVar(&f.perHost, "per-host-concurrency", 0, "max concurrent probes per host (0 = unlimited)")
	fs.IntVar(&f.hostConc, "host-concurrency", 0, "max distinct hosts scanned at once (0 = no host cap)")
	fs.DurationVar(&f.jitter, "jitter", 0, "random delay up to this before each service probe")
	fs.IntVar(&f.retries, "retries", 0, "extra attempts on a transient network error")
	fs.IntVar(&f.requestBudget, "request-budget", 0, "cap deep-mode probes per service; optional app-discovery probes stop when spent (0 = no cap)")

	// Enrichment.
	fs.BoolVar(&f.resolveDNS, "resolve-dns", false, "add forward and reverse DNS for each host")
	fs.BoolVar(&f.banners, "banners", false, "grab a service banner from open non-HTTP ports")

	// HTTP request shaping.
	fs.Var(&f.headers, "header", "extra request header 'Name: value' (repeatable)")
	fs.StringVar(&f.cookie, "cookie", "", "Cookie header value for authenticated scans")
	fs.StringVar(&f.bearer, "bearer", "", "Bearer token (sets Authorization: Bearer ...)")
	fs.StringVar(&f.basicAuth, "basic", "", "HTTP Basic auth as user:pass")
	fs.StringVar(&f.vhost, "vhost", "", "override the Host header (virtual-host scanning)")
	fs.StringVar(&f.proxy, "proxy", "", "route requests via an http(s):// or socks5:// proxy")
	fs.Var(&f.resolve, "resolve", "pin HOST:PORT:ADDR so HOST:PORT dials ADDR, curl-style (repeatable; e.g. origin behind a CDN)")
	fs.StringVar(&f.sni, "sni", "", "override the TLS SNI server name (independent of the Host header)")

	// Vulnerability data / resume / reporting extras.
	fs.Var(&f.vulnFeeds, "vuln-feed", "external vuln feed: native, OSV or CSAF JSON, file or URL (repeatable)")
	fs.Var(&f.faviconCatalogs, "favicon-catalog", "favicon-hash → product catalogue file or URL (repeatable)")
	fs.Var(&f.signaturePacks, "signature-pack", "detection-signature pack (header/cookie/body matchers) file or URL (repeatable)")
	fs.Var(&f.composerFiles, "composer-file", "supply a composer.json/composer.lock/installed.json to inventory (repeatable)")
	fs.Var(&f.allow, "allow", "allow-list pattern (host, CIDR or *.domain); keep only matching targets (repeatable)")
	fs.Var(&f.block, "block", "block-list pattern (host, CIDR or *.domain); drop matching targets (repeatable)")
	fs.StringVar(&f.failOn, "fail-on", "", "exit non-zero if a finding meets this severity: low|medium|high|critical|eol")
	fs.StringVar(&f.outAll, "oA", "", "write json/xml/csv/sarif/txt outputs and an HTML report to <base>.*")
	fs.StringVar(&f.diffPath, "diff", "", "compare against a prior JSON scan result and print the differences")
	fs.StringVar(&f.diffFormat, "diff-format", "text", "diff output format: text or json")
	fs.StringVar(&f.resume, "resume", "", "checkpoint file: record completed services and resume from it")
	fs.StringVar(&f.webAuth, "web-auth", "", "protect the web GUI with HTTP Basic auth (user:pass)")

	// Audit trail.
	fs.StringVar(&f.pcapPath, "pcap", "", "write a libpcap capture of every HTTP exchange to this file (audit trail)")
	fs.StringVar(&f.logPath, "log", "", "write a human-readable session log explaining each detection decision")

	fs.SetOutput(os.Stderr)
	return f
}
