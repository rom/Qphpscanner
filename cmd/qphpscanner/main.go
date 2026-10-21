// Command qphpscanner scans network ports and HTTP(S) services to determine
// whether they are backed by PHP, collects supporting evidence and — in deep
// mode — fingerprints the version, variant, extensions/modules and correlates
// known version-based vulnerabilities. It also reports any published
// security.txt. It runs as a CLI or as a small web GUI.
//
// All probing is passive fingerprinting: the tool reads banners, headers,
// cookies and response bodies. It does not attempt to exploit anything. Only
// scan systems you are authorised to test.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rom/qphpscanner/internal/config"
	"github.com/rom/qphpscanner/internal/php"
	"github.com/rom/qphpscanner/internal/portspec"
	"github.com/rom/qphpscanner/internal/probe"
	"github.com/rom/qphpscanner/internal/report"
	"github.com/rom/qphpscanner/internal/scanner"
	"github.com/rom/qphpscanner/internal/version"
	"github.com/rom/qphpscanner/internal/web"
)

// exitError carries a specific process exit code (e.g. for --fail-on) without
// an error message to print.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func main() {
	err := run(os.Args[1:])
	if err == nil {
		return
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.msg != "" {
			fmt.Fprintln(os.Stderr, "qphpscanner: "+ee.msg)
		}
		os.Exit(ee.code)
	}
	fmt.Fprintln(os.Stderr, "qphpscanner: "+err.Error())
	os.Exit(1)
}

func run(args []string) error {
	fs := newFlagSet()
	f := bindFlags(fs)
	positionals, err := parseArgs(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if f.showVersion {
		fmt.Println(version.String())
		return nil
	}
	if f.completion != "" {
		script, err := generateCompletion(f.completion, fs)
		if err != nil {
			return err
		}
		fmt.Print(script)
		return nil
	}

	set := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })

	// Load config, if any.
	var cfg *config.Config
	if f.configPath != "" {
		c, err := config.Load(f.configPath)
		if err != nil {
			return err
		}
		cfg = c
	}

	opts, outFmt, outFile, repFmt, repFile, targets, webEnabled, listen, err := resolve(f, set, cfg, positionals)
	if err != nil {
		return err
	}

	if err := validateFailOn(f.failOn); err != nil {
		return err
	}

	// Web mode.
	if webEnabled {
		srv := web.NewServer(listen)
		if f.webAuth != "" {
			u, p := splitColon(f.webAuth)
			srv.SetAuth(u, p)
		}
		fmt.Fprintf(os.Stderr, "qphpscanner web UI listening on http://%s/\n", displayAddr(listen))
		return srv.ListenAndServe()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Extra targets from a file or stdin.
	fileTargets, err := readTargetsFile(f.targetsFile)
	if err != nil {
		return err
	}
	targets = append(targets, fileTargets...)

	if len(targets) == 0 {
		fs.Usage()
		return fmt.Errorf("no targets given (pass targets as arguments, --targets-file, --config, or use --web)")
	}

	// Build the vulnerability catalogue, merging any external feeds (native,
	// OSV or CSAF — auto-detected).
	if len(f.vulnFeeds) > 0 {
		cat := php.DefaultCatalog()
		for _, src := range f.vulnFeeds {
			feed, err := php.LoadFeed(ctx, src, nil)
			if err != nil {
				return err
			}
			cat.Merge(feed)
		}
		opts.Catalog = cat
	}

	// Load any versioned signature packs onto the built-in default pack; their
	// id/version is recorded in scan provenance.
	if len(f.signaturePacks) > 0 {
		sigs := php.DefaultSignatureSet()
		for _, src := range f.signaturePacks {
			pack, perr := php.LoadSignaturePack(ctx, src, nil)
			if perr != nil {
				return perr
			}
			sigs.Merge(pack)
			fmt.Fprintf(os.Stderr, "loaded signature pack %s v%s (%d signatures) from %s\n",
				pack.ID, pack.Version, pack.Count(), src)
		}
		opts.Signatures = sigs
	}

	// Register any external favicon-hash catalogues before scanning.
	for _, src := range f.faviconCatalogs {
		n, err := php.LoadFaviconCatalog(ctx, src, nil)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "loaded %d favicon catalogue entries from %s\n", n, src)
	}

	// Load any operator-supplied Composer files for the dependency inventory.
	for _, path := range f.composerFiles {
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return fmt.Errorf("read composer file %q: %w", path, rerr)
		}
		opts.ComposerFiles = append(opts.ComposerFiles, data)
	}

	reporter := newProgressReporter(os.Stderr, f.verbose, f.quiet)
	opts.OnProgress = reporter.handle
	opts.DisableDNSEnum = f.noDNSEnum

	result, err := scanner.Scan(ctx, targets, opts)
	reporter.finish()
	if err != nil {
		return err
	}

	if err := emitResults(result, f, outFmt, outFile, repFmt, repFile); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "scanned %d host(s), %d open port(s), %d PHP service(s) in %d ms\n",
		result.Summary.HostsScanned, result.Summary.OpenPorts,
		result.Summary.PHPConfirmed+result.Summary.PHPLikely, result.Meta.DurationMS)

	if f.failOn != "" && report.FailOn(result, f.failOn) {
		return &exitError{code: 2}
	}
	return nil
}

// emitResults writes scan output and reports, honouring --diff and --oA.
func emitResults(result *scanner.ScanResult, f *flags, outFmt, outFile, repFmt, repFile string) error {
	if f.diffPath != "" {
		data, err := os.ReadFile(f.diffPath)
		if err != nil {
			return fmt.Errorf("read diff baseline: %w", err)
		}
		old, err := report.LoadScan(data)
		if err != nil {
			return err
		}
		if err := report.WriteDiff(os.Stdout, report.Diff(old, result), f.diffFormat); err != nil {
			return err
		}
		// With --diff, scan output goes only to an explicit file.
		if outFile != "" {
			if err := emitOutput(result, outFmt, outFile); err != nil {
				return err
			}
		}
		return nil
	}

	if f.outAll != "" {
		return emitAllFormats(result, f.outAll)
	}

	if err := emitOutput(result, outFmt, outFile); err != nil {
		return err
	}
	if repFmt != "" || repFile != "" {
		if err := emitReport(result, repFmt, repFile); err != nil {
			return err
		}
	}
	return nil
}

// emitAllFormats writes every machine output plus an HTML report under <base>.
func emitAllFormats(result *scanner.ScanResult, base string) error {
	outputs := map[string]string{
		base + ".json":  "json",
		base + ".xml":   "xml",
		base + ".csv":   "csv",
		base + ".sarif": "sarif",
		base + ".txt":   "text",
	}
	for path, format := range outputs {
		if err := emitOutput(result, format, path); err != nil {
			return err
		}
	}
	return emitReport(result, "html", base+".html")
}

// resolve merges config file values with explicit CLI flags (flags win).
func resolve(f *flags, set map[string]bool, cfg *config.Config, posArgs []string) (
	opts scanner.Options, outFmt, outFile, repFmt, repFile string,
	targets []string, webEnabled bool, listen string, err error,
) {
	// Start from config defaults.
	if cfg != nil {
		opts.Mode = cfg.Mode
		opts.TLSMode = cfg.TLS
		opts.Concurrency = cfg.Concurrency
		opts.IncludeClosed = boolVal(cfg.IncludeClosed, false)
		opts.Follow = boolVal(cfg.FollowRedirects, true)
		opts.Insecure = boolVal(cfg.Insecure, false)
		opts.SecurityTxt = boolVal(cfg.SecurityTxt, true)
		opts.UserAgent = cfg.UserAgent
		opts.MaxBodyBytes = cfg.MaxBodyBytes
		opts.MaxHostsPerSpec = cfg.MaxHostsPerSpec
		if cfg.Timeout != "" {
			d, perr := time.ParseDuration(cfg.Timeout)
			if perr != nil {
				err = fmt.Errorf("config timeout %q: %w", cfg.Timeout, perr)
				return
			}
			opts.Timeout = d
		}
		outFmt, outFile = cfg.Output.Format, cfg.Output.File
		repFmt, repFile = cfg.Report.Format, cfg.Report.File
		targets = cfg.Targets
		webEnabled = boolVal(cfg.Web.Enabled, false)
		listen = cfg.Web.Listen
	} else {
		opts.Follow = true
		opts.SecurityTxt = true
	}

	// Ports: flag > config > default.
	portStr := ""
	if cfg != nil {
		portStr = cfg.Ports
	}
	if set["ports"] {
		portStr = f.ports
	}
	if strings.TrimSpace(portStr) != "" {
		ports, perr := portspec.Parse(portStr)
		if perr != nil {
			err = perr
			return
		}
		opts.Ports = ports
	}

	// Apply explicitly-set flags.
	if set["mode"] {
		opts.Mode = f.mode
	}
	if set["tls"] {
		opts.TLSMode = f.tls
	}
	if set["timeout"] {
		opts.Timeout = f.timeout
	}
	if set["concurrency"] {
		opts.Concurrency = f.concurrency
	}
	if set["follow"] {
		opts.Follow = f.follow
	}
	if set["insecure"] {
		opts.Insecure = f.insecure
	}
	if set["security-txt"] {
		opts.SecurityTxt = f.securityTxt
	}
	if set["include-closed"] {
		opts.IncludeClosed = f.includeClosed
	}
	if set["user-agent"] {
		opts.UserAgent = f.userAgent
	}
	if set["max-hosts"] {
		opts.MaxHostsPerSpec = f.maxHosts
	}
	if set["format"] {
		outFmt = f.format
	}
	if set["out"] {
		outFile = f.out
	}
	if set["report"] {
		repFmt = f.report
	}
	if set["report-out"] {
		repFile = f.reportOut
	}
	if set["web"] {
		webEnabled = f.web
	}
	if set["listen"] {
		listen = f.listen
	}

	// Remaining options: config provides the base, an explicitly-set flag wins.
	if cfg != nil {
		opts.RateLimit = cfg.Rate
		opts.PerHostConcurrency = cfg.PerHostConcurrency
		opts.HostConcurrency = cfg.HostConcurrency
		opts.Retries = cfg.Retries
		opts.RequestBudget = cfg.RequestBudget
		opts.ResolveDNS = boolVal(cfg.ResolveDNS, false)
		opts.GrabBanners = boolVal(cfg.Banners, false)
		opts.VerifySubdomains = boolVal(cfg.VerifySubdomains, false)
		opts.Cookie = cfg.Cookie
		opts.BearerToken = cfg.Bearer
		opts.HostHeader = cfg.Vhost
		opts.ProxyURL = cfg.Proxy
		opts.SNIServerName = cfg.SNI
		if len(cfg.Resolve) > 0 {
			rules, rerr := parseResolveRules(cfg.Resolve)
			if rerr != nil {
				err = rerr
				return
			}
			opts.Resolve = rules
		}
		opts.CheckpointPath = cfg.Resume
		opts.PCAPPath = cfg.PCAP
		opts.LogPath = cfg.Log
		if len(cfg.Headers) > 0 {
			opts.Headers = parseHeaders(stringSlice(cfg.Headers))
		}
		if cfg.Basic != "" {
			opts.BasicUser, opts.BasicPass = splitColon(cfg.Basic)
		}
		if cfg.Jitter != "" {
			d, perr := time.ParseDuration(cfg.Jitter)
			if perr != nil {
				err = fmt.Errorf("config jitter %q: %w", cfg.Jitter, perr)
				return
			}
			opts.Jitter = d
		}
	}
	if set["rate"] {
		opts.RateLimit = f.rate
	}
	if set["per-host-concurrency"] {
		opts.PerHostConcurrency = f.perHost
	}
	if set["host-concurrency"] {
		opts.HostConcurrency = f.hostConc
	}
	if set["jitter"] {
		opts.Jitter = f.jitter
	}
	if set["retries"] {
		opts.Retries = f.retries
	}
	if set["request-budget"] {
		opts.RequestBudget = f.requestBudget
	}
	if set["resolve-dns"] {
		opts.ResolveDNS = f.resolveDNS
	}
	if set["banners"] {
		opts.GrabBanners = f.banners
	}
	if set["verify-subdomains"] {
		opts.VerifySubdomains = f.verifySubdomains
	}
	if set["cookie"] {
		opts.Cookie = f.cookie
	}
	if set["bearer"] {
		opts.BearerToken = f.bearer
	}
	if set["vhost"] {
		opts.HostHeader = f.vhost
	}
	if set["proxy"] {
		opts.ProxyURL = f.proxy
	}
	if set["sni"] {
		opts.SNIServerName = f.sni
	}
	if len(f.resolve) > 0 {
		rules, rerr := parseResolveRules(f.resolve)
		if rerr != nil {
			err = rerr
			return
		}
		opts.Resolve = append(opts.Resolve, rules...)
	}
	if set["resume"] {
		opts.CheckpointPath = f.resume
	}
	if set["pcap"] {
		opts.PCAPPath = f.pcapPath
	}
	if set["log"] {
		opts.LogPath = f.logPath
	}
	if len(f.headers) > 0 {
		opts.Headers = parseHeaders(f.headers)
	}
	if set["basic"] && f.basicAuth != "" {
		opts.BasicUser, opts.BasicPass = splitColon(f.basicAuth)
	}

	// Allow/block lists combine config entries with any from the CLI.
	opts.Allowlist = append([]string(nil), f.allow...)
	opts.Blocklist = append([]string(nil), f.block...)
	if cfg != nil {
		opts.Allowlist = append(append([]string(nil), cfg.Allow...), opts.Allowlist...)
		opts.Blocklist = append(append([]string(nil), cfg.Block...), opts.Blocklist...)
	}

	// Options read later in run() from f: fold config in when the flag is unset.
	if cfg != nil {
		if !set["fail-on"] && cfg.FailOn != "" {
			f.failOn = cfg.FailOn
		}
		if !set["no-dns-enum"] && cfg.NoDNSEnum != nil {
			f.noDNSEnum = *cfg.NoDNSEnum
		}
		if !set["web-auth"] && cfg.Web.Auth != "" {
			f.webAuth = cfg.Web.Auth
		}
		if !set["targets-file"] && !set["iL"] && cfg.TargetsFile != "" {
			f.targetsFile = cfg.TargetsFile
		}
		// Feeds and catalogues from config run before any from the CLI.
		f.vulnFeeds = append(stringSlice(cfg.VulnFeeds), f.vulnFeeds...)
		f.faviconCatalogs = append(stringSlice(cfg.FaviconCatalogs), f.faviconCatalogs...)
		f.signaturePacks = append(stringSlice(cfg.SignaturePacks), f.signaturePacks...)
		f.composerFiles = append(stringSlice(cfg.ComposerFiles), f.composerFiles...)
	}

	if outFmt == "" {
		outFmt = "text"
	}
	if listen == "" {
		listen = "127.0.0.1:8088"
	}

	// Validate mode/tls early for a friendly error.
	if err = validateMode(opts.Mode); err != nil {
		return
	}
	if err = validateTLS(opts.TLSMode); err != nil {
		return
	}

	// Positional args override config targets.
	if len(posArgs) > 0 {
		targets = posArgs
	}

	// Infer report format from file extension when only a file is given.
	if repFile != "" && repFmt == "" {
		repFmt = inferReportFormat(repFile)
	}
	// Infer output format from file extension when only a file is given.
	if outFile != "" && !set["format"] && (cfg == nil || cfg.Output.Format == "") {
		if ext := inferOutputFormat(outFile); ext != "" {
			outFmt = ext
		}
	}
	return
}

func emitOutput(res *scanner.ScanResult, format, file string) error {
	if file == "" {
		return report.WriteOutput(os.Stdout, res, format)
	}
	fh, err := os.Create(file)
	if err != nil {
		return err
	}
	defer fh.Close()
	if err := report.WriteOutput(fh, res, format); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s output to %s\n", format, file)
	return nil
}

func emitReport(res *scanner.ScanResult, format, file string) error {
	if format == "" {
		format = "text"
	}
	if file == "" {
		if format == "text" {
			return report.WriteReport(os.Stdout, res, format)
		}
		return fmt.Errorf("report format %q needs an output file (use --report-out)", format)
	}
	fh, err := os.Create(file)
	if err != nil {
		return err
	}
	defer fh.Close()
	if err := report.WriteReport(fh, res, format); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s report to %s\n", format, file)
	return nil
}

func validateMode(m string) error {
	switch m {
	case "", scanner.ModeDetect, scanner.ModeDeep:
		return nil
	default:
		return fmt.Errorf("invalid mode %q (want detect or deep)", m)
	}
}

func validateTLS(t string) error {
	switch t {
	case "", scanner.TLSAuto, scanner.TLSOn, scanner.TLSOff:
		return nil
	default:
		return fmt.Errorf("invalid tls %q (want auto, on or off)", t)
	}
}

func inferReportFormat(file string) string {
	switch strings.ToLower(ext(file)) {
	case "pdf":
		return "pdf"
	case "rtf":
		return "rtf"
	default:
		return "text"
	}
}

func inferOutputFormat(file string) string {
	switch strings.ToLower(ext(file)) {
	case "json":
		return "json"
	case "xml":
		return "xml"
	case "txt", "text":
		return "text"
	default:
		return ""
	}
}

func ext(file string) string {
	if i := strings.LastIndexByte(file, '.'); i >= 0 {
		return file[i+1:]
	}
	return ""
}

// parseArgs parses flags that may appear before, between or after positional
// target arguments. The standard flag package stops at the first non-flag
// argument, so we parse iteratively, collecting positionals between flag runs.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		positionals = append(positionals, rest[0])
		rest = rest[1:]
	}
	return positionals, nil
}

func validateFailOn(v string) error {
	switch strings.ToLower(v) {
	case "", "low", "medium", "high", "critical", "eol":
		return nil
	default:
		return fmt.Errorf("invalid --fail-on %q (want low, medium, high, critical or eol)", v)
	}
}

func splitColon(s string) (string, string) {
	if i := strings.Index(s, ":"); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

func parseResolveRules(rules []string) ([]probe.ResolveRule, error) {
	out := make([]probe.ResolveRule, 0, len(rules))
	for _, s := range rules {
		if strings.TrimSpace(s) == "" {
			continue
		}
		r, err := probe.ParseResolveRule(s)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func parseHeaders(hs stringSlice) map[string]string {
	if len(hs) == 0 {
		return nil
	}
	m := map[string]string{}
	for _, h := range hs {
		i := strings.Index(h, ":")
		if i < 0 {
			continue
		}
		k := strings.TrimSpace(h[:i])
		v := strings.TrimSpace(h[i+1:])
		if k != "" {
			m[k] = v
		}
	}
	return m
}

func readTargetsFile(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		fh, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("read targets file: %w", err)
		}
		defer fh.Close()
		r = fh
	}
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func boolVal(p *bool, def bool) bool {
	if p != nil {
		return *p
	}
	return def
}

func displayAddr(listen string) string {
	if strings.HasPrefix(listen, ":") {
		return "localhost" + listen
	}
	return listen
}
