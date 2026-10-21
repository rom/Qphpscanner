package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rom/qphpscanner/internal/dnsenum"
	"github.com/rom/qphpscanner/internal/php"
	"github.com/rom/qphpscanner/internal/portspec"
	"github.com/rom/qphpscanner/internal/probe"
	"github.com/rom/qphpscanner/internal/securitytxt"
	"github.com/rom/qphpscanner/internal/target"
	"github.com/rom/qphpscanner/internal/version"
	"github.com/rom/qphpscanner/internal/webserver"
)

// Mode selects how deep the analysis goes.
const (
	ModeDetect = "detect" // only decide whether the service is PHP
	ModeDeep   = "deep"   // also fingerprint version/extensions/modules and vulns
)

// TLS modes.
const (
	TLSAuto = "auto"
	TLSOn   = "on"
	TLSOff  = "off"
)

// Options configures a scan.
type Options struct {
	Mode            string
	TLSMode         string
	Ports           []int
	Timeout         time.Duration
	Concurrency     int
	Follow          bool
	Insecure        bool
	MaxBodyBytes    int64
	UserAgent       string
	SecurityTxt     bool
	IncludeClosed   bool
	MaxHostsPerSpec int

	// OnProgress, when set, receives incremental progress events.
	OnProgress ProgressFunc
	// OnService, when set, receives every completed service result as it
	// finishes — including closed/filtered and errored ones, before the
	// closed-port output filter — so streaming consumers can render partial
	// results that survive a cancellation or timeout.
	OnService func(ServiceResult)
	// OnHostResolved, when set and ResolveDNS is enabled, fires once per host
	// with its forward (A/AAAA) and reverse (PTR) names as soon as they are
	// resolved — before that host's services are probed — so a streaming
	// consumer can show the resolved hostname of an IP target live rather than
	// only after the whole scan finishes.
	OnHostResolved func(host string, addrs, ptr []string)
	// DisableDNSEnum turns off "*.domain" subdomain enumeration.
	DisableDNSEnum bool
	// Enumerator overrides the default Certificate Transparency enumerator
	// (primarily for testing).
	Enumerator SubdomainEnumerator
	// VerifySubdomains keeps only discovered subdomains that resolve in DNS.
	VerifySubdomains bool

	// --- Politeness ---
	// RateLimit caps outbound HTTP requests per second across the whole scan
	// (0 = unlimited).
	RateLimit float64
	// PerHostConcurrency caps concurrent service probes per host (0 = unlimited).
	PerHostConcurrency int
	// HostConcurrency caps how many distinct hosts are scanned at once
	// (0 = no host-level cap). Service probes are still bounded globally by
	// Concurrency and per host by PerHostConcurrency.
	HostConcurrency int
	// Jitter adds a random delay of up to this duration before each service.
	Jitter time.Duration
	// Retries is the number of extra attempts on a transient network error.
	Retries int

	// --- Enrichment ---
	// ResolveDNS adds forward and reverse DNS for each host.
	ResolveDNS bool
	// GrabBanners reads a short banner from open ports that do not speak HTTP.
	GrabBanners bool

	// --- HTTP request shaping ---
	Headers     map[string]string
	Cookie      string
	BearerToken string
	BasicUser   string
	BasicPass   string
	HostHeader  string
	ProxyURL    string
	// Resolve pins host:port pairs to fixed dial addresses (curl --resolve
	// style): connect to a specific origin IP while keeping the URL host, Host
	// header and TLS SNI as the real hostname.
	Resolve []probe.ResolveRule
	// SNIServerName overrides the TLS SNI for HTTPS probes. Intended for
	// single-origin scans (e.g. comparing an origin behind a CDN).
	SNIServerName string

	// --- Data ---
	// Catalog supplies vulnerability/EOL data (nil = built-in default).
	Catalog *php.Catalog
	// ComposerFiles are operator-supplied Composer file contents merged into the
	// dependency inventory for projects whose files are not web-exposed.
	ComposerFiles [][]byte

	// --- Resume ---
	// CheckpointPath records completed services so a scan can resume.
	CheckpointPath string

	// --- Target filtering ---
	// Allowlist, when non-empty, keeps only endpoints whose host matches one
	// of its patterns. Blocklist drops endpoints whose host matches. Patterns
	// are an exact host/IP, a CIDR block, or a "*.domain"/".domain" suffix.
	Allowlist []string
	Blocklist []string

	// --- Audit trail ---
	// PCAPPath, when set, writes a libpcap capture reconstructing every HTTP
	// exchange as a TCP conversation (opens in Wireshark/tcpdump).
	PCAPPath string
	// LogPath, when set, writes a human-readable session log explaining how
	// each piece of evidence and each verdict was decided.
	LogPath string

	// Resolver overrides DNS resolution (primarily for testing).
	Resolver DNSResolver
}

// DNSResolver is the subset of *net.Resolver the scanner uses.
type DNSResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// withDefaults fills unset options with sensible values.
func (o Options) withDefaults() Options {
	if o.Mode == "" {
		o.Mode = ModeDetect
	}
	if o.TLSMode == "" {
		o.TLSMode = TLSAuto
	}
	if len(o.Ports) == 0 {
		o.Ports = portspec.DefaultWebPorts
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 50
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = probe.DefaultMaxBodyBytes
	}
	if o.UserAgent == "" {
		o.UserAgent = probe.DefaultUserAgent
	}
	return o
}

var reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

type job struct {
	ep   target.Endpoint
	port int
}

type schemeChoice struct {
	scheme string
	tls    bool
}

// Scan runs the full pipeline over the given target specs.
func Scan(ctx context.Context, specs []string, opts Options) (*ScanResult, error) {
	opts = opts.withDefaults()
	start := time.Now()

	endpoints, err := expandTargets(ctx, specs, opts)
	if err != nil {
		return nil, err
	}

	// Build jobs and record host order + inputs.
	var jobs []job
	hostOrder := []string{}
	hostSeen := map[string]bool{}
	hostInputs := map[string]map[string]bool{}
	for _, ep := range endpoints {
		if !hostSeen[ep.Host] {
			hostSeen[ep.Host] = true
			hostOrder = append(hostOrder, ep.Host)
			hostInputs[ep.Host] = map[string]bool{}
		}
		hostInputs[ep.Host][ep.Input] = true

		ports := opts.Ports
		if len(ep.Ports) > 0 {
			ports = ep.Ports
		}
		for _, p := range ports {
			jobs = append(jobs, job{ep: ep, port: p})
		}
	}

	// Optional audit trail (PCAP capture and/or session log).
	audit, err := newAuditSink(opts, specs, start)
	if err != nil {
		return nil, err
	}
	defer audit.close()
	var recorder probe.Recorder
	if audit != nil {
		recorder = audit
	}

	fetcher := probe.NewFetcher(probe.FetcherConfig{
		Timeout:         opts.Timeout,
		Insecure:        opts.Insecure,
		FollowRedirects: opts.Follow,
		UserAgent:       opts.UserAgent,
		MaxBodyBytes:    opts.MaxBodyBytes,
		Headers:         opts.Headers,
		Cookie:          opts.Cookie,
		BearerToken:     opts.BearerToken,
		BasicUser:       opts.BasicUser,
		BasicPass:       opts.BasicPass,
		HostHeader:      opts.HostHeader,
		ProxyURL:        opts.ProxyURL,
		Resolve:         opts.Resolve,
		SNIServerName:   opts.SNIServerName,
		Retries:         opts.Retries,
		Limiter:         probe.NewRateLimiter(opts.RateLimit, rateBurst(opts.RateLimit)),
		Recorder:        recorder,
	})

	// Resume support.
	cp, err := loadCheckpoint(opts.CheckpointPath)
	if err != nil {
		return nil, err
	}
	defer cp.close()

	// Per-host service-concurrency gate.
	hostGate := newHostGate(opts.PerHostConcurrency)

	// Group job indices by host so hosts can be scheduled independently.
	jobsByHost := map[string][]int{}
	for i, j := range jobs {
		jobsByHost[j.ep.Host] = append(jobsByHost[j.ep.Host], i)
	}

	// Two levels of concurrency: a host-level cap on how many distinct hosts
	// are worked at once, and a global cap on concurrent service probes across
	// all of them. HostConcurrency 0 means "no host-level cap".
	results := make([]ServiceResult, len(jobs))
	total := len(jobs)
	sem := make(chan struct{}, opts.Concurrency)
	hostConc := opts.HostConcurrency
	if hostConc <= 0 || hostConc > len(hostOrder) {
		hostConc = len(hostOrder)
	}
	if hostConc < 1 {
		hostConc = 1
	}
	hostSem := make(chan struct{}, hostConc)

	var wg sync.WaitGroup
	var progMu sync.Mutex
	doneCount := 0

	// Per-host DNS cache: resolved once at the start of each host's goroutine
	// (when enabled) and reused for the final TargetResult so DNS is not looked
	// up twice. Protected by its own mutex because host goroutines run
	// concurrently.
	type dnsRecord struct{ addrs, ptr []string }
	var dnsMu sync.Mutex
	dnsCache := map[string]dnsRecord{}

	runJob := func(idx int) {
		j := jobs[idx]
		k := jobKey(j.ep.Host, j.port)
		var res ServiceResult
		if saved, ok := cp.lookup(k); ok {
			res = saved
			audit.logResumed(res)
		} else {
			hostGate.acquire(j.ep.Host)
			applyJitter(ctx, opts.Jitter)
			res = scanService(ctx, fetcher, j, opts)
			hostGate.release(j.ep.Host)
			cp.record(res)
			audit.logService(res)
		}
		results[idx] = res
		if opts.OnService != nil || opts.OnProgress != nil {
			progMu.Lock()
			if opts.OnService != nil {
				opts.OnService(res)
			}
			if opts.OnProgress != nil {
				doneCount++
				opts.OnProgress(serviceEvent(res, doneCount, total))
			}
			progMu.Unlock()
		}
	}

	for _, host := range hostOrder {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil, ctx.Err()
		default:
		}
		hostSem <- struct{}{}
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			defer func() { <-hostSem }()

			// Resolve DNS for the host before probing its services, so a
			// streaming consumer can show the resolved name (notably a PTR for
			// an IP target) alongside the first result rather than only after
			// the scan completes.
			if opts.ResolveDNS {
				addrs, ptr := resolveHost(ctx, opts.resolver(), host)
				dnsMu.Lock()
				dnsCache[host] = dnsRecord{addrs: addrs, ptr: ptr}
				dnsMu.Unlock()
				if opts.OnHostResolved != nil {
					progMu.Lock()
					opts.OnHostResolved(host, addrs, ptr)
					progMu.Unlock()
				}
			}

			var hwg sync.WaitGroup
			for _, idx := range jobsByHost[host] {
				select {
				case <-ctx.Done():
					hwg.Wait()
					return
				default:
				}
				sem <- struct{}{}
				hwg.Add(1)
				go func(idx int) {
					defer hwg.Done()
					defer func() { <-sem }()
					runJob(idx)
				}(idx)
			}
			hwg.Wait()
		}(host)
	}
	wg.Wait()

	// Group by host preserving order; drop closed ports unless requested.
	byHost := map[string][]ServiceResult{}
	for _, r := range results {
		if !r.PortOpen && !opts.IncludeClosed {
			continue
		}
		byHost[r.Host] = append(byHost[r.Host], r)
	}

	cat := opts.Catalog
	if cat == nil {
		cat = php.DefaultCatalog()
	}
	catPHP, catCMS := cat.Counts()

	out := &ScanResult{
		Meta: Meta{
			Tool:       version.Name,
			Version:    version.Version,
			Mode:       opts.Mode,
			StartedAt:  start,
			FinishedAt: time.Now(),
			DurationMS: time.Since(start).Milliseconds(),
			Ports:      opts.Ports,
			TLSMode:    opts.TLSMode,
			TimeoutMS:  opts.Timeout.Milliseconds(),
			Follow:     opts.Follow,
			Insecure:   opts.Insecure,
			Auth:       opts.Cookie != "" || opts.BearerToken != "" || opts.BasicUser != "" || opts.BasicPass != "",
			Pinned:     len(opts.Resolve) > 0 || opts.SNIServerName != "",
			AllowBlock: len(opts.Allowlist) > 0 || len(opts.Blocklist) > 0,
			CatalogPHP: catPHP,
			CatalogCMS: catCMS,
		},
	}
	for _, h := range hostOrder {
		svcs := byHost[h]
		if len(svcs) == 0 {
			continue
		}
		inputs := make([]string, 0, len(hostInputs[h]))
		for in := range hostInputs[h] {
			inputs = append(inputs, in)
		}
		tr := TargetResult{Host: h, Inputs: inputs, Services: svcs}
		if opts.ResolveDNS {
			dnsMu.Lock()
			rec, ok := dnsCache[h]
			dnsMu.Unlock()
			if !ok {
				// Host goroutine was skipped (e.g. context cancelled before it
				// ran); resolve now as a fallback.
				rec.addrs, rec.ptr = resolveHost(ctx, opts.resolver(), h)
			}
			tr.Addresses, tr.PTR = rec.addrs, rec.ptr
		}
		out.Targets = append(out.Targets, tr)
	}

	out.Summary = summarise(results, hostOrder, opts)
	return out, nil
}

// expandTargets turns raw specs into endpoints, resolving DNS wildcards
// ("*.example.com") via subdomain enumeration. Enumeration failures are
// reported through progress and skipped rather than aborting the whole scan.
func expandTargets(ctx context.Context, specs []string, opts Options) ([]target.Endpoint, error) {
	var eps []target.Endpoint
	for _, spec := range specs {
		if domain, ok := target.IsDNSWildcard(spec); ok {
			if opts.DisableDNSEnum {
				emitEnum(opts, "skipping DNS wildcard "+spec+" (enumeration disabled)")
				continue
			}
			enum := opts.Enumerator
			if enum == nil {
				d := dnsenum.New()
				d.Verify = opts.VerifySubdomains
				if opts.MaxHostsPerSpec > 0 {
					d.MaxHosts = opts.MaxHostsPerSpec
				}
				enum = d
			}
			emitEnum(opts, "enumerating subdomains for "+domain+" via certificate transparency…")
			hosts, err := enum.Enumerate(ctx, domain)
			if err != nil {
				emitEnum(opts, "subdomain enumeration for "+domain+" failed: "+err.Error())
				continue
			}
			emitEnum(opts, fmt.Sprintf("found %d host(s) for %s", len(hosts), domain))
			for _, h := range hosts {
				eps = append(eps, target.Endpoint{Input: spec, Host: h, Path: "/"})
			}
			continue
		}
		e, err := target.Expand(spec, target.ExpandOptions{MaxHosts: opts.MaxHostsPerSpec})
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", spec, err)
		}
		eps = append(eps, e...)
	}
	return filterEndpoints(eps, opts), nil
}

func emitEnum(opts Options, msg string) {
	if opts.OnProgress != nil {
		opts.OnProgress(ProgressEvent{Phase: "enumerate", Message: msg})
	}
}

func serviceEvent(r ServiceResult, done, total int) ProgressEvent {
	ev := ProgressEvent{
		Phase: "service", Done: done, Total: total,
		Host: r.Host, Port: r.Port, Open: r.PortOpen, Err: r.Error,
	}
	if r.HTTP != nil {
		ev.HTTP = true
	}
	if r.PHP != nil {
		ev.PHPVerdict = string(r.PHP.Verdict)
		ev.Version = r.PHP.Version
	}
	return ev
}

func summarise(results []ServiceResult, hosts []string, opts Options) Summary {
	s := Summary{HostsScanned: len(hosts), ServicesProbed: len(results)}
	for _, r := range results {
		if r.PortOpen {
			s.OpenPorts++
		}
		if r.HTTP != nil {
			s.HTTPServices++
		}
		if r.PHP != nil {
			switch r.PHP.Verdict {
			case php.VerdictConfirmed:
				s.PHPConfirmed++
			case php.VerdictLikely:
				s.PHPLikely++
			case php.VerdictPossible:
				s.PHPPossible++
			}
			s.Vulnerabilities += len(r.PHP.Vulnerabilities)
		}
		if r.SecurityTxt != nil && r.SecurityTxt.Present {
			s.SecurityTxt++
		}
		if r.Proxy != nil && r.Proxy.Present {
			s.BehindProxy++
			if len(r.Proxy.WAF) > 0 {
				s.WAFProtected++
			}
		}
	}
	return s
}

func scanService(ctx context.Context, fetcher *probe.Fetcher, j job, opts Options) ServiceResult {
	start := time.Now()
	res := ServiceResult{Host: j.ep.Host, Port: j.port, CheckedAt: start}

	// TCP connect check first.
	status := probe.CheckPort(ctx, j.ep.Host, j.port, opts.Timeout)
	res.PortOpen = status.Open
	if !status.Open {
		if status.Err != nil {
			res.Error = status.Err.Error()
		}
		res.DurationMS = time.Since(start).Milliseconds()
		return res
	}

	// Try HTTP(S) over the candidate scheme(s).
	schemes := decideSchemes(j.ep, j.port, opts.TLSMode)
	var root *probe.Response
	var chosen schemeChoice
	for _, sc := range schemes {
		url := origin(sc.scheme, j.ep.Host, j.port) + ensureLeadingSlash(j.ep.Path)
		resp := fetcher.Get(ctx, url)
		if resp.Err == "" && resp.Status > 0 {
			root, chosen = resp, sc
			break
		}
		// Keep the last attempt for diagnostics.
		root, chosen = resp, sc
	}

	res.Scheme = chosen.scheme
	res.TLS = chosen.tls
	res.URL = origin(chosen.scheme, j.ep.Host, j.port) + ensureLeadingSlash(j.ep.Path)

	if root == nil || (root.Err != "" && root.Status == 0) {
		if root != nil {
			res.Error = root.Err
		}
		// Open port that did not speak HTTP: optionally grab a service banner.
		if opts.GrabBanners {
			res.Banner = probe.GrabBanner(ctx, j.ep.Host, j.port, opts.Timeout)
		}
		res.DurationMS = time.Since(start).Milliseconds()
		return res
	}

	res.HTTP = buildHTTPInfo(res.URL, root)

	base := origin(chosen.scheme, j.ep.Host, j.port)

	// security.txt (independent of mode unless disabled).
	if opts.SecurityTxt {
		res.SecurityTxt = fetchSecurityTxt(ctx, fetcher, base)
	}

	// Active identification probes (deep mode): an OPTIONS request, a
	// guaranteed-404 to harvest the error-page server signature/WAF block page,
	// and a few status endpoints. These feed web-server/proxy fingerprinting
	// and PHP version leakage.
	var fpExtra []*probe.Response
	var notFound *probe.Response
	if opts.Mode == ModeDeep {
		fpExtra = append(fpExtra, fetcher.Request(ctx, "OPTIONS", base+"/"))
		notFound = fetcher.Get(ctx, base+"/qphpscanner_probe_404")
		fpExtra = append(fpExtra, notFound)
		for _, p := range serverStatusPaths() {
			fpExtra = append(fpExtra, fetcher.Get(ctx, base+p))
		}
	}

	// Web server / reverse proxy / CDN / WAF identification.
	wsRes := webserver.Analyze(root, fpExtra)
	res.Server = &wsRes.Server
	res.Proxy = &wsRes.Proxy

	// Build PHP analysis input.
	in := php.Input{
		TargetURL:     res.URL,
		Deep:          opts.Mode == ModeDeep,
		Root:          root,
		Catalog:       opts.Catalog,
		ComposerFiles: opts.ComposerFiles,
	}
	if in.Deep {
		in.Extra = map[string]*probe.Response{}
		for _, p := range php.DeepProbePaths() {
			if p == "/" {
				continue
			}
			u := base + ensureLeadingSlash(p)
			in.Extra[u] = fetcher.Get(ctx, u)
		}
		// The 404 page can leak a PHP version via an Apache signature, and also
		// serves as the soft-404 baseline for catch-all detection.
		if notFound != nil {
			in.Extra[base+"/qphpscanner_probe_404"] = notFound
			in.Control = notFound
		}
		in.EasterCredits = fetcher.Get(ctx, base+"/"+php.EasterEggCredits)
		in.EasterLogo = fetcher.Get(ctx, base+"/"+php.EasterEggLogo)
		in.Favicon = fetcher.Get(ctx, base+php.FaviconPath)
		in.PathInfo = fetcher.Get(ctx, base+php.PathInfoProbe)
	}

	res.PHP = php.Analyze(in)
	res.DurationMS = time.Since(start).Milliseconds()
	return res
}

// serverStatusPaths are read-only endpoints that often leak the web server,
// its modules or status (probed in deep mode).
func serverStatusPaths() []string {
	return []string{
		"/server-status",
		"/server-info",
		"/nginx_status",
		"/status",
		"/web.config",
		"/crossdomain.xml",
	}
}

func fetchSecurityTxt(ctx context.Context, fetcher *probe.Fetcher, base string) *securitytxt.SecurityTxt {
	for _, p := range securitytxt.WellKnownPaths {
		u := base + p
		resp := fetcher.Get(ctx, u)
		if resp.Err != "" || resp.Status != 200 {
			continue
		}
		if st, ok := securitytxt.Parse(u, resp.BodyString()); ok {
			return st
		}
	}
	return nil
}

func buildHTTPInfo(url string, resp *probe.Response) *HTTPInfo {
	info := &HTTPInfo{
		URL:         url,
		FinalURL:    resp.FinalURL,
		Status:      resp.Status,
		Proto:       resp.Proto,
		Server:      resp.HeaderGet("Server"),
		PoweredBy:   resp.HeaderGet("X-Powered-By"),
		ContentType: resp.HeaderGet("Content-Type"),
		Redirects:   resp.Hops,
		TLS:         resp.TLS,
	}
	if info.FinalURL == url {
		info.FinalURL = ""
	}
	info.HTTP2 = strings.HasPrefix(resp.Proto, "HTTP/2")
	if resp.TLS != nil {
		info.ALPN = resp.TLS.ALPN
	}
	// Cleartext HTTP/2 (h2c) advertised via an Upgrade header.
	for _, up := range resp.HeaderValues("Upgrade") {
		if strings.Contains(strings.ToLower(up), "h2c") {
			info.H2C = true
		}
	}
	if m := reTitle.FindStringSubmatch(resp.BodyString()); m != nil {
		info.Title = strings.TrimSpace(collapseSpace(m[1]))
		if len(info.Title) > 160 {
			info.Title = info.Title[:160] + "…"
		}
	}
	info.Headers = selectHeaders(resp)
	return info
}

var interestingHeaders = []string{
	"Server", "X-Powered-By", "X-Generator", "X-Drupal-Cache",
	"X-Drupal-Dynamic-Cache", "X-Redirect-By", "X-Pingback", "X-Debug-Token",
	"Via", "X-AspNet-Version", "X-Runtime", "X-Varnish", "X-Cache",
}

func selectHeaders(resp *probe.Response) map[string]string {
	out := map[string]string{}
	for _, h := range interestingHeaders {
		if v := resp.HeaderGet(h); v != "" {
			out[h] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func decideSchemes(ep target.Endpoint, port int, tlsMode string) []schemeChoice {
	switch ep.Scheme {
	case "https":
		return []schemeChoice{{"https", true}}
	case "http":
		return []schemeChoice{{"http", false}}
	}
	switch tlsMode {
	case TLSOn:
		return []schemeChoice{{"https", true}}
	case TLSOff:
		return []schemeChoice{{"http", false}}
	default: // auto: prefer the port's usual scheme, then fall back.
		if isTLSPort(port) {
			return []schemeChoice{{"https", true}, {"http", false}}
		}
		return []schemeChoice{{"http", false}, {"https", true}}
	}
}

func isTLSPort(port int) bool {
	switch port {
	case 443, 8443, 9443, 4443, 10443:
		return true
	default:
		return false
	}
}

func origin(scheme, host string, port int) string {
	hp := host
	if strings.Contains(host, ":") {
		hp = "[" + host + "]"
	}
	return scheme + "://" + hp + ":" + strconv.Itoa(port)
}

func ensureLeadingSlash(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

func collapseSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
