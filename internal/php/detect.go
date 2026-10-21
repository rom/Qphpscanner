package php

import (
	"sort"
	"strings"

	"github.com/rom/qphpscanner/internal/probe"
)

// Input bundles everything Analyze needs about one HTTP(S) service.
type Input struct {
	// TargetURL is the primary scheme://host:port/path that was requested.
	TargetURL string
	// Deep enables version/extension/module fingerprinting and vuln
	// correlation. When false, Analyze stops at the PHP yes/no verdict.
	Deep bool
	// Root is the response to the primary request. Required.
	Root *probe.Response
	// Extra holds deep-mode probe responses keyed by requested URL.
	Extra map[string]*probe.Response
	// Easter* are the expose_php easter-egg probe responses (deep mode).
	EasterCredits *probe.Response
	EasterLogo    *probe.Response
	// Favicon is the /favicon.ico response (deep mode), used for a Shodan-style
	// mmh3 fingerprint hash.
	Favicon *probe.Response
	// PathInfo is the response to /index.php/<token> (deep mode): a 200 implies
	// PHP PATH_INFO handling (cgi/fpm), another positive PHP signal.
	PathInfo *probe.Response
	// Catalog supplies vulnerability/EOL data. When nil, the built-in default
	// catalogue is used.
	Catalog *Catalog
}

const maxDataLen = 200

// Analyze turns collected responses into a PHP Detection.
func Analyze(in Input) *Detection {
	if in.Root == nil {
		return nil
	}

	d := &Detection{}
	seen := map[string]bool{}
	fwSet := map[string]bool{}
	extSet := map[string]bool{}
	modSet := map[string]bool{}
	var versionRank int // 3 phpinfo, 2 header, 1 easter/body

	addEv := func(ev Evidence) {
		// De-duplicate by signal: the same signal seen on several deep-mode
		// probe URLs should count and display only once.
		if seen[ev.Signal] {
			return
		}
		seen[ev.Signal] = true
		if len(ev.Data) > maxDataLen {
			ev.Data = ev.Data[:maxDataLen] + "…"
		}
		if ev.Confidence == "" {
			ev.Confidence = confidenceTier(ev.Weight)
		}
		if ev.Probe == "" {
			ev.Probe = ev.Source
		}
		if ev.Where == "" || ev.How == "" {
			w, h := provenanceDefaults(ev.Signal)
			if ev.Where == "" {
				ev.Where = w
			}
			if ev.How == "" {
				ev.How = h
			}
		}
		if ev.Snippet == "" && ev.Data != "" {
			ev.Snippet = ev.Data
		}
		d.Evidence = append(d.Evidence, ev)
		d.Confidence += ev.Weight
	}
	addFw := func(f string) {
		if f == "" || fwSet[f] {
			return
		}
		fwSet[f] = true
		d.Frameworks = append(d.Frameworks, f)
	}
	addExt := func(e string) {
		key := strings.ToLower(e)
		if e == "" || extSet[key] {
			return
		}
		extSet[key] = true
		d.Extensions = append(d.Extensions, e)
	}
	addMod := func(m string) {
		if m == "" || modSet[m] {
			return
		}
		modSet[m] = true
		d.Modules = append(d.Modules, m)
	}
	setVersion := func(v, source string, rank int) {
		if v == "" || rank <= versionRank {
			return
		}
		d.Version = v
		d.VersionSource = source
		versionRank = rank
	}
	setVariant := func(v string) {
		if v != "" && d.Variant == "" {
			d.Variant = v
		}
	}

	// --- Primary response ---------------------------------------------------
	analyzeResponse(in.Root, in.TargetURL, addEv, addFw, addExt, addMod, setVersion, setVariant)

	// --- URL extension hint -------------------------------------------------
	if u := strings.ToLower(in.TargetURL); hasPHPExtension(u) {
		addEv(Evidence{
			Signal: "url.php-extension", Source: in.TargetURL, Weight: 40,
			Detail: "Requested path uses a PHP file extension",
			Where:  "request URL", How: "URL suffix match",
			Pattern: ".php/.php5/.phtml/…", Snippet: in.TargetURL, Status: in.Root.Status,
		})
	}

	// --- Deep probes --------------------------------------------------------
	for url, resp := range in.Extra {
		if resp == nil || resp.Err != "" {
			continue
		}
		analyzeResponse(resp, url, addEv, addFw, addExt, addMod, setVersion, setVariant)

		body := resp.BodyString()
		if resp.Status == 200 && isPHPInfo(body) {
			d.PHPInfoExposed = true
			d.PHPInfoURL = url
			addEv(Evidence{
				Signal: "diag.phpinfo", Source: url, Weight: 90,
				Detail: "phpinfo() output is publicly exposed", Status: resp.Status,
			})
			if m := rePHPInfoVersion.FindStringSubmatch(body); m != nil {
				setVersion(m[1], "phpinfo()", 3)
			}
			parsePHPInfoModules(body, addExt, setVariant)
		}
		if resp.Status == 200 && isComposerManifest(url, body) {
			addEv(Evidence{
				Signal: "diag.composer", Source: url, Weight: 45,
				Detail: "Composer manifest/lock is publicly readable (PHP project)", Status: resp.Status,
			})
		}
		if resp.Status == 200 {
			st := resp.Status
			addEvStatus := func(ev Evidence) {
				if ev.Status == 0 {
					ev.Status = st
				}
				addEv(ev)
			}
			detectStatusDashboards(url, body, addEvStatus, addExt, addFw, addMod)
		}
	}

	// --- PATH_INFO behavioural probe ----------------------------------------
	if p := in.PathInfo; p != nil && p.Err == "" && p.Status == 200 {
		addEv(Evidence{
			Signal: "behavior.path-info", Source: p.FinalURL, Weight: 35,
			Detail: "index.php/<path> is served (PHP PATH_INFO handling)", Status: p.Status,
		})
	}

	// --- Easter eggs --------------------------------------------------------
	analyzeEasterEggs(in, addEv, setVersion)

	// --- Favicon fingerprint (deep mode) ------------------------------------
	if in.Favicon != nil && in.Favicon.Err == "" && in.Favicon.Status == 200 && len(in.Favicon.Body) > 0 {
		d.FaviconHash = faviconHash(in.Favicon.Body)
		if entry, ok := faviconLookup(d.FaviconHash); ok {
			w := 40
			if !entry.PHP {
				w = 20
			}
			detail := "favicon hash matches " + entry.Product
			if entry.Note != "" {
				detail += " (" + entry.Note + ")"
			}
			addEv(Evidence{
				Signal: "favicon.catalog", Source: in.Favicon.FinalURL, Weight: w,
				Detail: detail, Data: d.FaviconHash + " → " + entry.Product,
				Where: "site favicon", How: "mmh3 favicon-hash catalogue match",
				Pattern: d.FaviconHash, Snippet: entry.Product, Status: in.Favicon.Status,
			})
			addFw(entry.Framework)
		}
	}

	// --- CMS / framework versions -------------------------------------------
	cmsVersions := detectCMSVersions(in, fwSet, addEv, addFw)
	if len(cmsVersions) > 0 {
		d.FrameworkVersions = cmsVersions
	}

	// --- Finalise -----------------------------------------------------------
	if d.Confidence > 100 {
		d.Confidence = 100
	}
	d.Verdict = scoreToVerdict(d.Confidence)
	d.IsPHP = d.Confidence >= 50
	if d.IsPHP && d.Variant == "" {
		d.Variant = "PHP"
	}

	d.Frameworks, d.Addons = partitionAddons(d.Frameworks)
	sort.Strings(d.Frameworks)
	sort.Strings(d.Addons)
	sort.Strings(d.Extensions)
	sort.Strings(d.Modules)
	sortEvidence(d.Evidence)

	if d.IsPHP {
		d.SAPI = inferSAPI(in.Root, in.PathInfo != nil && in.PathInfo.Err == "" && in.PathInfo.Status == 200)
	}

	if in.Deep && d.IsPHP {
		cat := in.Catalog
		if cat == nil {
			cat = DefaultCatalog()
		}
		d.EndOfLife, d.EOLDetail = cat.EOL(d.Variant, d.Version)
		d.Vulnerabilities = cat.CorrelatePHP(d.Variant, d.Version)
		for fw, ver := range d.FrameworkVersions {
			d.Vulnerabilities = append(d.Vulnerabilities, cat.CorrelateCMS(fw, ver)...)
		}
		sortVulns(d.Vulnerabilities)
	}

	return d
}

// analyzeResponse extracts header, cookie and body evidence from one response.
func analyzeResponse(
	resp *probe.Response,
	source string,
	addEv func(Evidence),
	addFw func(string),
	addExt func(string),
	addMod func(string),
	setVersion func(string, string, int),
	setVariant func(string),
) {
	if resp == nil || resp.Err != "" {
		return
	}

	// Tag every signal from this response with its HTTP status code.
	rawAddEv := addEv
	addEv = func(ev Evidence) {
		if ev.Status == 0 {
			ev.Status = resp.Status
		}
		rawAddEv(ev)
	}

	// Header-based signatures.
	for _, sig := range headerSigs {
		for _, val := range resp.HeaderValues(sig.header) {
			if sig.contains == "" || containsFold(val, sig.contains) {
				how := "header present"
				if sig.contains != "" {
					how = "header substring match"
				}
				addEv(Evidence{
					Signal: "header." + strings.ToLower(sig.header),
					Source: source, Weight: phpWeight(sig.weight, sig.phpImplied, sig.variant), Detail: sig.detail, Data: val,
					Where: "response header '" + sig.header + "'", How: how,
					Pattern: sig.contains, Snippet: sig.header + ": " + val, Probe: source,
				})
				addFw(sig.framework)
				if sig.variant != "" {
					setVariant(sig.variant)
				}
				break
			}
		}
	}

	// Version from X-Powered-By / Server.
	for _, h := range []string{"X-Powered-By", "Server"} {
		for _, val := range resp.HeaderValues(h) {
			if m := reVersion.FindStringSubmatch(val); m != nil {
				setVersion(m[1], h+" header", 2)
				setVariant("PHP")
			}
			if m := reHHVM.FindStringSubmatch(val); m != nil {
				setVersion(m[1], h+" header (HHVM)", 2)
				setVariant("HHVM")
			}
		}
	}

	// Server header modules (mod_php, OpenSSL/..., PHP/...).
	for _, val := range resp.HeaderValues("Server") {
		for _, tok := range strings.Fields(val) {
			if strings.HasPrefix(tok, "mod_") || strings.Contains(tok, "/") {
				tok = strings.Trim(tok, "()")
				if tok != "" {
					addMod(tok)
				}
			}
		}
	}

	// Cookie-based signatures.
	for _, c := range resp.Cookies {
		for _, sig := range cookieSigs {
			if cookieMatch(c.Name, sig) {
				how := "cookie-name match"
				if sig.kind == matchPrefix {
					how = "cookie-name prefix match"
				}
				addEv(Evidence{
					Signal: "cookie." + strings.ToLower(strings.Trim(sig.name, "_-")),
					Source: source, Weight: sig.weight, Detail: sig.detail, Data: c.Name,
					Where: "Set-Cookie header", How: how, Pattern: sig.name,
					Snippet: "Set-Cookie: " + c.Name + "=…", Probe: source,
				})
				addFw(sig.framework)
			}
		}
	}

	// Body-based signatures.
	body := resp.BodyString()
	if body != "" {
		for _, sig := range bodySigs {
			if loc := sig.re.FindStringIndex(body); loc != nil {
				snippet, line := bodyContext(body, loc[0], loc[1])
				addEv(Evidence{
					Signal: sig.id, Source: source, Weight: phpWeight(sig.weight, sig.phpImplied, ""),
					Detail: sig.detail, Data: collapseWS(body[loc[0]:loc[1]]),
					Where: "response body", How: "regular expression",
					Pattern: sig.re.String(), Snippet: snippet, Line: line, Probe: source,
				})
				addFw(sig.framework)
			}
		}
		for _, lt := range loaderBodyTokens {
			if containsFold(body, lt.token) {
				addExt(lt.module)
			}
		}
		// Version from an Apache/server signature footer (default error pages).
		if m := reApacheSig.FindStringSubmatch(body); m != nil {
			setVersion(m[1], "Apache server signature", 2)
			setVariant("PHP")
		} else if m := reServerSig.FindStringSubmatch(body); m != nil {
			setVersion(m[1], "server signature", 2)
			setVariant("PHP")
		}
		// "Powered by <app>" footer names a PHP application.
		if m := rePoweredBy.FindStringSubmatch(body); m != nil {
			addFw(canonicalApp(m[1]))
		}
		if m := reGenerator.FindStringSubmatch(body); m != nil {
			gen := m[1]
			_, line := bodyContext(body, strings.Index(body, m[0]), strings.Index(body, m[0])+len(m[0]))
			addEv(Evidence{
				Signal: "body.generator", Source: source, Weight: 20,
				Detail: "HTML generator meta tag", Data: gen,
				Where: "response body", How: "regular expression", Pattern: reGenerator.String(),
				Snippet: collapseWS(m[0]), Line: line, Probe: source,
			})
			addFw(frameworkFromGenerator(gen))
		}
	}
}

func analyzeEasterEggs(in Input, addEv func(Evidence), setVersion func(string, string, int)) {
	if c := in.EasterCredits; c != nil && c.Err == "" && c.Status == 200 {
		b := c.BodyString()
		if containsFold(b, "PHP Credits") || containsFold(b, "Zend Engine") || containsFold(b, "PHP Group") {
			addEv(Evidence{
				Signal: "easter-egg.credits", Source: c.FinalURL, Weight: 85,
				Detail: "expose_php easter-egg credits page served (PHP < 5.5, expose_php On)", Status: c.Status,
			})
		}
	}
	if l := in.EasterLogo; l != nil && l.Err == "" && l.Status == 200 {
		ct := strings.ToLower(l.HeaderGet("Content-Type"))
		if strings.HasPrefix(ct, "image/") && len(l.Body) > 0 && len(l.Body) < 20000 {
			addEv(Evidence{
				Signal: "easter-egg.logo", Source: l.FinalURL, Weight: 80,
				Detail: "expose_php easter-egg logo image served (PHP < 5.5, expose_php On)",
				Data:   "Content-Type: " + l.HeaderGet("Content-Type"), Status: l.Status,
			})
		}
	}
}

func parsePHPInfoModules(body string, addExt func(string), setVariant func(string)) {
	lower := strings.ToLower(body)
	for _, mod := range phpInfoModules {
		if strings.Contains(lower, strings.ToLower(mod)) {
			addExt(mod)
		}
	}
	if containsFold(body, "HipHop") || containsFold(body, "HHVM") {
		setVariant("HHVM")
	} else if containsFold(body, "Zend Server") {
		setVariant("Zend Server")
	}
	if m := reWithLoaders.FindAllStringSubmatch(body, -1); m != nil {
		for _, g := range m {
			addExt(strings.TrimSpace(g[1]))
		}
	}
}

func cookieMatch(name string, sig cookieSig) bool {
	switch sig.kind {
	case matchPrefix:
		return strings.HasPrefix(strings.ToLower(name), strings.ToLower(sig.name))
	default:
		return strings.EqualFold(name, sig.name)
	}
}

func frameworkFromGenerator(gen string) string {
	g := strings.ToLower(gen)
	switch {
	case strings.Contains(g, "wordpress"):
		return "WordPress"
	case strings.Contains(g, "joomla"):
		return "Joomla"
	case strings.Contains(g, "drupal"):
		return "Drupal"
	case strings.Contains(g, "mediawiki"):
		return "MediaWiki"
	case strings.Contains(g, "typo3"):
		return "TYPO3"
	case strings.Contains(g, "prestashop"):
		return "PrestaShop"
	default:
		return ""
	}
}

// canonicalApp normalises a "Powered by" app name to a stable label.
func canonicalApp(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "simple machines":
		return "SMF"
	case "concrete5":
		return "ConcreteCMS"
	default:
		return strings.TrimSpace(name)
	}
}

// addonNames are technologies reported under Addons rather than Frameworks:
// PHP tools, dev aids and runtime agents.
var addonNames = map[string]bool{
	"Whoops":                true,
	"Laravel Debugbar":      true,
	"New Relic (PHP agent)": true,
	"Clockwork":             true,
	"Adminer":               true,
	"phpMyAdmin":            true,
	"WooCommerce":           true,
	"Polylang":              true,
	"K2":                    true,
	"LiteSpeed Cache":       true,
	"Laravel Telescope":     true,
	"Laravel Horizon":       true,
}

// partitionAddons moves addon technologies out of frameworks into addons.
func partitionAddons(frameworks []string) (fw, addons []string) {
	for _, f := range frameworks {
		if addonNames[f] {
			addons = append(addons, f)
		} else {
			fw = append(fw, f)
		}
	}
	return fw, addons
}

// inferSAPI makes a best-effort guess at the PHP server API from the response.
func inferSAPI(root *probe.Response, pathInfo bool) string {
	server := strings.ToLower(strings.Join(root.HeaderValues("Server"), " "))
	poweredBy := root.HeaderGet("X-Powered-By")
	hasPHPBanner := reVersion.MatchString(server)
	switch {
	case strings.Contains(server, "apache") && hasPHPBanner:
		return "apache (mod_php)"
	case strings.Contains(server, "apache"):
		return "apache (mod_php or php-fpm)"
	case strings.Contains(server, "nginx") || strings.Contains(server, "openresty"):
		return "php-fpm (behind nginx)"
	case strings.Contains(server, "litespeed"):
		return "litespeed (lsapi)"
	case strings.Contains(server, "caddy"):
		return "php-fpm (behind caddy)"
	case pathInfo && poweredBy != "":
		return "php-cgi/php-fpm (PATH_INFO enabled)"
	default:
		return ""
	}
}

// detectStatusDashboards recognises exposed status/management pages that reveal
// PHP extensions (OPcache, APCu) or PHP tools (Adminer, phpMyAdmin, Composer).
func detectStatusDashboards(url, body string, addEv func(Evidence), addExt, addFw, addMod func(string)) {
	lu := strings.ToLower(url)

	if contains(body, "opcache_get_status") ||
		(containsFold(body, "opcache") && (containsFold(body, "cached scripts") || containsFold(body, "opcache statistics") || containsFold(body, "opcache_reset"))) {
		addExt("Zend OPcache")
		addEv(Evidence{Signal: "diag.opcache-dashboard", Source: url, Weight: 30, Detail: "OPcache status page exposed"})
	}
	if containsFold(body, "apcu_cache_info") || containsFold(body, "apcu version") {
		addExt("apcu")
		addEv(Evidence{Signal: "diag.apcu-dashboard", Source: url, Weight: 30, Detail: "APCu status page exposed"})
	}
	if (strings.Contains(lu, "adminer") && containsFold(body, "adminer")) ||
		(containsFold(body, "adminer") && containsFold(body, "<form") && containsFold(body, "login")) {
		addFw("Adminer")
		addEv(Evidence{Signal: "diag.adminer", Source: url, Weight: 45, Detail: "Adminer database tool exposed"})
	}
	if strings.Contains(lu, "phpmyadmin") || (containsFold(body, "phpmyadmin") && containsFold(body, "pma_")) {
		addFw("phpMyAdmin")
		addEv(Evidence{Signal: "diag.phpmyadmin", Source: url, Weight: 45, Detail: "phpMyAdmin exposed"})
	}
	if strings.Contains(lu, "installed.json") && (strings.Contains(body, "\"packages\"") || strings.Contains(body, "\"name\"")) {
		addEv(Evidence{Signal: "diag.composer-installed", Source: url, Weight: 45, Detail: "Composer installed packages exposed (vendor/composer/installed.json)"})
	}

	// Exposed dotenv file: a strong PHP/Laravel signal and a notable leak.
	if strings.HasSuffix(lu, "/.env") && (containsFold(body, "APP_KEY=") || containsFold(body, "APP_ENV=") || containsFold(body, "DB_CONNECTION=") || containsFold(body, "DB_PASSWORD=")) {
		addEv(Evidence{Signal: "diag.dotenv", Source: url, Weight: 55, Detail: "Exposed .env configuration file (secrets may be readable)"})
		if containsFold(body, "APP_KEY=") || containsFold(body, "DB_CONNECTION=") {
			addFw("Laravel")
		}
	}
	// Symfony dev front controller / web profiler.
	if (strings.Contains(lu, "app_dev.php") || strings.Contains(lu, "/_profiler")) &&
		(containsFold(body, "sf-toolbar") || containsFold(body, "Symfony Profiler") || containsFold(body, "WebProfilerBundle") || containsFold(body, "Symfony\\")) {
		addFw("Symfony")
		addEv(Evidence{Signal: "diag.symfony-profiler", Source: url, Weight: 45, Detail: "Symfony dev front controller / web profiler exposed (debug mode)"})
	}
	// Laravel Telescope / Horizon dashboards.
	if strings.Contains(lu, "telescope") && (containsFold(body, "Telescope") || containsFold(body, "Laravel")) {
		addFw("Laravel")
		addFw("Laravel Telescope")
		addEv(Evidence{Signal: "diag.telescope", Source: url, Weight: 45, Detail: "Laravel Telescope debug dashboard exposed"})
	}
	if strings.Contains(lu, "horizon") && (containsFold(body, "Horizon") || containsFold(body, "Laravel")) {
		addFw("Laravel")
		addFw("Laravel Horizon")
		addEv(Evidence{Signal: "diag.horizon", Source: url, Weight: 40, Detail: "Laravel Horizon queue dashboard exposed"})
	}
	// php-fpm status page.
	if containsFold(body, "pool:") && containsFold(body, "accepted conn") {
		addMod("php-fpm")
		addEv(Evidence{Signal: "diag.fpm-status", Source: url, Weight: 40, Detail: "PHP-FPM status page exposed"})
	}
	// Nextcloud / ownCloud / OpenCloud status.php.
	if strings.HasSuffix(lu, "status.php") && containsFold(body, "\"installed\"") && containsFold(body, "\"version\"") {
		prod := "Nextcloud/ownCloud"
		phpCloud := true
		if m := reCloudProduct.FindStringSubmatch(body); m != nil && m[1] != "" {
			if c := canonCloud(m[1]); c != "" {
				prod = c
			} else {
				prod = m[1] // e.g. OpenCloud / Infinite Scale (Go backend)
				phpCloud = false
			}
		}
		addFw(prod)
		w := 45
		if !phpCloud {
			w = 0 // detected, but a non-PHP backend must not boost PHP confidence
		}
		addEv(Evidence{Signal: "diag.nextcloud-status", Source: url, Weight: w, Detail: prod + " status.php exposed (version/edition disclosed)"})
	}
}

func isComposerManifest(url, body string) bool {
	u := strings.ToLower(url)
	if !strings.Contains(u, "composer.json") && !strings.Contains(u, "composer.lock") {
		return false
	}
	return strings.Contains(body, "\"require\"") ||
		strings.Contains(body, "\"packages\"") ||
		strings.Contains(body, "\"name\"")
}

func hasPHPExtension(u string) bool {
	// Trim query/fragment.
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	for _, ext := range []string{".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phps"} {
		if strings.HasSuffix(u, ext) {
			return true
		}
	}
	return false
}

// bodyContext returns a collapsed context window around a body match and the
// 1-based line number where the match begins.
func bodyContext(body string, start, end int) (string, int) {
	if start < 0 {
		start = 0
	}
	if end > len(body) {
		end = len(body)
	}
	line := 1 + strings.Count(body[:start], "\n")
	lo := start - 60
	if lo < 0 {
		lo = 0
	}
	hi := end + 60
	if hi > len(body) {
		hi = len(body)
	}
	seg := collapseWS(body[lo:hi])
	if len(seg) > 220 {
		seg = seg[:220] + "…"
	}
	return seg, line
}

func collapseWS(s string) string { return strings.Join(strings.Fields(s), " ") }

// provenanceDefaults supplies a baseline where/how for a signal by prefix.
func provenanceDefaults(signal string) (where, how string) {
	switch {
	case strings.HasPrefix(signal, "header."):
		return "response header", "header match"
	case strings.HasPrefix(signal, "cookie."):
		return "Set-Cookie header", "cookie-name match"
	case strings.HasPrefix(signal, "diag."):
		return "deep-probe response", "exposed diagnostic/tool page"
	case strings.HasPrefix(signal, "easter-egg."):
		return "expose_php easter-egg probe", "GUID easter-egg response"
	case strings.HasPrefix(signal, "behavior."):
		return "server behaviour", "behavioural probe"
	case strings.HasPrefix(signal, "cms.version."):
		return "response body / version file", "CMS version extraction"
	case strings.HasPrefix(signal, "url."):
		return "request URL", "URL inspection"
	case strings.HasPrefix(signal, "favicon."):
		return "site favicon", "mmh3 favicon-hash catalogue match"
	case strings.HasPrefix(signal, "body."):
		return "response body", "content match"
	default:
		return "response", "heuristic"
	}
}

// phpWeight gates a signature's confidence contribution: a signature that does
// not imply PHP (e.g. a Go-based app, or a generic web-server marker) still
// records its framework and evidence, but adds 0 to the PHP confidence score.
func phpWeight(weight int, phpImplied bool, variant string) int {
	if phpImplied || variant != "" {
		return weight
	}
	return 0
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func sortEvidence(ev []Evidence) {
	sort.SliceStable(ev, func(i, j int) bool {
		if ev[i].Weight != ev[j].Weight {
			return ev[i].Weight > ev[j].Weight
		}
		return ev[i].Signal < ev[j].Signal
	})
}

func sortVulns(vs []Vulnerability) {
	sort.SliceStable(vs, func(i, j int) bool {
		ri, rj := SeverityRank(vs[i].Severity), SeverityRank(vs[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return vs[i].ID > vs[j].ID
	})
}
