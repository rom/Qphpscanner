package webserver

import "regexp"

// category groups a front-layer detection.
type category string

const (
	catCDN   category = "CDN"
	catWAF   category = "WAF"
	catCache category = "cache"
	catLB    category = "load-balancer"
)

// headerSig matches a response header value.
type headerSig struct {
	header   string // header name
	contains string // case-insensitive substring; "" means "present at all"
	name     string // technology name
	cat      category
	conf     int
	detail   string
}

// cookieSig matches a Set-Cookie name.
type cookieSig struct {
	name   string
	prefix bool
	tech   string
	cat    category
	conf   int
	detail string
}

// bodySig matches a block/challenge page body.
type bodySig struct {
	re     *regexp.Regexp
	tech   string
	cat    category
	conf   int
	detail string
}

// proxyHeaderSigs identify CDNs, WAFs, caches and load balancers from headers.
var proxyHeaderSigs = []headerSig{
	// Cloudflare.
	{"Server", "cloudflare", "Cloudflare", catCDN, 90, "Server: cloudflare"},
	{"CF-RAY", "", "Cloudflare", catCDN, 95, "CF-RAY header"},
	{"CF-Cache-Status", "", "Cloudflare", catCDN, 85, "CF-Cache-Status header"},
	{"cf-mitigated", "", "Cloudflare", catWAF, 75, "Cloudflare mitigation header"},
	// Akamai.
	{"Server", "akamaighost", "Akamai", catCDN, 90, "Server: AkamaiGHost"},
	{"X-Akamai-Transformed", "", "Akamai", catCDN, 85, "X-Akamai-Transformed header"},
	{"X-Akamai-Request-ID", "", "Akamai", catCDN, 80, "X-Akamai-Request-ID header"},
	// Amazon CloudFront / AWS.
	{"X-Amz-Cf-Id", "", "Amazon CloudFront", catCDN, 90, "X-Amz-Cf-Id header"},
	{"X-Amz-Cf-Pop", "", "Amazon CloudFront", catCDN, 90, "X-Amz-Cf-Pop header"},
	{"Via", "cloudfront", "Amazon CloudFront", catCDN, 85, "Via mentions CloudFront"},
	{"Server", "cloudfront", "Amazon CloudFront", catCDN, 85, "Server: CloudFront"},
	{"X-Amzn-Trace-Id", "", "AWS ALB", catLB, 70, "X-Amzn-Trace-Id header"},
	{"Server", "awselb", "AWS ELB", catLB, 80, "Server: awselb"},
	// Fastly.
	{"X-Fastly-Request-ID", "", "Fastly", catCDN, 90, "X-Fastly-Request-ID header"},
	{"Fastly-Debug-Digest", "", "Fastly", catCDN, 80, "Fastly-Debug-Digest header"},
	{"X-Served-By", "cache-", "Fastly", catCDN, 60, "Fastly X-Served-By cache node"},
	// Sucuri.
	{"Server", "sucuri", "Sucuri", catWAF, 90, "Server: Sucuri/Cloudproxy"},
	{"X-Sucuri-ID", "", "Sucuri", catWAF, 95, "X-Sucuri-ID header"},
	{"X-Sucuri-Cache", "", "Sucuri", catCache, 70, "X-Sucuri-Cache header"},
	// Imperva Incapsula.
	{"X-Iinfo", "", "Imperva Incapsula", catWAF, 90, "X-Iinfo header"},
	{"X-CDN", "incapsula", "Imperva Incapsula", catCDN, 90, "X-CDN: Incapsula"},
	{"Server", "incapsula", "Imperva Incapsula", catWAF, 85, "Server mentions Incapsula"},
	// Caching proxies.
	{"X-Varnish", "", "Varnish", catCache, 85, "X-Varnish header"},
	{"Via", "varnish", "Varnish", catCache, 80, "Via mentions Varnish"},
	{"Via", "squid", "Squid", catCache, 85, "Via mentions Squid"},
	{"X-Squid-Error", "", "Squid", catCache, 85, "X-Squid-Error header"},
	// Platform CDNs.
	{"Server", "vercel", "Vercel", catCDN, 85, "Server: Vercel"},
	{"X-Vercel-Id", "", "Vercel", catCDN, 90, "X-Vercel-Id header"},
	{"Server", "netlify", "Netlify", catCDN, 85, "Server: Netlify"},
	{"X-Nf-Request-Id", "", "Netlify", catCDN, 85, "X-Nf-Request-Id header"},
	{"Server", "keycdn", "KeyCDN", catCDN, 85, "Server: keycdn-engine"},
	{"Server", "bunnycdn", "BunnyCDN", catCDN, 85, "Server: BunnyCDN"},
	{"Server", "stackpath", "StackPath", catCDN, 80, "Server: StackPath"},
	{"X-Azure-Ref", "", "Azure Front Door", catCDN, 85, "X-Azure-Ref header"},
	{"X-Msedge-Ref", "", "Azure / MS Edge", catCDN, 80, "X-Msedge-Ref header"},
	{"Via", "google", "Google", catCDN, 55, "Via mentions Google"},
	{"Server", "ECAcc", "Edgecast / Verizon", catCDN, 75, "Server: ECAcc"},
	// WAFs / security proxies.
	{"Server", "mod_security", "ModSecurity", catWAF, 70, "Server mentions mod_security"},
	{"Server", "NOYB", "ModSecurity", catWAF, 60, "Server: NOYB (mod_security)"},
	{"Server", "barracuda", "Barracuda", catWAF, 80, "Server mentions Barracuda"},
	{"Server", "safedog", "SafeDog", catWAF, 80, "Server: SafeDog"},
	{"Server", "yunjiasu", "Baidu Yunjiasu", catWAF, 80, "Server: Yunjiasu"},
	{"X-Protected-By", "sqreen", "Sqreen", catWAF, 80, "X-Protected-By: Sqreen"},
	{"Server", "ddos-guard", "DDoS-Guard", catWAF, 85, "Server: ddos-guard"},
	{"Server", "BIG-IP", "F5 BIG-IP", catLB, 80, "Server mentions BIG-IP"},
	// Generic intermediary indicators.
	{"X-Backend-Server", "", "reverse proxy (backend named)", catLB, 45, "X-Backend-Server header"},
}

// genericProxyHeaders are present only when an intermediary (proxy/cache) is
// in the path, even when the specific product is unknown.
var genericProxyHeaders = []string{
	"Via", "X-Cache", "X-Cache-Hits", "X-Served-By", "Age", "X-Proxy-Cache",
	"X-Varnish", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host",
}

var proxyCookieSigs = []cookieSig{
	{"__cfduid", false, "Cloudflare", catCDN, 70, "Cloudflare cookie"},
	{"__cf_bm", false, "Cloudflare", catWAF, 80, "Cloudflare bot-management cookie"},
	{"cf_clearance", false, "Cloudflare", catWAF, 85, "Cloudflare challenge-clearance cookie"},
	{"incap_ses_", true, "Imperva Incapsula", catWAF, 85, "Incapsula session cookie"},
	{"visid_incap_", true, "Imperva Incapsula", catWAF, 85, "Incapsula visitor cookie"},
	{"nlbi_", true, "Imperva Incapsula", catLB, 70, "Incapsula load-balancing cookie"},
	{"ak_bmsc", false, "Akamai Bot Manager", catWAF, 80, "Akamai Bot Manager cookie"},
	{"bm_sv", false, "Akamai Bot Manager", catWAF, 75, "Akamai Bot Manager cookie"},
	{"_abck", false, "Akamai Bot Manager", catWAF, 70, "Akamai Bot Manager cookie"},
	{"AWSALB", false, "AWS ELB/ALB", catLB, 85, "AWS ALB stickiness cookie"},
	{"AWSALBCORS", false, "AWS ELB/ALB", catLB, 85, "AWS ALB stickiness cookie"},
	{"AWSELB", false, "AWS ELB", catLB, 85, "AWS ELB cookie"},
	{"BIGipServer", true, "F5 BIG-IP", catLB, 90, "F5 BIG-IP persistence cookie"},
	{"NSC_", true, "Citrix NetScaler", catLB, 85, "Citrix NetScaler cookie"},
	{"barra_counter_session", false, "Barracuda", catWAF, 80, "Barracuda WAF cookie"},
	{"sucuri_cloudproxy_", true, "Sucuri", catWAF, 85, "Sucuri cloudproxy cookie"},
	{"__ddg", true, "DDoS-Guard", catWAF, 80, "DDoS-Guard cookie"},
}

var proxyBodySigs = []bodySig{
	{regexp.MustCompile(`(?i)Attention Required! \| Cloudflare`), "Cloudflare", catWAF, 90, "Cloudflare block page"},
	{regexp.MustCompile(`(?i)<title>Just a moment\.\.\.</title>|challenge-platform|cf-browser-verification`), "Cloudflare", catWAF, 80, "Cloudflare challenge page"},
	{regexp.MustCompile(`(?i)Cloudflare Ray ID|cf-error-details`), "Cloudflare", catCDN, 60, "Cloudflare error page"},
	{regexp.MustCompile(`(?i)Access Denied.*Sucuri|Sucuri WebSite Firewall`), "Sucuri", catWAF, 90, "Sucuri block page"},
	{regexp.MustCompile(`(?i)Request unsuccessful\. Incapsula incident ID|_Incapsula_Resource`), "Imperva Incapsula", catWAF, 90, "Incapsula block page"},
	{regexp.MustCompile(`(?i)This error was generated by Mod_Security|Mod_Security|mod_security`), "ModSecurity", catWAF, 75, "ModSecurity block page"},
	{regexp.MustCompile(`(?i)Generated by Wordfence`), "Wordfence", catWAF, 85, "Wordfence (WordPress WAF) block page"},
	{regexp.MustCompile(`(?i)DDoS protection by|DDoS-Guard`), "DDoS-Guard", catWAF, 80, "DDoS-Guard page"},
	{regexp.MustCompile(`(?i)Radware|AppWall`), "Radware AppWall", catWAF, 70, "Radware AppWall page"},
	{regexp.MustCompile(`(?i)The requested URL was rejected.*support ID`), "F5 BIG-IP ASM", catWAF, 80, "F5 BIG-IP ASM block page"},
}

// --- Web server product/version/module patterns ---

var (
	reServerProduct = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_.\-]*?)(?:/([0-9][A-Za-z0-9.\-]*))?(?:\s|$)`)
	reNginxBody     = regexp.MustCompile(`(?i)<(?:center|hr)>\s*nginx(?:/([0-9.]+))?`)
	// reNginxStatus matches the ngx_http_stub_status_module page body.
	reNginxStatus = regexp.MustCompile(`(?i)Active connections:\s*\d+\s+server\s+accepts\s+handled\s+requests`)
	// reNginxVer recovers an nginx version from any page body (status/error),
	// used when the Server header hides it (server_tokens off).
	reNginxVer = regexp.MustCompile(`(?i)\b(?:nginx|openresty|tengine)/([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:\.[0-9]+)?)`)
	// nginxAccelHeaders are nginx-specific internal-redirect / offload headers.
	nginxAccelHeaders = []string{"X-Accel-Buffering", "X-Accel-Redirect", "X-Accel-Limit-Rate", "X-Accel-Expires", "X-Accel-Charset"}
	reApacheBody      = regexp.MustCompile(`(?i)Apache/([0-9][0-9.]+)`)
	reIISBody         = regexp.MustCompile(`(?i)Microsoft-IIS/([0-9][0-9.]+)`)
	reLiteSpeedBody   = regexp.MustCompile(`(?i)LiteSpeed`)
)

// knownServers maps a Server-header product token (lowercased) to a display
// name. Tokens that are really CDNs/proxies are handled separately.
var knownServers = map[string]string{
	"apache":        "Apache",
	"nginx":         "nginx",
	"openresty":     "OpenResty",
	"microsoft-iis": "Microsoft IIS",
	"litespeed":     "LiteSpeed",
	"lsws":          "LiteSpeed",
	"caddy":         "Caddy",
	"lighttpd":      "lighttpd",
	"tengine":       "Tengine",
	"cherokee":      "Cherokee",
	"apache-coyote": "Apache Tomcat",
	"jetty":         "Jetty",
	"kestrel":       "Kestrel",
	"cowboy":        "Cowboy",
	"werkzeug":      "Werkzeug",
	"gunicorn":      "Gunicorn",
	"gws":           "Google Web Server",
	"gvs":           "Google Video Server",
	"gfe":           "Google Front End",
	"squid":         "Squid",
	"webrick":       "WEBrick",
	"puma":          "Puma",
	"hypercorn":     "Hypercorn",
	"uvicorn":       "Uvicorn",
	"daphne":        "Daphne",
	"tornadoserver": "Tornado",
	"mochiweb":      "MochiWeb",
	"openbsd httpd": "OpenBSD httpd",
}

// cdnServerTokens are Server-header values that indicate a CDN/proxy rather
// than the origin web server (origin product is concealed).
var cdnServerTokens = map[string]string{
	"cloudflare":        "Cloudflare",
	"cloudfront":        "Amazon CloudFront",
	"akamaighost":       "Akamai",
	"sucuri/cloudproxy": "Sucuri",
	"vercel":            "Vercel",
	"netlify":           "Netlify",
	"ecacc":             "Edgecast / Verizon",
	"ecs":               "Edgecast",
	"ddos-guard":        "DDoS-Guard",
}

// moduleHeaderSigs derive server-level modules/runtimes from headers.
var moduleHeaderSigs = []struct {
	header   string
	contains string
	label    string // "" means "use the header value"
}{
	{"X-AspNet-Version", "", "ASP.NET"},
	{"X-AspNetMvc-Version", "", "ASP.NET MVC"},
	{"X-Powered-By", "asp.net", "ASP.NET"},
	{"X-Powered-By", "express", "Express"},
	{"X-Powered-By", "phusion passenger", "Phusion Passenger"},
	{"X-Powered-By", "servlet", "Java Servlet"},
	{"X-Mod-Pagespeed", "", "mod_pagespeed"},
	{"X-Page-Speed", "", "mod_pagespeed/ngx_pagespeed"},
	{"X-Runtime", "", "Rack/Rails (X-Runtime)"},
}
