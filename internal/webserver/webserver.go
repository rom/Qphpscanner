// Package webserver identifies the web server (product, version, modules) and
// any reverse proxy, CDN, WAF or load balancer in front of a service. A front
// layer means the real origin reply may be concealed and/or protected, which
// is flagged in the result.
package webserver

import (
	"sort"
	"strings"

	"github.com/rom/qphpscanner/internal/probe"
)

// Finding is one signal with a confidence score (0-100) and a tier label.
type Finding struct {
	Signal     string `json:"signal"`
	Detail     string `json:"detail"`
	Data       string `json:"data,omitempty"`
	Confidence int    `json:"confidence"`
	Tier       string `json:"tier"`
}

// ServerInfo describes the identified web server.
type ServerInfo struct {
	Product  string    `json:"product,omitempty"`
	Version  string    `json:"version,omitempty"`
	OS       string    `json:"os,omitempty"`
	Modules  []string  `json:"modules,omitempty"`
	Evidence []Finding `json:"evidence,omitempty"`
}

// ProxyInfo describes any reverse proxy / CDN / WAF / load balancer in front.
type ProxyInfo struct {
	Present       bool      `json:"present"`
	Concealed     bool      `json:"concealed"`
	CDN           []string  `json:"cdn,omitempty"`
	WAF           []string  `json:"waf,omitempty"`
	Caches        []string  `json:"caches,omitempty"`
	LoadBalancers []string  `json:"load_balancers,omitempty"`
	Note          string    `json:"note,omitempty"`
	Evidence      []Finding `json:"evidence,omitempty"`
}

// Result bundles the server and proxy assessments.
type Result struct {
	Server ServerInfo `json:"server"`
	Proxy  ProxyInfo  `json:"proxy"`
}

// Tier maps a confidence score to low/medium/high.
func Tier(conf int) string {
	switch {
	case conf >= 70:
		return "high"
	case conf >= 40:
		return "medium"
	default:
		return "low"
	}
}

const nameThreshold = 40

// Analyze inspects the root response plus any extra responses (error pages,
// OPTIONS, status probes) and returns server + proxy identification.
func Analyze(root *probe.Response, extra []*probe.Response) *Result {
	all := make([]*probe.Response, 0, len(extra)+1)
	if root != nil && root.Err == "" {
		all = append(all, root)
	}
	for _, r := range extra {
		if r != nil && r.Err == "" {
			all = append(all, r)
		}
	}
	return &Result{
		Server: detectServer(root, all),
		Proxy:  detectProxy(all),
	}
}

func detectProxy(responses []*probe.Response) ProxyInfo {
	p := ProxyInfo{}
	names := map[category]map[string]int{catCDN: {}, catWAF: {}, catCache: {}, catLB: {}}
	seen := map[string]bool{}
	record := func(cat category, name string, conf int, f Finding) {
		if cur, ok := names[cat][name]; !ok || conf > cur {
			names[cat][name] = conf
		}
		if !seen[f.Signal] {
			seen[f.Signal] = true
			p.Evidence = append(p.Evidence, f)
		}
	}

	generic := ""
	for _, r := range responses {
		for _, s := range proxyHeaderSigs {
			vals := r.HeaderValues(s.header)
			if len(vals) == 0 {
				continue
			}
			matched := ""
			if s.contains == "" {
				matched = vals[0]
			} else {
				for _, v := range vals {
					if containsFold(v, s.contains) {
						matched = v
						break
					}
				}
			}
			if matched == "" {
				continue
			}
			record(s.cat, s.name, s.conf, Finding{
				Signal: "header." + strings.ToLower(s.header) + "." + s.name,
				Detail: s.detail, Data: trim(matched), Confidence: s.conf, Tier: Tier(s.conf),
			})
		}
		for _, h := range genericProxyHeaders {
			if v := r.HeaderGet(h); v != "" {
				generic = h + ": " + trim(v)
			}
		}
		for _, c := range r.Cookies {
			for _, s := range proxyCookieSigs {
				if cookieMatch(c.Name, s.name, s.prefix) {
					record(s.cat, s.tech, s.conf, Finding{
						Signal: "cookie." + s.tech, Detail: s.detail, Data: c.Name,
						Confidence: s.conf, Tier: Tier(s.conf),
					})
				}
			}
		}
		if body := r.BodyString(); body != "" {
			for _, s := range proxyBodySigs {
				if s.re.MatchString(body) {
					record(s.cat, s.tech, s.conf, Finding{
						Signal: "body." + s.tech, Detail: s.detail,
						Confidence: s.conf, Tier: Tier(s.conf),
					})
				}
			}
		}
	}

	p.CDN = namesAbove(names[catCDN], nameThreshold)
	p.WAF = namesAbove(names[catWAF], nameThreshold)
	p.Caches = namesAbove(names[catCache], nameThreshold)
	p.LoadBalancers = namesAbove(names[catLB], nameThreshold)

	if generic != "" && len(p.Caches) == 0 && len(p.CDN) == 0 {
		p.Caches = append(p.Caches, "reverse proxy / cache (unidentified)")
		p.Evidence = append(p.Evidence, Finding{
			Signal: "proxy.generic", Detail: "intermediary header present", Data: generic,
			Confidence: 45, Tier: Tier(45),
		})
	}

	p.Present = len(p.CDN)+len(p.WAF)+len(p.Caches)+len(p.LoadBalancers) > 0
	p.Concealed = p.Present
	p.Note = proxyNote(p)
	sortFindings(p.Evidence)
	return p
}

func detectServer(root *probe.Response, all []*probe.Response) ServerInfo {
	s := ServerInfo{}
	modSet := map[string]bool{}
	addMod := func(m string) {
		m = trim(m)
		if m == "" || modSet[strings.ToLower(m)] {
			return
		}
		modSet[strings.ToLower(m)] = true
		s.Modules = append(s.Modules, m)
	}

	if root != nil && root.Err == "" {
		productSet := false
		cdnFronted, cdnData := "", ""
		var firstUnknown []string // [raw, product, version]

		for _, serverVal := range root.HeaderValues("Server") {
			if serverVal == "" {
				continue
			}
			for _, tok := range serverModules(serverVal) {
				addMod(tok)
			}
			if os := osHint(serverVal); os != "" && s.OS == "" {
				s.OS = os
			}
			m := reServerProduct.FindStringSubmatch(serverVal)
			if m == nil {
				continue
			}
			tok := strings.ToLower(m[1])
			switch {
			case cdnServerTokens[tok] != "":
				if cdnFronted == "" {
					cdnFronted, cdnData = cdnServerTokens[tok], serverVal
				}
			case knownServers[tok] != "" && !productSet:
				s.Product, s.Version, productSet = knownServers[tok], m[2], true
				s.Evidence = append(s.Evidence, Finding{Signal: "server.header", Detail: "Server header", Data: serverVal, Confidence: 80, Tier: "high"})
			default:
				if firstUnknown == nil {
					firstUnknown = []string{serverVal, m[1], m[2]}
				}
			}
		}
		// A known origin server wins; otherwise a CDN conceals it; otherwise
		// report the first unrecognised product.
		if !productSet {
			switch {
			case cdnFronted != "":
				s.Evidence = append(s.Evidence, Finding{
					Signal: "server.cdn-fronted", Confidence: 60, Tier: "medium", Data: cdnData,
					Detail: "Server header names a CDN/proxy (" + cdnFronted + "); origin server is concealed",
				})
			case firstUnknown != nil:
				s.Product, s.Version = firstUnknown[1], firstUnknown[2]
				s.Evidence = append(s.Evidence, Finding{Signal: "server.header", Detail: "Server header (unrecognised product)", Data: firstUnknown[0], Confidence: 50, Tier: "medium"})
			}
		}
		for _, ms := range moduleHeaderSigs {
			v := root.HeaderGet(ms.header)
			if v == "" || (ms.contains != "" && !containsFold(v, ms.contains)) {
				continue
			}
			label := ms.label
			switch ms.header {
			case "X-AspNet-Version":
				label = "ASP.NET " + v
			case "X-AspNetMvc-Version":
				label = "ASP.NET MVC " + v
			case "X-Mod-Pagespeed", "X-Page-Speed":
				label = ms.label + " " + v
			}
			addMod(label)
			s.Evidence = append(s.Evidence, Finding{
				Signal: "module." + strings.ToLower(ms.header), Detail: "module/runtime header",
				Data: ms.header + ": " + trim(v), Confidence: 60, Tier: "medium",
			})
		}
	}

	// Error-page fallback / corroboration when the Server header is absent or
	// concealed by a CDN.
	if s.Product == "" {
		for _, r := range all {
			body := r.BodyString()
			if body == "" {
				continue
			}
			if m := reNginxBody.FindStringSubmatch(body); m != nil {
				s.Product, s.Version = "nginx", m[1]
				s.Evidence = append(s.Evidence, Finding{Signal: "server.error-page", Detail: "nginx error-page signature", Confidence: 70, Tier: "high"})
				break
			}
			if m := reApacheBody.FindStringSubmatch(body); m != nil {
				s.Product, s.Version = "Apache", m[1]
				s.Evidence = append(s.Evidence, Finding{Signal: "server.error-page", Detail: "Apache error-page signature", Confidence: 70, Tier: "high"})
				break
			}
			if m := reIISBody.FindStringSubmatch(body); m != nil {
				s.Product, s.Version = "Microsoft IIS", m[1]
				s.Evidence = append(s.Evidence, Finding{Signal: "server.error-page", Detail: "IIS error-page signature", Confidence: 70, Tier: "high"})
				break
			}
			if reLiteSpeedBody.MatchString(body) {
				s.Product = "LiteSpeed"
				s.Evidence = append(s.Evidence, Finding{Signal: "server.error-page", Detail: "LiteSpeed signature", Confidence: 60, Tier: "medium"})
				break
			}
		}
	}

	// WebDAV advertised via the DAV header (typically on an OPTIONS response).
	for _, r := range all {
		if dav := r.HeaderGet("DAV"); dav != "" {
			addMod("WebDAV")
			break
		}
	}

	// nginx-specific enrichment (version recovery, stub_status, X-Accel, Lua).
	enrichNginx(&s, all, addMod)

	sort.Strings(s.Modules)
	sortFindings(s.Evidence)
	return s
}

// enrichNginx adds nginx-specific metadata beyond the Server header: the
// OpenResty Lua runtime, the stub_status module (with its live connection
// counters), X-Accel internal-redirect/offload support, and a version recovered
// from a status or error page when the Server header hid it (server_tokens off).
func enrichNginx(s *ServerInfo, all []*probe.Response, addMod func(string)) {
	nginxFamily := func() bool {
		switch s.Product {
		case "nginx", "OpenResty", "Tengine":
			return true
		default:
			return false
		}
	}

	for _, r := range all {
		for _, h := range nginxAccelHeaders {
			if r.HeaderGet(h) != "" {
				addMod("ngx X-Accel offload")
				if nginxFamily() {
					s.Evidence = append(s.Evidence, Finding{
						Signal: "server.nginx-xaccel", Detail: "nginx X-Accel internal redirect / offload header",
						Data: h, Confidence: 55, Tier: Tier(55),
					})
				}
				break
			}
		}

		body := r.BodyString()
		if body == "" {
			continue
		}
		if reNginxStatus.MatchString(body) {
			if s.Product == "" {
				s.Product = "nginx"
			}
			addMod("ngx_http_stub_status_module")
			s.Evidence = append(s.Evidence, Finding{
				Signal: "server.nginx-stub-status",
				Detail: "nginx stub_status page exposed (live connection counters)",
				Data:   trim(strings.Join(strings.Fields(body), " ")), Confidence: 70, Tier: Tier(70),
			})
		}
		// Recover a hidden version from a status/error page.
		if s.Version == "" && (nginxFamily() || s.Product == "") {
			if m := reNginxVer.FindStringSubmatch(body); m != nil {
				if s.Product == "" {
					s.Product = "nginx"
				}
				s.Version = m[1]
				s.Evidence = append(s.Evidence, Finding{
					Signal: "server.nginx-version-page", Detail: "nginx version recovered from a page body",
					Data: trim(m[0]), Confidence: 60, Tier: Tier(60),
				})
			}
		}
	}

	// OpenResty bundles the LuaJIT runtime; Tengine is Taobao's nginx fork.
	switch s.Product {
	case "OpenResty":
		addMod("LuaJIT (OpenResty)")
	case "Tengine":
		addMod("Tengine (nginx fork)")
	}
}

func proxyNote(p ProxyInfo) string {
	switch {
	case len(p.WAF) > 0:
		return "A WAF / security proxy (" + strings.Join(p.WAF, ", ") + ") is in front: responses may be filtered, challenged or blocked, and the origin is likely concealed and protected."
	case len(p.CDN) > 0:
		return "Served via a CDN (" + strings.Join(p.CDN, ", ") + "): the origin IP and some response headers are likely concealed."
	case len(p.LoadBalancers) > 0:
		return "Behind a load balancer (" + strings.Join(p.LoadBalancers, ", ") + "): responses may come from one of several backends."
	case len(p.Caches) > 0:
		return "A reverse proxy / cache is in front: replies may be cached and the origin server concealed."
	default:
		return ""
	}
}

func serverModules(serverVal string) []string {
	fields := strings.Fields(serverVal)
	var out []string
	for i, tok := range fields {
		if i == 0 {
			continue // product/version
		}
		low := strings.ToLower(tok)
		if strings.HasPrefix(tok, "(") {
			continue // OS hint, handled separately
		}
		if strings.Contains(tok, "/") || strings.HasPrefix(low, "mod_") {
			out = append(out, strings.Trim(tok, "()"))
		}
	}
	return out
}

func osHint(serverVal string) string {
	for _, os := range []string{"Ubuntu", "Debian", "CentOS", "Red Hat", "Fedora", "FreeBSD", "Win64", "Win32", "Unix", "Gentoo", "SUSE", "Alpine", "Amazon"} {
		if strings.Contains(serverVal, "("+os) || strings.Contains(serverVal, os+")") {
			return os
		}
	}
	return ""
}

func namesAbove(m map[string]int, threshold int) []string {
	var out []string
	for name, conf := range m {
		if conf >= threshold {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func cookieMatch(name, want string, prefix bool) bool {
	if prefix {
		return strings.HasPrefix(strings.ToLower(name), strings.ToLower(want))
	}
	return strings.EqualFold(name, want)
}

func containsFold(h, n string) bool { return strings.Contains(strings.ToLower(h), strings.ToLower(n)) }

func trim(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Confidence != fs[j].Confidence {
			return fs[i].Confidence > fs[j].Confidence
		}
		return fs[i].Signal < fs[j].Signal
	})
}
