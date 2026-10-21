// Package report renders a ScanResult into machine formats (text, JSON, XML)
// and human-readable reports (text, RTF, PDF). The RTF and PDF writers are
// self-contained and add no external dependencies.
package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rom/qphpscanner/internal/php"
	"github.com/rom/qphpscanner/internal/scanner"
	"github.com/rom/qphpscanner/internal/securitytxt"
	"github.com/rom/qphpscanner/internal/webserver"
)

type blockKind int

const (
	kindH1 blockKind = iota
	kindH2
	kindH3
	kindText
	kindKV
	kindBullet
	kindSpacer
	kindRule
)

type block struct {
	kind blockKind
	text string
	key  string
	val  string
}

// document is the format-agnostic representation of a report.
type document struct {
	title  string
	blocks []block
}

func (d *document) h1(s string)     { d.blocks = append(d.blocks, block{kind: kindH1, text: s}) }
func (d *document) h2(s string)     { d.blocks = append(d.blocks, block{kind: kindH2, text: s}) }
func (d *document) h3(s string)     { d.blocks = append(d.blocks, block{kind: kindH3, text: s}) }
func (d *document) text(s string)   { d.blocks = append(d.blocks, block{kind: kindText, text: s}) }
func (d *document) bullet(s string) { d.blocks = append(d.blocks, block{kind: kindBullet, text: s}) }
func (d *document) spacer()         { d.blocks = append(d.blocks, block{kind: kindSpacer}) }
func (d *document) rule()           { d.blocks = append(d.blocks, block{kind: kindRule}) }
func (d *document) kv(k, v string)  { d.blocks = append(d.blocks, block{kind: kindKV, key: k, val: v}) }

// buildDocument turns a scan result into a report document.
func buildDocument(res *scanner.ScanResult) *document {
	d := &document{title: "PHP Service Scan Report"}

	d.h1("PHP Service Scan Report")
	d.kv("Tool", fmt.Sprintf("%s %s", res.Meta.Tool, res.Meta.Version))
	d.kv("Mode", res.Meta.Mode)
	d.kv("Started", res.Meta.StartedAt.Format("2006-01-02 15:04:05 MST"))
	d.kv("Finished", res.Meta.FinishedAt.Format("2006-01-02 15:04:05 MST"))
	d.kv("Duration", fmt.Sprintf("%d ms", res.Meta.DurationMS))
	d.kv("Ports", intsToString(res.Meta.Ports))
	d.spacer()

	d.h2("Summary")
	s := res.Summary
	d.kv("Hosts scanned", fmt.Sprintf("%d", s.HostsScanned))
	d.kv("Services probed", fmt.Sprintf("%d", s.ServicesProbed))
	d.kv("Open ports", fmt.Sprintf("%d", s.OpenPorts))
	d.kv("HTTP services", fmt.Sprintf("%d", s.HTTPServices))
	d.kv("PHP confirmed", fmt.Sprintf("%d", s.PHPConfirmed))
	d.kv("PHP likely", fmt.Sprintf("%d", s.PHPLikely))
	d.kv("PHP possible", fmt.Sprintf("%d", s.PHPPossible))
	d.kv("Vulnerability leads", fmt.Sprintf("%d", s.Vulnerabilities))
	d.kv("security.txt found", fmt.Sprintf("%d", s.SecurityTxt))
	d.spacer()
	d.rule()

	if len(res.Targets) == 0 {
		d.spacer()
		d.text("No open services were found.")
		return d
	}

	for _, t := range res.Targets {
		d.h2("Host: " + t.Host)
		if len(t.Inputs) > 0 {
			d.kv("From targets", strings.Join(sortedCopy(t.Inputs), ", "))
		}
		if len(t.Addresses) > 0 {
			d.kv("Addresses", strings.Join(t.Addresses, ", "))
		}
		if len(t.PTR) > 0 {
			d.kv("Reverse DNS", strings.Join(t.PTR, ", "))
		}
		d.spacer()
		for _, svc := range t.Services {
			renderService(d, svc)
		}
		d.rule()
	}
	return d
}

func renderService(d *document, svc scanner.ServiceResult) {
	d.h3(fmt.Sprintf("%s  (port %d, %s)", svc.URL, svc.Port, schemeLabel(svc)))

	if !svc.PortOpen {
		d.kv("Port", "closed/filtered")
		if svc.Error != "" {
			d.kv("Error", svc.Error)
		}
		d.spacer()
		return
	}

	if svc.Banner != "" {
		d.kv("Banner", svc.Banner)
	}

	if svc.HTTP == nil {
		d.kv("HTTP", "no HTTP response")
		if svc.Error != "" {
			d.kv("Error", svc.Error)
		}
		d.spacer()
		return
	}

	h := svc.HTTP
	d.kv("HTTP status", fmt.Sprintf("%d %s", h.Status, h.Proto))
	if h.FinalURL != "" {
		d.kv("Redirected to", h.FinalURL)
	}
	if h.Server != "" {
		d.kv("Server", h.Server)
	}
	if h.PoweredBy != "" {
		d.kv("X-Powered-By", h.PoweredBy)
	}
	if h.Title != "" {
		d.kv("Title", h.Title)
	}
	if h.TLS != nil {
		d.kv("TLS", fmt.Sprintf("%s (%s)", h.TLS.Version, h.TLS.CipherSuite))
	}
	if proto := httpVersionLabel(h); proto != "" {
		d.kv("HTTP version", proto)
	}
	if h.ALPN != "" {
		d.kv("ALPN", h.ALPN)
	}
	if h.H2C {
		d.kv("h2c", "advertised (cleartext HTTP/2 upgrade offered)")
	}

	renderServer(d, svc.Server)
	renderProxy(d, svc.Proxy)
	renderPHP(d, svc.PHP)
	renderSecurityTxt(d, svc.SecurityTxt)
	d.spacer()
}

func renderServer(d *document, s *webserver.ServerInfo) {
	if s == nil {
		return
	}
	if s.Product != "" {
		v := s.Product
		if s.Version != "" {
			v += " " + s.Version
		}
		d.kv("Web server", v)
	}
	if s.OS != "" {
		d.kv("Server OS hint", s.OS)
	}
	if len(s.Modules) > 0 {
		d.kv("Server modules", strings.Join(s.Modules, ", "))
	}
}

func renderProxy(d *document, p *webserver.ProxyInfo) {
	if p == nil || !p.Present {
		return
	}
	d.kv("Reverse proxy", "YES — origin reply is concealed")
	if len(p.CDN) > 0 {
		d.kv("  CDN", strings.Join(p.CDN, ", "))
	}
	if len(p.WAF) > 0 {
		d.kv("  WAF", strings.Join(p.WAF, ", "))
	}
	if len(p.LoadBalancers) > 0 {
		d.kv("  Load balancer", strings.Join(p.LoadBalancers, ", "))
	}
	if len(p.Caches) > 0 {
		d.kv("  Cache/proxy", strings.Join(p.Caches, ", "))
	}
	if p.Note != "" {
		d.text(p.Note)
	}
}

func renderPHP(d *document, det *php.Detection) {
	if det == nil {
		return
	}
	d.spacer()
	verdict := strings.ToUpper(string(det.Verdict))
	d.kv("PHP verdict", fmt.Sprintf("%s (confidence %d/100)", verdict, det.Confidence))
	if det.Variant != "" {
		d.kv("Variant", det.Variant)
	}
	if det.Version != "" {
		src := det.VersionSource
		if src != "" {
			src = " via " + src
		}
		d.kv("Version", det.Version+src)
	}
	if det.EOLDetail != "" {
		label := det.EOLDetail
		if det.EndOfLife {
			label = "END OF LIFE — " + label
		}
		d.kv("Lifecycle", label)
	}
	if det.SAPI != "" {
		d.kv("SAPI (guess)", det.SAPI)
	}
	if len(det.Frameworks) > 0 {
		d.kv("Frameworks", strings.Join(det.Frameworks, ", "))
	}
	for _, fw := range sortedKeys(det.FrameworkVersions) {
		d.kv("  "+fw+" version", det.FrameworkVersions[fw])
	}
	if len(det.Addons) > 0 {
		d.kv("Addons / tools", strings.Join(det.Addons, ", "))
	}
	if det.FaviconHash != "" {
		d.kv("Favicon hash", det.FaviconHash+" (mmh3)")
	}
	if len(det.Extensions) > 0 {
		d.kv("PHP extensions", strings.Join(det.Extensions, ", "))
	}
	if det.PHPInfoExposed {
		d.kv("phpinfo() exposed", det.PHPInfoURL)
	}

	if len(det.Evidence) > 0 {
		d.text("Evidence:")
		max := len(det.Evidence)
		if max > 10 {
			max = 10
		}
		for _, ev := range det.Evidence[:max] {
			d.bullet(fmt.Sprintf("[%s w%d] %s — %s", ev.Confidence, ev.Weight, ev.Signal, ev.Detail))
			meta := "↳ where: " + ev.Where + "; how: " + ev.How
			if ev.Probe != "" {
				meta += "; probe: " + ev.Probe
			}
			if ev.Pattern != "" {
				meta += "; matcher: " + collapse(ev.Pattern)
			}
			if ev.Line > 0 {
				meta += fmt.Sprintf("; body line %d", ev.Line)
			}
			d.bullet(meta)
			if ev.Snippet != "" {
				d.bullet("↳ match: " + collapse(ev.Snippet))
			}
		}
	}

	if len(det.Vulnerabilities) > 0 {
		d.text(fmt.Sprintf("Version-correlated vulnerability leads (%d):", len(det.Vulnerabilities)))
		for _, v := range det.Vulnerabilities {
			d.bullet(fmt.Sprintf("%s [%s] %s", v.ID, strings.ToUpper(v.Severity), v.Title))
			d.bullet(fmt.Sprintf("    affects %s — %s", v.AffectedVersions, v.MatchBasis))
		}
		d.text("NOTE: vulnerability leads are correlated from the detected version only; confirm each against the live service and configuration.")
	}
}

func renderSecurityTxt(d *document, st *securitytxt.SecurityTxt) {
	if st == nil || !st.Present {
		return
	}
	d.spacer()
	d.kv("security.txt", st.URL)
	if st.Signed {
		d.kv("  signed", "yes (PGP)")
	}
	if len(st.Contact) > 0 {
		d.kv("  contact", strings.Join(st.Contact, ", "))
	}
	if st.Expires != "" {
		exp := st.Expires
		if st.Expired {
			exp += " (EXPIRED)"
		}
		d.kv("  expires", exp)
	}
	if len(st.Policy) > 0 {
		d.kv("  policy", strings.Join(st.Policy, ", "))
	}
	if len(st.Encryption) > 0 {
		d.kv("  encryption", strings.Join(st.Encryption, ", "))
	}
	if len(st.PreferredLanguages) > 0 {
		d.kv("  languages", strings.Join(st.PreferredLanguages, ", "))
	}
	if len(st.Acknowledgments) > 0 {
		d.kv("  acknowledgments", strings.Join(st.Acknowledgments, ", "))
	}
	if len(st.Hiring) > 0 {
		d.kv("  hiring", strings.Join(st.Hiring, ", "))
	}
}

// httpVersionLabel highlights HTTP/2 (the raw proto is already shown on the
// status line, so HTTP/1.x needs no extra row).
func httpVersionLabel(h *scanner.HTTPInfo) string {
	if h.HTTP2 {
		return "HTTP/2 (negotiated)"
	}
	return ""
}

func schemeLabel(svc scanner.ServiceResult) string {
	if svc.TLS {
		return svc.Scheme + "/TLS"
	}
	return svc.Scheme
}

func intsToString(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprintf("%d", x)
	}
	return strings.Join(parts, ",")
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func collapse(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
