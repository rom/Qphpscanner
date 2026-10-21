package scanner

import (
	"net"
	"strings"

	"github.com/rom/qphpscanner/internal/target"
)

// filterEndpoints applies the allow/block lists to expanded endpoints. When the
// allowlist is non-empty, only endpoints whose host matches it are kept; then
// any endpoint whose host matches the blocklist is dropped. Dropped counts are
// reported through progress.
func filterEndpoints(eps []target.Endpoint, opts Options) []target.Endpoint {
	allow := compilePatterns(opts.Allowlist)
	block := compilePatterns(opts.Blocklist)
	if len(allow) == 0 && len(block) == 0 {
		return eps
	}
	out := eps[:0:0]
	var droppedAllow, droppedBlock int
	for _, ep := range eps {
		if len(allow) > 0 && !matchAny(ep.Host, allow) {
			droppedAllow++
			continue
		}
		if len(block) > 0 && matchAny(ep.Host, block) {
			droppedBlock++
			continue
		}
		out = append(out, ep)
	}
	if droppedAllow > 0 {
		emitEnum(opts, plural(droppedAllow, "target")+" not on the allow list, skipped")
	}
	if droppedBlock > 0 {
		emitEnum(opts, plural(droppedBlock, "target")+" on the block list, skipped")
	}
	return out
}

func plural(n int, noun string) string {
	s := noun
	if n != 1 {
		s += "s"
	}
	return itoa(n) + " " + s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// pattern is a compiled allow/block entry.
type pattern struct {
	raw    string
	cidr   *net.IPNet
	suffix string // for *.domain / .domain (the base domain, lowercased)
	host   string // exact host/IP, lowercased
}

func compilePatterns(entries []string) []pattern {
	var out []pattern
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		p := pattern{raw: e}
		switch {
		case strings.Contains(e, "/"):
			if _, cidr, err := net.ParseCIDR(e); err == nil {
				p.cidr = cidr
			} else {
				p.host = strings.ToLower(e)
			}
		case strings.HasPrefix(e, "*."):
			p.suffix = strings.ToLower(e[2:])
		case strings.HasPrefix(e, "."):
			p.suffix = strings.ToLower(e[1:])
		default:
			p.host = strings.ToLower(e)
		}
		out = append(out, p)
	}
	return out
}

func matchAny(host string, pats []pattern) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	ip := net.ParseIP(host)
	for _, p := range pats {
		switch {
		case p.cidr != nil:
			if ip != nil && p.cidr.Contains(ip) {
				return true
			}
		case p.suffix != "":
			if h == p.suffix || strings.HasSuffix(h, "."+p.suffix) {
				return true
			}
		default:
			if h == p.host {
				return true
			}
		}
	}
	return false
}
