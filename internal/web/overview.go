package web

import (
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/rom/qphpscanner/internal/scanner"
)

// itemRef points back to one scanned service for a tag.
type itemRef struct {
	ScanID string `json:"scan_id"`
	Host   string `json:"host"`
	URL    string `json:"url"`
	At     string `json:"at"`
}

// tagGroup is a framework/addon/vulnerability and the scan items carrying it.
type tagGroup struct {
	Name     string    `json:"name"`
	Severity string    `json:"severity,omitempty"`
	Count    int       `json:"count"`
	Items    []itemRef `json:"items"`
}

// topEntry is one row of a toplist.
type topEntry struct {
	Key      string `json:"key"`
	Count    int    `json:"count"`
	Severity string `json:"severity,omitempty"`
}

type verRef struct {
	Version string `json:"version"`
	Host    string `json:"host"`
	URL     string `json:"url"`
}

type appRef struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Host    string `json:"host"`
	URL     string `json:"url"`
}

type overviewStats struct {
	Scans           int        `json:"scans"`
	Services        int        `json:"services"`
	PHPServices     int        `json:"php_services"`
	HighestSeverity string     `json:"highest_severity"`
	AvgScanMS       int64      `json:"avg_scan_ms"`
	OldestPHP       *verRef    `json:"oldest_php,omitempty"`
	OldestApp       *appRef    `json:"oldest_app,omitempty"`
	TopVulns        []topEntry `json:"top_vulns"`
	TopApps         []topEntry `json:"top_apps"`
	TopNetworks     []topEntry `json:"top_networks"`
	// Breakdowns for charts: vulnerability leads by severity, and PHP-analysed
	// services by verdict.
	SeverityBreakdown map[string]int `json:"severity_breakdown"`
	VerdictBreakdown  map[string]int `json:"verdict_breakdown"`
}

type overview struct {
	Stats      overviewStats `json:"stats"`
	Frameworks []tagGroup    `json:"frameworks"`
	Addons     []tagGroup    `json:"addons"`
	Vulns      []tagGroup    `json:"vulns"`
}

// computeOverview aggregates statistics and tag groups across all retained
// scans. It is safe for concurrent use.
func (s *Server) computeOverview() overview {
	s.mu.Lock()
	items := make([]historyItem, len(s.history))
	copy(items, s.history)
	s.mu.Unlock()

	fw := newTagAgg()
	addon := newTagAgg()
	vuln := newTagAgg()
	vulnSev := map[string]string{}
	appCount := map[string]int{}
	netCount := map[string]int{}

	var stats overviewStats
	stats.SeverityBreakdown = map[string]int{}
	stats.VerdictBreakdown = map[string]int{}
	var durSum int64
	var durN int
	stats.Scans = len(items)

	for _, h := range items {
		res := h.Result
		if res == nil {
			continue
		}
		durSum += res.Meta.DurationMS
		durN++
		for _, t := range res.Targets {
			for _, svc := range t.Services {
				stats.Services++
				net := networkKey(svc.Host)
				netCount[net]++
				ref := itemRef{ScanID: h.ID, Host: svc.Host, URL: svc.URL, At: h.At.Format("2006-01-02 15:04")}
				p := svc.PHP
				if p == nil {
					continue
				}
				if p.Verdict != "none" && p.Verdict != "" {
					stats.PHPServices++
				}
				if v := string(p.Verdict); v != "" {
					stats.VerdictBreakdown[v]++
				}
				for _, f := range p.Frameworks {
					fw.add(f, "", ref)
					appCount[f]++
				}
				for _, a := range p.Addons {
					addon.add(a, "", ref)
				}
				for _, v := range p.Vulnerabilities {
					vuln.add(v.ID, v.Severity, ref)
					vulnSev[v.ID] = v.Severity
					sev := v.Severity
					if sev == "" {
						sev = "unknown"
					}
					stats.SeverityBreakdown[sev]++
					if sevRank(v.Severity) > sevRank(stats.HighestSeverity) {
						stats.HighestSeverity = v.Severity
					}
				}
				considerOldestPHP(&stats, p.Version, svc.Host, svc.URL)
				for name, ver := range p.FrameworkVersions {
					considerOldestApp(&stats, name, ver, svc.Host, svc.URL)
				}
			}
		}
	}

	if durN > 0 {
		stats.AvgScanMS = durSum / int64(durN)
	}
	stats.TopVulns = topFromCountsSev(vuln.counts(), vulnSev, 10)
	stats.TopApps = topFromCounts(appCount, 10)
	stats.TopNetworks = topFromCounts(netCount, 10)

	return overview{
		Stats:      stats,
		Frameworks: fw.groups(),
		Addons:     addon.groups(),
		Vulns:      vuln.groups(),
	}
}

// tagAgg accumulates items per tag, de-duplicating by URL within a tag.
type tagAgg struct {
	order []string
	items map[string][]itemRef
	sev   map[string]string
	seen  map[string]map[string]bool
}

func newTagAgg() *tagAgg {
	return &tagAgg{items: map[string][]itemRef{}, sev: map[string]string{}, seen: map[string]map[string]bool{}}
}

func (a *tagAgg) add(name, severity string, ref itemRef) {
	if name == "" {
		return
	}
	if _, ok := a.items[name]; !ok {
		a.order = append(a.order, name)
		a.seen[name] = map[string]bool{}
	}
	if severity != "" {
		a.sev[name] = severity
	}
	key := ref.ScanID + "\x00" + ref.URL
	if a.seen[name][key] {
		return
	}
	a.seen[name][key] = true
	a.items[name] = append(a.items[name], ref)
}

func (a *tagAgg) counts() map[string]int {
	m := map[string]int{}
	for name, refs := range a.items {
		m[name] = len(refs)
	}
	return m
}

func (a *tagAgg) groups() []tagGroup {
	out := make([]tagGroup, 0, len(a.order))
	for _, name := range a.order {
		out = append(out, tagGroup{Name: name, Severity: a.sev[name], Count: len(a.items[name]), Items: a.items[name]})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func considerOldestPHP(stats *overviewStats, version, host, url string) {
	if version == "" {
		return
	}
	if stats.OldestPHP == nil || versionLess(version, stats.OldestPHP.Version) {
		stats.OldestPHP = &verRef{Version: version, Host: host, URL: url}
	}
}

func considerOldestApp(stats *overviewStats, name, version, host, url string) {
	if version == "" {
		return
	}
	if stats.OldestApp == nil || versionLess(version, stats.OldestApp.Version) {
		stats.OldestApp = &appRef{Name: name, Version: version, Host: host, URL: url}
	}
}

// networkKey groups a host into a network: /24 for IPv4, /48 for IPv6, else the
// registrable-ish parent domain (last two labels).
func networkKey(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return strconv.Itoa(int(v4[0])) + "." + strconv.Itoa(int(v4[1])) + "." + strconv.Itoa(int(v4[2])) + ".0/24"
		}
		return "IPv6"
	}
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	if len(labels) >= 2 {
		return strings.Join(labels[len(labels)-2:], ".")
	}
	return host
}

func topFromCounts(counts map[string]int, limit int) []topEntry {
	return topFromCountsSev(counts, nil, limit)
}

func topFromCountsSev(counts map[string]int, sev map[string]string, limit int) []topEntry {
	out := make([]topEntry, 0, len(counts))
	for k, n := range counts {
		e := topEntry{Key: k, Count: n}
		if sev != nil {
			e.Severity = sev[k]
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func sevRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium", "moderate":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// versionLess reports whether a is an older (lower) dotted version than b.
func versionLess(a, b string) bool {
	as := splitVer(a)
	bs := splitVer(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func splitVer(v string) []int {
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n := 0
		for _, r := range p {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
		}
		out = append(out, n)
	}
	return out
}

// ensure scanner import is used even if the struct shapes change.
var _ = scanner.ScanResult{}
