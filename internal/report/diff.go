package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/rom/qphpscanner/internal/scanner"
)

// DiffResult summarises what changed between two scans.
type DiffResult struct {
	AddedServices   []string        `json:"added_services,omitempty"`
	RemovedServices []string        `json:"removed_services,omitempty"`
	Changed         []ServiceChange `json:"changed,omitempty"`
}

// ServiceChange records a per-service change between two scans.
type ServiceChange struct {
	URL           string   `json:"url"`
	VerdictChange string   `json:"verdict_change,omitempty"`
	VersionChange string   `json:"version_change,omitempty"`
	NewVulns      []string `json:"new_vulns,omitempty"`
	ResolvedVulns []string `json:"resolved_vulns,omitempty"`
}

// Empty reports whether the diff found no changes.
func (d *DiffResult) Empty() bool {
	return len(d.AddedServices) == 0 && len(d.RemovedServices) == 0 && len(d.Changed) == 0
}

type svcSnapshot struct {
	verdict string
	version string
	vulns   map[string]bool
}

func snapshot(res *scanner.ScanResult) map[string]svcSnapshot {
	m := map[string]svcSnapshot{}
	for _, t := range res.Targets {
		for _, s := range t.Services {
			snap := svcSnapshot{vulns: map[string]bool{}}
			if s.PHP != nil {
				snap.verdict = string(s.PHP.Verdict)
				snap.version = s.PHP.Version
				for _, v := range s.PHP.Vulnerabilities {
					snap.vulns[v.ID] = true
				}
			}
			m[s.URL] = snap
		}
	}
	return m
}

// Diff compares an older scan with a newer one.
func Diff(oldRes, newRes *scanner.ScanResult) *DiffResult {
	oldMap := snapshot(oldRes)
	newMap := snapshot(newRes)
	d := &DiffResult{}

	for url := range newMap {
		if _, ok := oldMap[url]; !ok {
			d.AddedServices = append(d.AddedServices, url)
		}
	}
	for url := range oldMap {
		if _, ok := newMap[url]; !ok {
			d.RemovedServices = append(d.RemovedServices, url)
		}
	}
	for url, nw := range newMap {
		od, ok := oldMap[url]
		if !ok {
			continue
		}
		ch := ServiceChange{URL: url}
		if od.verdict != nw.verdict {
			ch.VerdictChange = od.verdict + " → " + nw.verdict
		}
		if od.version != nw.version {
			ch.VersionChange = od.version + " → " + nw.version
		}
		for id := range nw.vulns {
			if !od.vulns[id] {
				ch.NewVulns = append(ch.NewVulns, id)
			}
		}
		for id := range od.vulns {
			if !nw.vulns[id] {
				ch.ResolvedVulns = append(ch.ResolvedVulns, id)
			}
		}
		if ch.VerdictChange != "" || ch.VersionChange != "" || len(ch.NewVulns) > 0 || len(ch.ResolvedVulns) > 0 {
			sort.Strings(ch.NewVulns)
			sort.Strings(ch.ResolvedVulns)
			d.Changed = append(d.Changed, ch)
		}
	}

	sort.Strings(d.AddedServices)
	sort.Strings(d.RemovedServices)
	sort.Slice(d.Changed, func(i, j int) bool { return d.Changed[i].URL < d.Changed[j].URL })
	return d
}

// WriteDiff renders a diff as text or JSON.
func WriteDiff(w io.Writer, d *DiffResult, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(d)
	case "", "text", "txt":
		return writeDiffText(w, d)
	default:
		return fmt.Errorf("unknown diff format %q (want text or json)", format)
	}
}

func writeDiffText(w io.Writer, d *DiffResult) error {
	var b strings.Builder
	b.WriteString("SCAN DIFF\n=========\n")
	if d.Empty() {
		b.WriteString("\nNo changes between scans.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}
	if len(d.AddedServices) > 0 {
		b.WriteString("\nNew services:\n")
		for _, u := range d.AddedServices {
			b.WriteString("  + " + u + "\n")
		}
	}
	if len(d.RemovedServices) > 0 {
		b.WriteString("\nGone services:\n")
		for _, u := range d.RemovedServices {
			b.WriteString("  - " + u + "\n")
		}
	}
	if len(d.Changed) > 0 {
		b.WriteString("\nChanged services:\n")
		for _, c := range d.Changed {
			b.WriteString("  ~ " + c.URL + "\n")
			if c.VerdictChange != "" {
				b.WriteString("      verdict: " + c.VerdictChange + "\n")
			}
			if c.VersionChange != "" {
				b.WriteString("      version: " + c.VersionChange + "\n")
			}
			if len(c.NewVulns) > 0 {
				b.WriteString("      new vulns: " + strings.Join(c.NewVulns, ", ") + "\n")
			}
			if len(c.ResolvedVulns) > 0 {
				b.WriteString("      resolved: " + strings.Join(c.ResolvedVulns, ", ") + "\n")
			}
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// LoadScan reads a previously-saved JSON scan result for diffing.
func LoadScan(data []byte) (*scanner.ScanResult, error) {
	var res scanner.ScanResult
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("parse scan result: %w", err)
	}
	return &res, nil
}

// LoadScanAny reads a previously-saved scan result as either JSON or XML
// (sniffed from the first non-space byte), for diffing an uploaded file.
func LoadScanAny(data []byte) (*scanner.ScanResult, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty scan file")
	}
	if trimmed[0] == '<' {
		var res scanner.ScanResult
		if err := xml.Unmarshal(trimmed, &res); err != nil {
			return nil, fmt.Errorf("parse XML scan result: %w", err)
		}
		return &res, nil
	}
	return LoadScan(trimmed)
}
