package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rom/qphpscanner/internal/php"
	"github.com/rom/qphpscanner/internal/scanner"
)

// DiffResult summarises what changed between two scans. Coverage awareness
// distinguishes a finding that genuinely went away (the endpoint was
// reassessed) from one that simply could not be re-checked (timeout, WAF
// challenge, auth required, or not scanned at all).
type DiffResult struct {
	AddedServices   []string        `json:"added_services,omitempty"`
	RemovedServices []string        `json:"removed_services,omitempty"`
	Changed         []ServiceChange `json:"changed,omitempty"`
	// NotReassessed lists endpoints present in the older scan that the newer
	// scan did not actually re-check, so their absent findings are not claimed
	// as resolved.
	NotReassessed []CoverageItem `json:"not_reassessed,omitempty"`
	// ProvenanceNotes flags differences in how the two scans were run (mode,
	// ports, TLS, auth, catalogue size, …) that can explain result changes.
	ProvenanceNotes []string `json:"provenance_notes,omitempty"`
}

// ServiceChange records a per-service change between two scans.
type ServiceChange struct {
	URL           string   `json:"url"`
	VerdictChange string   `json:"verdict_change,omitempty"`
	VersionChange string   `json:"version_change,omitempty"`
	NewVulns      []string `json:"new_vulns,omitempty"`
	ResolvedVulns []string `json:"resolved_vulns,omitempty"`
	// Coverage is the newer scan's coverage state for this endpoint when it was
	// not a clean response ("challenged", "auth-required", "unreachable").
	Coverage string `json:"coverage,omitempty"`
	// UnconfirmedVulns were present in the older scan but could not be
	// reassessed by the newer one (so they are not reported as resolved).
	UnconfirmedVulns []string `json:"unconfirmed_vulns,omitempty"`
}

// CoverageItem is an endpoint plus why it could not be reassessed.
type CoverageItem struct {
	URL    string `json:"url"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// Empty reports whether the diff found no changes.
func (d *DiffResult) Empty() bool {
	return len(d.AddedServices) == 0 && len(d.RemovedServices) == 0 &&
		len(d.Changed) == 0 && len(d.NotReassessed) == 0
}

type svcSnapshot struct {
	verdict  string
	version  string
	vulns    map[string]bool
	coverage string // responded | auth-required | challenged | unreachable | closed
	reason   string
}

// reassessed reports whether a snapshot represents an endpoint the scan
// actually re-checked (so an absent finding can be trusted as resolved).
func (s svcSnapshot) reassessed() bool {
	return s.coverage == "responded" || s.coverage == "closed"
}

func snapshot(res *scanner.ScanResult) map[string]svcSnapshot {
	m := map[string]svcSnapshot{}
	for _, t := range res.Targets {
		for _, s := range t.Services {
			snap := svcSnapshot{vulns: map[string]bool{}}
			snap.coverage, snap.reason = classifyCoverage(s)
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

// classifyCoverage derives how well a scan actually assessed an endpoint from
// its service record.
func classifyCoverage(s scanner.ServiceResult) (state, reason string) {
	if s.HTTP != nil && s.HTTP.Status > 0 {
		switch {
		case s.HTTP.Status == 401 || s.HTTP.Status == 403:
			return "auth-required", fmt.Sprintf("HTTP %d", s.HTTP.Status)
		case s.HTTP.Status == 429 || s.HTTP.Status == 503:
			return "challenged", fmt.Sprintf("HTTP %d", s.HTTP.Status)
		case s.Proxy != nil && len(s.Proxy.WAF) > 0 && (s.PHP == nil || s.PHP.Verdict == "" || string(s.PHP.Verdict) == "none"):
			return "challenged", "WAF in front (" + strings.Join(s.Proxy.WAF, ", ") + ")"
		case s.Discovery != nil && s.Discovery.Limited == "budget":
			return "budget-limited", "deep-probe request budget exhausted"
		case s.Discovery != nil && s.Discovery.Limited == "retry-after":
			return "challenged", "Retry-After back-off"
		default:
			return "responded", ""
		}
	}
	if !s.PortOpen {
		if strings.Contains(strings.ToLower(s.Error), "refused") {
			return "closed", s.Error
		}
		return "unreachable", firstNonEmpty(s.Error, "port closed/filtered")
	}
	return "unreachable", firstNonEmpty(s.Error, "no HTTP response")
}

// budgetLabel renders a per-service request budget for a provenance note.
func budgetLabel(n int) string {
	if n <= 0 {
		return "unlimited"
	}
	return strconv.Itoa(n)
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// Diff compares an older scan with a newer one.
func Diff(oldRes, newRes *scanner.ScanResult) *DiffResult {
	oldMap := snapshot(oldRes)
	newMap := snapshot(newRes)
	d := &DiffResult{}
	d.ProvenanceNotes = provenanceNotes(oldRes, newRes)

	for url := range newMap {
		if _, ok := oldMap[url]; !ok {
			d.AddedServices = append(d.AddedServices, url)
		}
	}
	for url := range oldMap {
		if _, ok := newMap[url]; !ok {
			// Absent from the newer scan: we have no evidence it was re-checked,
			// so it is "not reassessed", never silently "removed".
			d.NotReassessed = append(d.NotReassessed, CoverageItem{
				URL: url, State: "not-reassessed", Reason: "no result in the newer scan (host/port not covered)",
			})
		}
	}
	for url, nw := range newMap {
		od, ok := oldMap[url]
		if !ok {
			continue
		}
		// Reassessed and found closed → genuinely gone.
		if nw.coverage == "closed" {
			d.RemovedServices = append(d.RemovedServices, url)
			continue
		}
		ch := ServiceChange{URL: url}
		if nw.coverage != "responded" {
			ch.Coverage = nw.coverage
		}
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
			if nw.vulns[id] {
				continue
			}
			// An old finding missing from the newer scan is only "resolved" when
			// the endpoint was actually reassessed; otherwise it is unconfirmed.
			if nw.reassessed() {
				ch.ResolvedVulns = append(ch.ResolvedVulns, id)
			} else {
				ch.UnconfirmedVulns = append(ch.UnconfirmedVulns, id)
			}
		}
		if ch.VerdictChange != "" || ch.VersionChange != "" || len(ch.NewVulns) > 0 ||
			len(ch.ResolvedVulns) > 0 || len(ch.UnconfirmedVulns) > 0 {
			sort.Strings(ch.NewVulns)
			sort.Strings(ch.ResolvedVulns)
			sort.Strings(ch.UnconfirmedVulns)
			d.Changed = append(d.Changed, ch)
		}
	}

	sort.Strings(d.AddedServices)
	sort.Strings(d.RemovedServices)
	sort.Slice(d.NotReassessed, func(i, j int) bool { return d.NotReassessed[i].URL < d.NotReassessed[j].URL })
	sort.Slice(d.Changed, func(i, j int) bool { return d.Changed[i].URL < d.Changed[j].URL })
	return d
}

// provenanceNotes reports differences in how the two scans were configured.
// It returns nil when either scan predates provenance capture (TimeoutMS == 0).
func provenanceNotes(o, n *scanner.ScanResult) []string {
	om, nm := o.Meta, n.Meta
	if om.TimeoutMS == 0 || nm.TimeoutMS == 0 {
		return nil
	}
	var notes []string
	add := func(label, a, b string) {
		if a != b {
			notes = append(notes, label+": "+a+" → "+b)
		}
	}
	yesno := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	add("scan mode", om.Mode, nm.Mode)
	add("TLS mode", om.TLSMode, nm.TLSMode)
	add("ports", strconv.Itoa(len(om.Ports)), strconv.Itoa(len(nm.Ports)))
	add("timeout", (time.Duration(om.TimeoutMS) * time.Millisecond).String(), (time.Duration(nm.TimeoutMS) * time.Millisecond).String())
	add("follow redirects", yesno(om.Follow), yesno(nm.Follow))
	add("ignore TLS errors", yesno(om.Insecure), yesno(nm.Insecure))
	add("auth sent", yesno(om.Auth), yesno(nm.Auth))
	add("connection pinned", yesno(om.Pinned), yesno(nm.Pinned))
	add("allow/block lists", yesno(om.AllowBlock), yesno(nm.AllowBlock))
	add("request budget", budgetLabel(om.RequestBudget), budgetLabel(nm.RequestBudget))
	if om.CatalogPHP != nm.CatalogPHP || om.CatalogCMS != nm.CatalogCMS {
		notes = append(notes, fmt.Sprintf("vuln catalogue: php %d/cms %d → php %d/cms %d",
			om.CatalogPHP, om.CatalogCMS, nm.CatalogPHP, nm.CatalogCMS))
	}
	add("signature packs", signaturePackLabel(om.SignaturePacks), signaturePackLabel(nm.SignaturePacks))
	return notes
}

// signaturePackLabel renders the active signature packs for a provenance note.
func signaturePackLabel(refs []php.PackRef) string {
	if len(refs) == 0 {
		return "built-in only"
	}
	parts := make([]string, 0, len(refs))
	for _, r := range refs {
		parts = append(parts, r.ID+"/"+r.Version)
	}
	return strings.Join(parts, ", ")
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
	if len(d.ProvenanceNotes) > 0 {
		b.WriteString("\nScans differ in how they were run (results may differ for this reason):\n")
		for _, n := range d.ProvenanceNotes {
			b.WriteString("  ! " + n + "\n")
		}
	}
	if d.Empty() {
		if len(d.ProvenanceNotes) == 0 {
			b.WriteString("\nNo changes between scans.\n")
		} else {
			b.WriteString("\nNo per-service changes between scans.\n")
		}
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
		b.WriteString("\nGone services (reassessed, now closed):\n")
		for _, u := range d.RemovedServices {
			b.WriteString("  - " + u + "\n")
		}
	}
	if len(d.NotReassessed) > 0 {
		b.WriteString("\nNot reassessed (absent findings NOT treated as resolved):\n")
		for _, c := range d.NotReassessed {
			line := "  ? " + c.URL
			if c.Reason != "" {
				line += " — " + c.Reason
			}
			b.WriteString(line + "\n")
		}
	}
	if len(d.Changed) > 0 {
		b.WriteString("\nChanged services:\n")
		for _, c := range d.Changed {
			b.WriteString("  ~ " + c.URL + "\n")
			if c.Coverage != "" {
				b.WriteString("      coverage: " + c.Coverage + " (findings not fully reassessed)\n")
			}
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
			if len(c.UnconfirmedVulns) > 0 {
				b.WriteString("      not reassessed: " + strings.Join(c.UnconfirmedVulns, ", ") + "\n")
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
