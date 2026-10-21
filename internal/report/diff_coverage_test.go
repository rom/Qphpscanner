package report

import (
	"strings"
	"testing"

	"github.com/rom/qphpscanner/internal/php"
	"github.com/rom/qphpscanner/internal/scanner"
)

// phpSvc builds a responded PHP service carrying the given vuln IDs.
func phpSvc(url string, status int, vulns ...string) scanner.ServiceResult {
	var vs []php.Vulnerability
	for _, id := range vulns {
		vs = append(vs, php.Vulnerability{ID: id, Severity: "high"})
	}
	return scanner.ServiceResult{
		Host: "h", URL: url, PortOpen: true,
		HTTP: &scanner.HTTPInfo{Status: status},
		PHP:  &php.Detection{Verdict: php.VerdictConfirmed, Vulnerabilities: vs},
	}
}

func oneScan(svcs ...scanner.ServiceResult) *scanner.ScanResult {
	return &scanner.ScanResult{Targets: []scanner.TargetResult{{Host: "h", Services: svcs}}}
}

func changeFor(d *DiffResult, url string) *ServiceChange {
	for i := range d.Changed {
		if d.Changed[i].URL == url {
			return &d.Changed[i]
		}
	}
	return nil
}

func TestDiffAbsentIsNotReassessed(t *testing.T) {
	old := oneScan(phpSvc("https://h/", 200, "CVE-X"))
	nw := oneScan() // the endpoint was not covered at all
	d := Diff(old, nw)
	if len(d.NotReassessed) != 1 || d.NotReassessed[0].URL != "https://h/" {
		t.Fatalf("expected not-reassessed, got %+v", d.NotReassessed)
	}
	if len(d.RemovedServices) != 0 {
		t.Fatalf("an absent endpoint must not be reported 'removed': %v", d.RemovedServices)
	}
	for _, c := range d.Changed {
		if len(c.ResolvedVulns) > 0 {
			t.Fatalf("an unseen finding must not be 'resolved': %+v", c)
		}
	}
}

func TestDiffResolvedWhenReassessed(t *testing.T) {
	old := oneScan(phpSvc("https://h/", 200, "CVE-X"))
	nw := oneScan(phpSvc("https://h/", 200)) // re-checked, vuln gone
	c := changeFor(Diff(old, nw), "https://h/")
	if c == nil || len(c.ResolvedVulns) != 1 || c.ResolvedVulns[0] != "CVE-X" {
		t.Fatalf("expected CVE-X resolved: %+v", c)
	}
	if len(c.UnconfirmedVulns) != 0 {
		t.Fatalf("should not be unconfirmed: %+v", c)
	}
}

func TestDiffChallengedLeavesUnconfirmed(t *testing.T) {
	old := oneScan(phpSvc("https://h/", 200, "CVE-X"))
	chal := scanner.ServiceResult{Host: "h", URL: "https://h/", PortOpen: true, HTTP: &scanner.HTTPInfo{Status: 503}}
	c := changeFor(Diff(old, oneScan(chal)), "https://h/")
	if c == nil {
		t.Fatal("expected a change entry for the challenged endpoint")
	}
	if c.Coverage != "challenged" {
		t.Errorf("coverage = %q, want challenged", c.Coverage)
	}
	if len(c.ResolvedVulns) != 0 {
		t.Errorf("a challenged endpoint must not resolve findings: %+v", c)
	}
	if len(c.UnconfirmedVulns) != 1 || c.UnconfirmedVulns[0] != "CVE-X" {
		t.Errorf("expected CVE-X unconfirmed: %+v", c)
	}
}

func TestDiffUnreachableLeavesUnconfirmed(t *testing.T) {
	old := oneScan(phpSvc("http://h:8080/", 200, "CVE-Y"))
	down := scanner.ServiceResult{Host: "h", URL: "http://h:8080/", PortOpen: false, Error: "dial tcp: i/o timeout"}
	c := changeFor(Diff(old, oneScan(down)), "http://h:8080/")
	if c == nil || c.Coverage != "unreachable" {
		t.Fatalf("expected an unreachable change: %+v", c)
	}
	if len(c.UnconfirmedVulns) != 1 {
		t.Fatalf("expected the vuln left unconfirmed: %+v", c)
	}
}

func TestDiffReassessedClosedIsRemoved(t *testing.T) {
	old := oneScan(phpSvc("http://h:8080/", 200, "CVE-Z"))
	closed := scanner.ServiceResult{Host: "h", URL: "http://h:8080/", PortOpen: false, Error: "connection refused"}
	d := Diff(old, oneScan(closed))
	if len(d.RemovedServices) != 1 || d.RemovedServices[0] != "http://h:8080/" {
		t.Fatalf("a reassessed-and-closed endpoint should be removed: %+v", d)
	}
}

func TestDiffBudgetLimitedLeavesUnconfirmed(t *testing.T) {
	old := oneScan(phpSvc("https://h/", 200, "CVE-B"))
	// A 200 response whose deep-probe schedule was cut short by the budget: the
	// absent finding must not be claimed resolved.
	limited := phpSvc("https://h/", 200)
	limited.Discovery = &scanner.Discovery{ProbesIssued: 3, Budget: 3, Limited: "budget"}
	c := changeFor(Diff(old, oneScan(limited)), "https://h/")
	if c == nil || c.Coverage != "budget-limited" {
		t.Fatalf("expected budget-limited coverage, got %+v", c)
	}
	if len(c.ResolvedVulns) != 0 {
		t.Errorf("budget-limited endpoint must not resolve findings: %+v", c)
	}
	if len(c.UnconfirmedVulns) != 1 || c.UnconfirmedVulns[0] != "CVE-B" {
		t.Errorf("expected CVE-B left unconfirmed: %+v", c)
	}
}

func TestDiffRetryAfterChallenged(t *testing.T) {
	old := oneScan(phpSvc("https://h/", 200, "CVE-R"))
	limited := phpSvc("https://h/", 200)
	limited.Discovery = &scanner.Discovery{ProbesIssued: 3, Limited: "retry-after", RetryAfterMS: 5000}
	c := changeFor(Diff(old, oneScan(limited)), "https://h/")
	if c == nil || c.Coverage != "challenged" {
		t.Fatalf("expected a Retry-After back-off to read as challenged, got %+v", c)
	}
	if len(c.UnconfirmedVulns) != 1 {
		t.Errorf("expected the finding left unconfirmed: %+v", c)
	}
}

func TestDiffBudgetProvenanceNote(t *testing.T) {
	old := oneScan(phpSvc("https://h/", 200))
	nw := oneScan(phpSvc("https://h/", 200))
	old.Meta = scanner.Meta{Mode: "deep", TLSMode: "auto", TimeoutMS: 10000}
	nw.Meta = scanner.Meta{Mode: "deep", TLSMode: "auto", TimeoutMS: 10000, RequestBudget: 10}
	notes := strings.Join(Diff(old, nw).ProvenanceNotes, " | ")
	if !strings.Contains(notes, "request budget: unlimited → 10") {
		t.Errorf("missing request-budget note: %q", notes)
	}
}

func TestDiffSignaturePackProvenanceNote(t *testing.T) {
	old := oneScan(phpSvc("https://h/", 200))
	nw := oneScan(phpSvc("https://h/", 200))
	old.Meta = scanner.Meta{Mode: "deep", TLSMode: "auto", TimeoutMS: 10000}
	nw.Meta = scanner.Meta{Mode: "deep", TLSMode: "auto", TimeoutMS: 10000,
		SignaturePacks: []php.PackRef{{ID: "builtin", Version: "1"}, {ID: "acme", Version: "9.9"}}}
	notes := strings.Join(Diff(old, nw).ProvenanceNotes, " | ")
	if !strings.Contains(notes, "signature packs: built-in only → builtin/1, acme/9.9") {
		t.Errorf("missing signature-pack note: %q", notes)
	}
}

func TestDiffProvenanceNotes(t *testing.T) {
	old := oneScan(phpSvc("https://h/", 200))
	nw := oneScan(phpSvc("https://h/", 200))
	old.Meta = scanner.Meta{Mode: "detect", TLSMode: "auto", TimeoutMS: 10000, CatalogPHP: 40, CatalogCMS: 10}
	nw.Meta = scanner.Meta{Mode: "deep", TLSMode: "auto", TimeoutMS: 10000, CatalogPHP: 45, CatalogCMS: 12}
	notes := strings.Join(Diff(old, nw).ProvenanceNotes, " | ")
	if !strings.Contains(notes, "scan mode: detect → deep") {
		t.Errorf("missing mode note: %q", notes)
	}
	if !strings.Contains(notes, "vuln catalogue") {
		t.Errorf("missing catalogue note: %q", notes)
	}
}

func TestDiffNoProvenanceForOldScans(t *testing.T) {
	// TimeoutMS == 0 on a side (older saved scan) → no provenance notes, and the
	// coverage logic still resolves a genuinely reassessed-and-gone finding.
	d := Diff(oneScan(phpSvc("https://h/", 200, "CVE-X")), oneScan(phpSvc("https://h/", 200)))
	if len(d.ProvenanceNotes) != 0 {
		t.Errorf("expected no provenance notes for pre-provenance scans: %v", d.ProvenanceNotes)
	}
	c := changeFor(d, "https://h/")
	if c == nil || len(c.ResolvedVulns) != 1 {
		t.Fatalf("expected the vuln resolved: %+v", c)
	}
}
