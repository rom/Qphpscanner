package php

import (
	"testing"

	"github.com/rom/qphpscanner/internal/probe"
)

func findLead(vs []Vulnerability, id string) *Vulnerability {
	for i := range vs {
		if vs[i].ID == id {
			return &vs[i]
		}
	}
	return nil
}

func TestVersionObservationsAndConflict(t *testing.T) {
	in := Input{
		TargetURL: "http://host/",
		Deep:      true,
		Root:      resp(200, map[string]string{"X-Powered-By": "PHP/7.4.3"}, []string{"PHPSESSID"}, "<html></html>"),
		Extra: map[string]*probe.Response{
			// An exposed phpinfo reports a different major.minor.
			"http://host/phpinfo.php": resp(200, map[string]string{"Content-Type": "text/html"}, nil,
				"<title>phpinfo()</title><h1>PHP Version 8.2.1</h1>Zend Engine"),
		},
	}
	d := Analyze(in)
	if d == nil {
		t.Fatal("nil detection")
	}
	if len(d.VersionObservations) < 2 {
		t.Fatalf("expected >=2 version observations, got %+v", d.VersionObservations)
	}
	if !d.VersionConflict {
		t.Errorf("expected a version conflict (7.4 vs 8.2): %+v", d.VersionObservations)
	}
	// phpinfo (rank 3) outranks the header, so it is the headline version.
	if d.Version != "8.2.1" {
		t.Errorf("headline version = %q, want 8.2.1", d.Version)
	}
}

func TestVersionDistroSuffixPreserved(t *testing.T) {
	in := Input{
		TargetURL: "http://host/",
		Root:      resp(200, map[string]string{"X-Powered-By": "PHP/7.4.33-1+deb11u3"}, []string{"PHPSESSID"}, "<html></html>"),
	}
	d := Analyze(in)
	if d == nil || d.Version != "7.4.33-1+deb11u3" {
		t.Fatalf("distro suffix not preserved: %q", d.Version)
	}
}

func TestPrereqSAPIResolution(t *testing.T) {
	c := DefaultCatalog()
	const v = "8.1.5" // in range for CVE-2024-4577

	// apache2handler is mod_php, not php-cgi → the SAPI prereq is contradicted.
	lead := findLead(c.CorrelatePHP("PHP", v, ObservedFacts{PHPInfoSAPI: "apache2handler"}), "CVE-2024-4577")
	if lead == nil {
		t.Fatal("CVE-2024-4577 should still be a lead (never dropped)")
	}
	if lead.Applicability != "contradicted" {
		t.Errorf("apache2handler → applicability %q, want contradicted", lead.Applicability)
	}

	// php-cgi on Windows → both prereqs observed.
	lead = findLead(c.CorrelatePHP("PHP", v, ObservedFacts{PHPInfoSAPI: "cgi-fcgi", System: "Windows NT HOST 10.0"}), "CVE-2024-4577")
	if lead == nil || lead.Applicability != "observed" {
		t.Fatalf("php-cgi/Windows → applicability %q, want observed", applOf(lead))
	}

	// No SAPI/OS evidence → unknown, left as a plain lead.
	lead = findLead(c.CorrelatePHP("PHP", v), "CVE-2024-4577")
	if lead == nil || lead.Applicability != "" {
		t.Fatalf("no evidence → applicability %q, want empty", applOf(lead))
	}

	// The ambiguous inferred "php-cgi/php-fpm" must not contradict.
	lead = findLead(c.CorrelatePHP("PHP", v, ObservedFacts{SAPI: "php-cgi/php-fpm (PATH_INFO enabled)"}), "CVE-2024-4577")
	if lead == nil || lead.Applicability == "contradicted" {
		t.Fatalf("ambiguous SAPI must not contradict: %q", applOf(lead))
	}
}

func TestPrereqConfigResolution(t *testing.T) {
	c := DefaultCatalog()
	const v = "8.3.1" // php2shell range

	off := findLead(c.CorrelatePHP("PHP", v, ObservedFacts{Directives: map[string]string{"session.upload_progress.enabled": "off"}}), "CVE-2026-109618")
	if off == nil || off.Applicability != "contradicted" {
		t.Fatalf("upload_progress off → applicability %q, want contradicted", applOf(off))
	}
	on := findLead(c.CorrelatePHP("PHP", v, ObservedFacts{Directives: map[string]string{"session.upload_progress.enabled": "on"}}), "CVE-2026-109618")
	if on == nil || on.Applicability != "observed" {
		t.Fatalf("upload_progress on → applicability %q, want observed", applOf(on))
	}
	unk := findLead(c.CorrelatePHP("PHP", v), "CVE-2026-109618")
	if unk == nil || unk.Applicability != "" {
		t.Fatalf("no directive evidence → applicability %q, want empty", applOf(unk))
	}
}

func applOf(v *Vulnerability) string {
	if v == nil {
		return "<nil lead>"
	}
	return v.Applicability
}
