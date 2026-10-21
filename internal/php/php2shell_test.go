package php

import (
	"testing"

	"github.com/rom/qphpscanner/internal/probe"
)

func hasVuln(d *Detection, id string) bool {
	for _, v := range d.Vulnerabilities {
		if v.ID == id {
			return true
		}
	}
	return false
}

func analyzeVersion(t *testing.T, version string) *Detection {
	t.Helper()
	in := Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      resp(200, map[string]string{"X-Powered-By": "PHP/" + version}, nil, "<html></html>"),
	}
	d := Analyze(in)
	if d == nil {
		t.Fatal("nil detection")
	}
	return d
}

func TestPHP2ShellCorrelation(t *testing.T) {
	// Vulnerable: within an unpatched 8.3 branch.
	d := analyzeVersion(t, "8.3.0")
	if !hasVuln(d, "CVE-2026-109618") || !hasVuln(d, "CVE-2026-109619") {
		t.Fatalf("8.3.0 should flag both php2shell CVEs, got %+v", vulnIDs(d))
	}
	// Vulnerable: an EOL branch below 8.2 (no fix).
	if d := analyzeVersion(t, "7.4.33"); !hasVuln(d, "CVE-2026-109618") {
		t.Errorf("7.4.33 should flag php2shell, got %v", vulnIDs(d))
	}
	// Patched: at/after the fixed 8.3 release.
	if d := analyzeVersion(t, "8.3.36"); hasVuln(d, "CVE-2026-109618") {
		t.Errorf("8.3.36 is patched, should not flag php2shell")
	}
	// Patched: a future 8.5 past the fix.
	if d := analyzeVersion(t, "8.5.20"); hasVuln(d, "CVE-2026-109619") {
		t.Errorf("8.5.20 is past the fix, should not flag php2shell")
	}
	// The lead should surface its mitigation note.
	d = analyzeVersion(t, "8.4.0")
	var found bool
	for _, v := range d.Vulnerabilities {
		if v.ID == "CVE-2026-109618" {
			found = true
			if v.Severity != "critical" {
				t.Errorf("php2shell severity = %q, want critical", v.Severity)
			}
		}
	}
	if !found {
		t.Error("8.4.0 should flag CVE-2026-109618")
	}
}

func vulnIDs(d *Detection) []string {
	var out []string
	for _, v := range d.Vulnerabilities {
		out = append(out, v.ID)
	}
	return out
}

func TestMediaWikiAndTYPO3Versions(t *testing.T) {
	in := Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root: resp(200, nil, nil,
			`<meta name="generator" content="MediaWiki 1.39.4"/>`),
	}
	d := Analyze(in)
	if d.FrameworkVersions["MediaWiki"] != "1.39.4" {
		t.Errorf("MediaWiki version = %q", d.FrameworkVersions["MediaWiki"])
	}

	in2 := Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      resp(200, nil, nil, `<meta name="generator" content="TYPO3 CMS 12.4.8">`),
	}
	d2 := Analyze(in2)
	if d2.FrameworkVersions["TYPO3"] != "12.4.8" {
		t.Errorf("TYPO3 version = %q", d2.FrameworkVersions["TYPO3"])
	}
}

func TestMoreAppSignatures(t *testing.T) {
	cases := map[string]string{
		"Mautic":           `<script src="/mtc.js"></script> mauticForm`,
		"SPIP":             `<!-- Composed with SPIP --> <a href="spip.php?article1">`,
		"EspoCRM":          `<div id="espocrm">EspoCRM</div>`,
		"Zen Cart":         `<a href="index.php?main_page=index&zenid=abc">Zen Cart</a>`,
		"ExpressionEngine": `Powered by EE — ExpressionEngine`,
	}
	for want, body := range cases {
		d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, map[string]string{"X-Powered-By": "PHP/8.2.0"}, nil, body)})
		if !hasStr(d.Frameworks, want) {
			t.Errorf("expected framework %q from body %q, got %v", want, body, d.Frameworks)
		}
	}
}

func TestPHPVersionHeaderEvidence(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, map[string]string{"X-Php-Version": "8.2.1"}, nil, "x")})
	if _, ok := findEv(d, "header.x-php-version"); !ok {
		t.Errorf("X-Php-Version should be evidence: %+v", d.Evidence)
	}
}

var _ = probe.Response{}
