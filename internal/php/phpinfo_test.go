package php

import (
	"testing"

	"github.com/rom/qphpscanner/internal/probe"
)

// A realistic (trimmed) phpinfo() page covering the general section, a few
// security-relevant directives, a credential-shaped directive, and an Xdebug
// version in the credits line.
const phpinfoFixture = `<html><head><title>phpinfo()</title></head><body>
<h1 class="p">PHP Version 8.2.12</h1>
<table>
<tr><td class="e">System </td><td class="v">Linux web01 5.15.0-91-generic x86_64</td></tr>
<tr><td class="e">Build Date </td><td class="v">Oct 24 2023 21:19:30</td></tr>
<tr><td class="e">Server API </td><td class="v">FPM/FastCGI</td></tr>
<tr><td class="e">Loaded Configuration File </td><td class="v">/etc/php/8.2/fpm/php.ini</td></tr>
<tr><td class="e">Scan this dir for additional .ini files </td><td class="v">/etc/php/8.2/fpm/conf.d</td></tr>
<tr><td class="e">Thread Safety </td><td class="v">disabled</td></tr>
<tr><td class="e">Zend Engine </td><td class="v">v4.2.12</td></tr>
</table>
<h2>Core</h2>
<table>
<tr><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">display_errors</td><td class="v">On</td><td class="v">Off</td></tr>
<tr><td class="e">allow_url_include</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">session.upload_progress.enabled</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">open_basedir</td><td class="v">no value</td><td class="v">no value</td></tr>
</table>
<h2>mysqli</h2>
<table>
<tr><td class="e">mysqli.default_pw</td><td class="v">hunter2</td><td class="v">hunter2</td></tr>
</table>
<i>with Xdebug v3.2.1, Copyright (c) 2002-2023, by Derick Rethans</i>
</body></html>`

func TestParsePHPInfoFacts(t *testing.T) {
	f := parsePHPInfo(phpinfoFixture)
	if f == nil {
		t.Fatal("expected facts from a phpinfo page")
	}
	if f.SAPI != "FPM/FastCGI" {
		t.Errorf("SAPI = %q, want FPM/FastCGI", f.SAPI)
	}
	if f.ThreadSafety != "disabled" {
		t.Errorf("ThreadSafety = %q, want disabled", f.ThreadSafety)
	}
	if f.Architecture != "x86_64" {
		t.Errorf("Architecture = %q, want x86_64", f.Architecture)
	}
	if f.LoadedConfigFile != "/etc/php/8.2/fpm/php.ini" {
		t.Errorf("LoadedConfigFile = %q", f.LoadedConfigFile)
	}
	if f.ScanDir != "/etc/php/8.2/fpm/conf.d" {
		t.Errorf("ScanDir = %q", f.ScanDir)
	}
	if f.ExtensionVersions["Xdebug"] != "3.2.1" {
		t.Errorf("Xdebug version = %q, want 3.2.1", f.ExtensionVersions["Xdebug"])
	}

	// display_errors=On and session.upload_progress.enabled=On are risk-flagged;
	// allow_url_include=Off is captured but not risky.
	risk := map[string]bool{}
	captured := map[string]string{}
	for _, d := range f.Directives {
		risk[d.Name] = d.Risk
		captured[d.Name] = d.Local
	}
	if !risk["display_errors"] {
		t.Error("display_errors=On should be risk-flagged")
	}
	if !risk["session.upload_progress.enabled"] {
		t.Error("session.upload_progress.enabled=On should be risk-flagged")
	}
	if _, ok := captured["allow_url_include"]; !ok {
		t.Error("allow_url_include should be captured")
	}
	if risk["allow_url_include"] {
		t.Error("allow_url_include=Off must not be risk-flagged")
	}

	// A credential-shaped directive value is redacted.
	if captured["mysqli.default_pw"] != "[redacted]" {
		t.Errorf("mysqli.default_pw should be redacted, got %q", captured["mysqli.default_pw"])
	}

	if !containsStr(f.Observations, "PHP-FPM confirmed (SAPI: FPM/FastCGI)") {
		t.Errorf("missing FPM observation: %v", f.Observations)
	}
	if !containsStr(f.Observations, "Xdebug enabled (3.2.1)") {
		t.Errorf("missing Xdebug observation: %v", f.Observations)
	}
}

func TestParsePHPInfoNonPage(t *testing.T) {
	if f := parsePHPInfo("<html><body>just a normal page</body></html>"); f != nil {
		t.Errorf("expected nil facts for a non-phpinfo page, got %+v", f)
	}
}

func TestAnalyzeWiresPHPInfoFacts(t *testing.T) {
	in := Input{
		TargetURL: "http://host/",
		Deep:      true,
		Root:      resp(200, map[string]string{"X-Powered-By": "PHP/8.2.12"}, []string{"PHPSESSID"}, "<html></html>"),
		Extra: map[string]*probe.Response{
			"http://host/phpinfo.php": resp(200, map[string]string{"Content-Type": "text/html"}, nil, phpinfoFixture),
		},
	}
	d := Analyze(in)
	if d == nil || d.PHPInfo == nil {
		t.Fatal("expected PHPInfo facts to be attached")
	}
	if d.PHPInfo.SAPI != "FPM/FastCGI" {
		t.Errorf("observed SAPI not wired through: %q", d.PHPInfo.SAPI)
	}
	// Observed SAPI is kept separate from the inferred SAPI guess.
	if !hasEvidence(d, "phpinfo.sapi") {
		t.Errorf("expected phpinfo.sapi evidence: %+v", d.Evidence)
	}
	if !hasEvidence(d, "phpinfo.directive.display_errors") {
		t.Error("expected a risk observation for display_errors")
	}
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
