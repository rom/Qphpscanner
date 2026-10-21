package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/rom/qphpscanner/internal/php"
	"github.com/rom/qphpscanner/internal/scanner"
)

func composerResult() *scanner.ScanResult {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return &scanner.ScanResult{
		Meta: scanner.Meta{Tool: "qphpscanner", Version: "0.1.0", Mode: "deep", StartedAt: now, FinishedAt: now, Ports: []int{80}},
		Targets: []scanner.TargetResult{{
			Host: "h", Services: []scanner.ServiceResult{{
				Host: "h", Port: 80, Scheme: "http", URL: "http://h:80/", PortOpen: true,
				HTTP: &scanner.HTTPInfo{Status: 200},
				PHP: &php.Detection{
					IsPHP: true, Verdict: php.VerdictConfirmed, Confidence: 90, Variant: "PHP", Version: "8.3.1",
					Composer: &php.ComposerInventory{
						PHPConstraint: "^8.1",
						Sources:       []string{"http://h:80/composer.lock"},
						Packages: []php.ComposerPackage{
							{
								Name: "guzzlehttp/guzzle", Version: "7.4.0", Class: php.ComposerClassInstalled,
								Constraint: "^7.4", Source: "abc123",
								Advisories: []php.Vulnerability{{
									ID: "CVE-2022-31042", Severity: "high", Title: "Guzzle cookie leak",
									AffectedVersions: "7.0.0 – 7.4.3", MatchBasis: "composer-package version-correlation",
								}},
							},
							{Name: "monolog/monolog", Version: "2.3.5", Class: php.ComposerClassLocked},
							{Name: "phpunit/phpunit", Version: "^9.5", Class: php.ComposerClassRequired, Dev: true},
						},
					},
				},
			}},
		}},
		Summary: scanner.Summary{HostsScanned: 1, OpenPorts: 1, HTTPServices: 1, PHPConfirmed: 1},
	}
}

func TestComposerInText(t *testing.T) {
	var b bytes.Buffer
	if err := WriteOutput(&b, composerResult(), "text"); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{"Composer inventory", "php requirement", "^8.1", "guzzlehttp/guzzle 7.4.0", "[installed]", "CVE-2022-31042", "[locked]", "(dev)"} {
		if !strings.Contains(s, want) {
			t.Fatalf("text output missing %q\n%s", want, s)
		}
	}
}

func TestComposerInHTML(t *testing.T) {
	var b bytes.Buffer
	if err := WriteReport(&b, composerResult(), "html"); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if !strings.Contains(s, "Composer inventory") || !strings.Contains(s, "guzzlehttp/guzzle") {
		t.Fatalf("html report missing composer section:\n%s", s)
	}
}

func TestComposerInCSV(t *testing.T) {
	var b bytes.Buffer
	if err := WriteOutput(&b, composerResult(), "csv"); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if !strings.Contains(s, "composer_packages") || !strings.Contains(s, "composer_advisory_leads") {
		t.Fatalf("csv header missing composer columns:\n%s", s)
	}
	// The data row should carry the package count (3) and advisory count (1).
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) < 2 || !strings.Contains(lines[1], ",3,1,") {
		t.Fatalf("csv row missing composer counts:\n%s", s)
	}
}

func TestComposerInSARIF(t *testing.T) {
	var b bytes.Buffer
	if err := WriteOutput(&b, composerResult(), "sarif"); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{"CVE-2022-31042", "composer_package", "guzzlehttp/guzzle"} {
		if !strings.Contains(s, want) {
			t.Fatalf("sarif output missing %q", want)
		}
	}
}

func TestComposerInJSONXML(t *testing.T) {
	var j, x bytes.Buffer
	if err := WriteOutput(&j, composerResult(), "json"); err != nil {
		t.Fatal(err)
	}
	if err := WriteOutput(&x, composerResult(), "xml"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(j.String(), "\"composer\"") || !strings.Contains(j.String(), "php_constraint") {
		t.Fatalf("json missing composer block:\n%s", j.String())
	}
	if !strings.Contains(x.String(), "<composer>") || !strings.Contains(x.String(), "guzzlehttp/guzzle") {
		t.Fatalf("xml missing composer block:\n%s", x.String())
	}
}
