package php

import "testing"

const sampleComposerJSON = `{"require":{"php":"^8.1","guzzlehttp/guzzle":"^7.4","ext-mbstring":"*"},"require-dev":{"phpunit/phpunit":"^9.5"}}`
const sampleComposerLock = `{"_readme":["x"],"content-hash":"abc","packages":[{"name":"guzzlehttp/guzzle","version":"7.4.4"},{"name":"phpmailer/phpmailer","version":"v6.9.1"}],"packages-dev":[{"name":"phpunit/phpunit","version":"9.5.0"}]}`
const sampleInstalled = `{"packages":[{"name":"guzzlehttp/guzzle","version":"7.4.4","version_normalized":"7.4.4.0"}],"dev-package-names":[]}`

func pkgByName(inv *ComposerInventory, name string) *ComposerPackage {
	if inv == nil {
		return nil
	}
	for i := range inv.Packages {
		if inv.Packages[i].Name == name {
			return &inv.Packages[i]
		}
	}
	return nil
}

func TestBuildComposerInventory(t *testing.T) {
	inv := buildComposerInventory(sampleComposerJSON, sampleComposerLock, "")
	if inv == nil {
		t.Fatal("nil inventory")
	}
	// The php platform constraint is kept separate, not treated as a package.
	if inv.PHPRequire != "^8.1" {
		t.Errorf("PHPRequire = %q, want ^8.1", inv.PHPRequire)
	}
	if pkgByName(inv, "php") != nil || pkgByName(inv, "ext-mbstring") != nil {
		t.Error("platform requirements must not appear as packages")
	}
	// A locked concrete version outranks the declared constraint; leading "v" is
	// stripped.
	g := pkgByName(inv, "guzzlehttp/guzzle")
	if g == nil || g.Version != "7.4.4" || g.Class != "locked" {
		t.Fatalf("guzzle: %+v", g)
	}
	pm := pkgByName(inv, "phpmailer/phpmailer")
	if pm == nil || pm.Version != "6.9.1" {
		t.Fatalf("phpmailer (v-stripped): %+v", pm)
	}
}

func TestComposerInstalledOutranksLocked(t *testing.T) {
	inv := buildComposerInventory(sampleComposerJSON, sampleComposerLock, sampleInstalled)
	g := pkgByName(inv, "guzzlehttp/guzzle")
	if g == nil || g.Class != "installed" {
		t.Fatalf("installed should outrank locked: %+v", g)
	}
}

func TestComposerMalformed(t *testing.T) {
	if inv := buildComposerInventory("{not json", "also bad", ""); inv != nil {
		t.Errorf("malformed input should yield nil, got %+v", inv)
	}
}

func TestClassifyComposer(t *testing.T) {
	cases := map[string]string{
		sampleComposerJSON:                 "json",
		sampleComposerLock:                 "lock",
		sampleInstalled:                    "installed",
		`[{"name":"a/b","version":"1.0"}]`: "installed",
		"":                                 "",
	}
	for body, want := range cases {
		if got := classifyComposer(body); got != want {
			t.Errorf("classifyComposer(%.30q) = %q, want %q", body, got, want)
		}
	}
}

func TestComposerPackageAdvisories(t *testing.T) {
	c := DefaultCatalog()
	if !hasVulnID(c.CorrelatePackage("guzzlehttp/guzzle", "7.4.4"), "CVE-2022-31090") {
		t.Error("guzzle 7.4.4 should match CVE-2022-31090")
	}
	if hasVulnID(c.CorrelatePackage("guzzlehttp/guzzle", "7.4.5"), "CVE-2022-31090") {
		t.Error("guzzle 7.4.5 should be patched")
	}
	if len(c.CorrelatePackage("unknown/package", "1.0.0")) != 0 {
		t.Error("an unknown package should have no leads")
	}
}

func TestComposerPackageFeedMerge(t *testing.T) {
	c := DefaultCatalog()
	c.Merge(&VulnFeed{
		Schema: FeedSchema,
		Packages: map[string][]FeedEntry{
			"acme/widget": {{ID: "CVE-ACME-1", Severity: "high", Title: "t", Affected: []RangeSpec{lo("2.0.0")}}},
		},
	})
	if !hasVulnID(c.CorrelatePackage("acme/widget", "1.5.0"), "CVE-ACME-1") {
		t.Error("a merged external package advisory should correlate")
	}
	if hasVulnID(c.CorrelatePackage("acme/widget", "2.0.0"), "CVE-ACME-1") {
		t.Error("2.0.0 should be out of range")
	}
}

func TestComposerSuppliedFilesViaAnalyze(t *testing.T) {
	in := Input{
		TargetURL:     "http://host/",
		Deep:          true,
		Root:          resp(200, map[string]string{"X-Powered-By": "PHP/8.2.0"}, []string{"PHPSESSID"}, "<html></html>"),
		ComposerFiles: [][]byte{[]byte(sampleComposerJSON), []byte(sampleComposerLock)},
	}
	d := Analyze(in)
	if d == nil || d.Composer == nil {
		t.Fatal("expected a Composer inventory from supplied files")
	}
	if d.Composer.PHPRequire != "^8.1" {
		t.Errorf("PHPRequire not captured: %q", d.Composer.PHPRequire)
	}
	// The Composer php constraint must not leak into the detected runtime version.
	if d.Version == "^8.1" {
		t.Error("Composer php constraint leaked into runtime Version")
	}
	g := pkgByName(d.Composer, "guzzlehttp/guzzle")
	if g == nil || len(g.Vulnerabilities) == 0 {
		t.Fatalf("guzzle 7.4.4 should carry an advisory lead: %+v", g)
	}
}
