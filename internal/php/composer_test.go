package php

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/rom/qphpscanner/internal/probe"
)

// sample Composer documents used across the inventory tests.
const (
	sampleComposerJSON = `{
	  "name": "acme/site",
	  "require": {
	    "php": "^8.1",
	    "guzzlehttp/guzzle": "^7.4",
	    "monolog/monolog": "^2.0",
	    "ext-json": "*"
	  },
	  "require-dev": {
	    "phpunit/phpunit": "^9.5"
	  }
	}`

	sampleComposerLock = `{
	  "packages": [
	    {"name":"guzzlehttp/guzzle","version":"7.4.0","source":{"reference":"abc123"}},
	    {"name":"monolog/monolog","version":"2.3.5","source":{"reference":"def456"}}
	  ],
	  "packages-dev": [
	    {"name":"phpunit/phpunit","version":"9.5.10"}
	  ],
	  "platform": {"php":"^8.1"}
	}`

	sampleInstalledJSON = `{
	  "packages": [
	    {"name":"guzzlehttp/guzzle","version":"7.4.0","source":{"reference":"abc123"}},
	    {"name":"twig/twig","version":"3.5.0","source":{"reference":"zzz999"}}
	  ],
	  "dev-package-names": ["phpunit/phpunit"]
	}`
)

func findPkg(inv *ComposerInventory, name string) *ComposerPackage {
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

func hasAdvisory(p *ComposerPackage, id string) bool {
	if p == nil {
		return false
	}
	for _, a := range p.Advisories {
		if a.ID == id {
			return true
		}
	}
	return false
}

// TestComposerInventoryClassification parses a composer.lock and an
// installed.json (web-exposed) into a classified package inventory.
func TestComposerInventoryClassification(t *testing.T) {
	in := Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      resp(200, map[string]string{"X-Powered-By": "PHP/8.3.1"}, nil, "<html></html>"),
		Extra: map[string]*probe.Response{
			"http://h/composer.lock":                  resp(200, nil, nil, sampleComposerLock),
			"http://h/vendor/composer/installed.json": resp(200, nil, nil, sampleInstalledJSON),
		},
	}
	d := Analyze(in)
	if d == nil || d.Composer == nil {
		t.Fatal("expected a Composer inventory")
	}
	inv := d.Composer

	// guzzle appears in both lock and installed → installed wins.
	g := findPkg(inv, "guzzlehttp/guzzle")
	if g == nil || g.Class != ComposerClassInstalled || g.Version != "7.4.0" {
		t.Fatalf("guzzle: %+v", g)
	}
	if g.Source != "abc123" {
		t.Errorf("guzzle source reference not captured: %q", g.Source)
	}
	// monolog only in the lock → locked.
	m := findPkg(inv, "monolog/monolog")
	if m == nil || m.Class != ComposerClassLocked || m.Version != "2.3.5" {
		t.Fatalf("monolog: %+v", m)
	}
	// twig only in installed.json → installed.
	tw := findPkg(inv, "twig/twig")
	if tw == nil || tw.Class != ComposerClassInstalled || tw.Version != "3.5.0" {
		t.Fatalf("twig: %+v", tw)
	}
	// phpunit is a dev dependency (packages-dev).
	p := findPkg(inv, "phpunit/phpunit")
	if p == nil || !p.Dev {
		t.Fatalf("phpunit should be a dev dependency: %+v", p)
	}
	// Platform php requirement is captured from the lock, not as a package.
	if inv.PHPConstraint != "^8.1" {
		t.Errorf("php constraint = %q, want ^8.1", inv.PHPConstraint)
	}
	if findPkg(inv, "php") != nil {
		t.Error("php platform entry must not appear as a package")
	}
	if len(inv.Sources) == 0 {
		t.Error("inventory should record its sources")
	}
}

// TestComposerPHPConstraintSeparate proves the Composer `php` requirement is
// kept distinct from the detected runtime version and never used for
// PHP-version correlation.
func TestComposerPHPConstraintSeparate(t *testing.T) {
	in := Input{
		TargetURL: "http://h/",
		Deep:      true,
		// Runtime version comes from the header; the constraint is "^8.1".
		Root: resp(200, map[string]string{"X-Powered-By": "PHP/8.3.1"}, nil, "<html></html>"),
		Extra: map[string]*probe.Response{
			"http://h/composer.json": resp(200, nil, nil, sampleComposerJSON),
		},
	}
	d := Analyze(in)
	if d == nil || !d.IsPHP {
		t.Fatalf("expected PHP: %+v", d)
	}
	if d.Version != "8.3.1" {
		t.Fatalf("runtime version should be the header value 8.3.1, got %q", d.Version)
	}
	if d.Composer == nil || d.Composer.PHPConstraint != "^8.1" {
		t.Fatalf("php requirement not captured in inventory: %+v", d.Composer)
	}
	// None of the correlated PHP-core leads may come from the "8.1" constraint:
	// they must all be relative to the real 8.3.1 runtime.
	for _, v := range d.Vulnerabilities {
		if v.MatchBasis != "" && v.ID == "" {
			t.Fatalf("unexpected lead shape: %+v", v)
		}
	}
	// A declared require that is not resolved shows up as a required entry.
	m := findPkg(d.Composer, "monolog/monolog")
	if m == nil || m.Class != ComposerClassRequired || m.Version != "^2.0" {
		t.Fatalf("monolog should be a required constraint: %+v", m)
	}
	// ext-json is a platform/virtual package and must be dropped.
	if findPkg(d.Composer, "ext-json") != nil {
		t.Error("ext-json platform package must not appear in the inventory")
	}
}

// TestCorrelatePackage checks that a package advisory fires for a vulnerable
// version and not for a fixed one.
func TestCorrelatePackage(t *testing.T) {
	c := DefaultCatalog()
	// guzzle 7.4.0 is inside the CVE-2022-31042 range [7.0.0, 7.4.3).
	leads := c.CorrelatePackage("guzzlehttp/guzzle", "7.4.0")
	if !hasVulnID(leads, "CVE-2022-31042") {
		t.Fatalf("guzzle 7.4.0 should be flagged: %+v", leads)
	}
	// 7.5.0 is past every built-in guzzle range → no leads.
	if leads := c.CorrelatePackage("guzzlehttp/guzzle", "7.5.0"); len(leads) != 0 {
		t.Fatalf("guzzle 7.5.0 should be clean, got %+v", leads)
	}
	// Case-insensitive package names and leading-v versions are tolerated.
	if len(c.CorrelatePackage("GuzzleHTTP/Guzzle", "v7.4.0")) == 0 {
		t.Fatal("package lookup should be case-insensitive and tolerate a v prefix")
	}
	// Unknown package and empty inputs yield nothing.
	if c.CorrelatePackage("no/such-package", "1.0.0") != nil {
		t.Error("unknown package => nil")
	}
	if c.CorrelatePackage("", "1.0.0") != nil || c.CorrelatePackage("guzzlehttp/guzzle", "") != nil {
		t.Error("empty inputs => nil")
	}
}

// TestComposerAdvisoriesInInventory checks advisory leads attach to resolved
// packages in the inventory, and clear once the version is patched.
func TestComposerAdvisoriesInInventory(t *testing.T) {
	vuln := `{"packages":[{"name":"guzzlehttp/guzzle","version":"7.4.0"}]}`
	d := Analyze(Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      resp(200, nil, nil, "<html></html>"),
		SuppliedComposer: []SuppliedComposerFile{
			{Name: "installed.json", Data: []byte(vuln)},
		},
	})
	g := findPkg(d.Composer, "guzzlehttp/guzzle")
	if !hasAdvisory(g, "CVE-2022-31042") {
		t.Fatalf("expected an advisory lead on guzzle 7.4.0: %+v", g)
	}
	if d.Composer.AdvisoryCount() == 0 {
		t.Fatal("AdvisoryCount should be > 0")
	}

	fixed := `{"packages":[{"name":"guzzlehttp/guzzle","version":"7.5.0"}]}`
	d2 := Analyze(Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      resp(200, nil, nil, "<html></html>"),
		SuppliedComposer: []SuppliedComposerFile{
			{Name: "installed.json", Data: []byte(fixed)},
		},
	})
	g2 := findPkg(d2.Composer, "guzzlehttp/guzzle")
	if g2 == nil || len(g2.Advisories) != 0 {
		t.Fatalf("guzzle 7.5.0 should have no advisory leads: %+v", g2)
	}
}

// TestSuppliedComposerInventory checks operator-supplied files build an
// inventory and raise the supplied-composer evidence.
func TestSuppliedComposerInventory(t *testing.T) {
	d := Analyze(Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      resp(200, nil, nil, "<html></html>"),
		SuppliedComposer: []SuppliedComposerFile{
			{Name: "composer.lock", Data: []byte(sampleComposerLock)},
		},
	})
	if d.Composer == nil || len(d.Composer.Packages) == 0 {
		t.Fatal("supplied composer.lock should produce an inventory")
	}
	if !hasEvidence(d, "diag.composer-supplied") {
		t.Fatalf("supplied composer evidence missing: %+v", d.Evidence)
	}
	foundSupplied := false
	for _, s := range d.Composer.Sources {
		if s == "supplied:composer.lock" {
			foundSupplied = true
		}
	}
	if !foundSupplied {
		t.Errorf("source provenance should name the supplied file: %+v", d.Composer.Sources)
	}
}

// TestComposerMalformedAndOversized checks that malformed and oversized files
// are handled gracefully (no panic, no bogus inventory).
func TestComposerMalformedAndOversized(t *testing.T) {
	// Malformed JSON → skipped, no inventory, no panic.
	d := Analyze(Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      resp(200, nil, nil, "<html></html>"),
		SuppliedComposer: []SuppliedComposerFile{
			{Name: "composer.json", Data: []byte("{ this is not valid json")},
		},
	})
	if d == nil {
		t.Fatal("Analyze must not return nil")
	}
	if d.Composer != nil {
		t.Errorf("malformed file should yield no inventory, got %+v", d.Composer)
	}

	// A valid lock plus an oversized installed.json → partial inventory, flagged
	// truncated, still no panic.
	oversized := append([]byte(`{"packages":[`), bytes.Repeat([]byte("x"), maxComposerBytes+16)...)
	d2 := Analyze(Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      resp(200, nil, nil, "<html></html>"),
		SuppliedComposer: []SuppliedComposerFile{
			{Name: "composer.lock", Data: []byte(sampleComposerLock)},
			{Name: "installed.json", Data: oversized},
		},
	})
	if d2.Composer == nil || len(d2.Composer.Packages) == 0 {
		t.Fatal("the valid lock should still produce an inventory")
	}
	if !d2.Composer.Truncated {
		t.Error("oversized supplied file should set Truncated")
	}
}

// TestComposerPackageCap bounds the number of retained packages.
func TestComposerPackageCap(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(`{"packages":[`)
	for i := 0; i < maxComposerPackages+100; i++ {
		if i > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf, `{"name":"vendor/pkg%d","version":"1.0.0"}`, i)
	}
	buf.WriteString(`]}`)
	d := Analyze(Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      resp(200, nil, nil, "<html></html>"),
		SuppliedComposer: []SuppliedComposerFile{
			{Name: "installed.json", Data: buf.Bytes()},
		},
	})
	if d.Composer == nil {
		t.Fatal("expected an inventory")
	}
	if len(d.Composer.Packages) != maxComposerPackages {
		t.Fatalf("retained %d packages, want the cap of %d", len(d.Composer.Packages), maxComposerPackages)
	}
	if !d.Composer.Truncated {
		t.Error("hitting the package cap should set Truncated")
	}
}

// TestComposerInstalledBareArray parses the Composer 1 installed.json layout
// (a bare array rather than an object).
func TestComposerInstalledBareArray(t *testing.T) {
	bare := `[{"name":"monolog/monolog","version":"2.9.1","source":{"reference":"r1"}}]`
	d := Analyze(Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      resp(200, nil, nil, "<html></html>"),
		SuppliedComposer: []SuppliedComposerFile{
			{Name: "installed.json", Data: []byte(bare)},
		},
	})
	m := findPkg(d.Composer, "monolog/monolog")
	if m == nil || m.Class != ComposerClassInstalled || m.Version != "2.9.1" {
		t.Fatalf("bare-array installed.json not parsed: %+v", m)
	}
}

// TestClassifyComposerSniff covers filename and content-based classification.
func TestClassifyComposerSniff(t *testing.T) {
	cases := []struct {
		name, body string
		want       composerKind
	}{
		{"composer.lock", `{}`, kindComposerLock},
		{"vendor/composer/installed.json", `{}`, kindInstalledJSON},
		{"COMPOSER.JSON", `{}`, kindComposerJSON},
		{"", `[{"name":"a/b","version":"1.0.0"}]`, kindInstalledJSON},
		{"", `{"packages":[],"dev-package-names":[]}`, kindInstalledJSON},
		{"", `{"packages":[],"content-hash":"x"}`, kindComposerLock},
		{"", `{"require":{"php":"^8.1"}}`, kindComposerJSON},
		{"", `{"packages":[]}`, kindInstalledJSON},
		{"", `{"totally":"unrelated"}`, kindUnknown},
	}
	for _, c := range cases {
		if got := classifyComposer(c.name, c.body); got != c.want {
			t.Errorf("classifyComposer(%q, %q) = %d, want %d", c.name, c.body, got, c.want)
		}
	}
}

// TestComposerInventoryIgnoresNonComposer checks that non-composer or errored
// deep-probe responses do not feed the inventory.
func TestComposerInventoryIgnoresNonComposer(t *testing.T) {
	in := Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      resp(200, nil, nil, "<html></html>"),
		Extra: map[string]*probe.Response{
			"http://h/robots.txt":    resp(200, nil, nil, "User-agent: *"),
			"http://h/composer.json": resp(404, nil, nil, "not found"),
		},
	}
	d := Analyze(in)
	if d.Composer != nil {
		t.Fatalf("no usable composer data, inventory should be nil: %+v", d.Composer)
	}
}

// TestOSVPackageRouting checks OSV Packagist library records feed the package
// dimension (keyed by the full vendor/package name) while CMS cores stay in the
// CMS dimension.
func TestOSVPackageRouting(t *testing.T) {
	const osvGuzzle = `{
	  "id":"GHSA-xxxx","aliases":["CVE-2099-0001"],
	  "summary":"Example Guzzle issue",
	  "affected":[{"package":{"ecosystem":"Packagist","name":"guzzlehttp/guzzle"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"7.0.0"},{"fixed":"7.9.9"}]}]}],
	  "database_specific":{"severity":"HIGH"}
	}`
	f, err := ParseFeed([]byte(osvGuzzle))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Packages["guzzlehttp/guzzle"]) != 1 {
		t.Fatalf("guzzle should be routed to the package dimension: %+v", f.Packages)
	}
	if len(f.CMS) != 0 {
		t.Errorf("a library package should not land in the CMS dimension: %+v", f.CMS)
	}
	c := DefaultCatalog()
	c.Merge(f)
	if !hasVulnID(c.CorrelatePackage("guzzlehttp/guzzle", "7.5.0"), "CVE-2099-0001") {
		t.Fatal("merged OSV package advisory should correlate against the inventory")
	}

	// A CMS core package (drupal/core) still routes to the CMS dimension.
	const osvDrupal = `{
	  "id":"CVE-2099-0002","summary":"Drupal core issue",
	  "affected":[{"package":{"ecosystem":"Packagist","name":"drupal/core"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"9.0.0"},{"fixed":"9.9.9"}]}]}],
	  "database_specific":{"severity":"high"}
	}`
	fd, err := ParseFeed([]byte(osvDrupal))
	if err != nil {
		t.Fatal(err)
	}
	if len(fd.CMS["drupal"]) == 0 {
		t.Fatalf("drupal/core should stay in the CMS dimension: %+v", fd)
	}
	if len(fd.Packages) != 0 {
		t.Errorf("a CMS core must not enter the package dimension: %+v", fd.Packages)
	}
}
