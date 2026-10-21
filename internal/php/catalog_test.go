package php

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/qphpscanner/internal/probe"
)

func TestCatalogCorrelatePHP(t *testing.T) {
	c := DefaultCatalog()
	vulns := c.CorrelatePHP("PHP", "7.4.3")
	if len(vulns) == 0 {
		t.Fatal("expected leads for 7.4.3")
	}
	// 8.4.x (future supported) should have few/none and not be EOL.
	if eol, _ := c.EOL("PHP", "8.4.1"); eol {
		t.Fatal("8.4 should not be EOL")
	}
	php, cms := c.Counts()
	if php < 20 || cms < 3 {
		t.Fatalf("catalogue too small: php=%d cms=%d", php, cms)
	}
}

func TestCatalogCorrelateCMS(t *testing.T) {
	c := DefaultCatalog()
	v := c.CorrelateCMS("WordPress", "5.8.0")
	if len(v) == 0 {
		t.Fatal("expected WordPress leads for 5.8.0")
	}
	if len(c.CorrelateCMS("WordPress", "6.9.0")) != 0 {
		t.Fatal("recent WordPress should have no built-in leads")
	}
	if len(c.CorrelateCMS("unknown-cms", "1.0")) != 0 {
		t.Fatal("unknown CMS => none")
	}
	// Drupalgeddon2 range check.
	if len(c.CorrelateCMS("Drupal", "7.57")) == 0 {
		t.Fatal("Drupal 7.57 should match Drupalgeddon2")
	}
	if len(c.CorrelateCMS("Drupal", "7.59")) != 0 {
		t.Fatal("Drupal 7.59 should be patched")
	}
	// Joomla 3.7.0 SQL injection (CVE-2017-8917) is a single-release window.
	if !hasVulnID(c.CorrelateCMS("Joomla", "3.7.0"), "CVE-2017-8917") {
		t.Fatal("Joomla 3.7.0 should match CVE-2017-8917")
	}
	if hasVulnID(c.CorrelateCMS("Joomla", "3.7.1"), "CVE-2017-8917") {
		t.Fatal("Joomla 3.7.1 should be patched for CVE-2017-8917")
	}
}

func TestCatalogNewPHPEntries(t *testing.T) {
	c := DefaultCatalog()
	// SHA-3 buffer overflow affects 8.1.10, fixed in 8.1.11.
	if !hasVulnID(c.CorrelatePHP("PHP", "8.1.10"), "CVE-2022-37454") {
		t.Error("8.1.10 should match CVE-2022-37454")
	}
	if hasVulnID(c.CorrelatePHP("PHP", "8.1.11"), "CVE-2022-37454") {
		t.Error("8.1.11 should be patched for CVE-2022-37454")
	}
	// March 2025 line: 8.3.18 vulnerable, 8.3.19 fixed.
	if !hasVulnID(c.CorrelatePHP("PHP", "8.3.18"), "CVE-2025-1219") {
		t.Error("8.3.18 should match CVE-2025-1219")
	}
	if hasVulnID(c.CorrelatePHP("PHP", "8.3.19"), "CVE-2025-1219") {
		t.Error("8.3.19 should be patched for CVE-2025-1219")
	}
}

func hasVulnID(vs []Vulnerability, id string) bool {
	for _, v := range vs {
		if v.ID == id {
			return true
		}
	}
	return false
}

func TestRangeSpecMatching(t *testing.T) {
	cases := []struct {
		r    RangeSpec
		v    string
		want bool
	}{
		{RangeSpec{Branch: "8.1", LessThan: "8.1.29"}, "8.1.20", true},
		{RangeSpec{Branch: "8.1", LessThan: "8.1.29"}, "8.1.29", false},
		{RangeSpec{Branch: "8.1", LessThan: "8.1.29"}, "8.2.0", false},
		{RangeSpec{LessThan: "5.3.12"}, "5.2.0", true},
		{RangeSpec{Introduced: "8.0", Fixed: "8.6.10"}, "8.5.0", true},
		{RangeSpec{Introduced: "8.0", Fixed: "8.6.10"}, "8.6.10", false},
		{RangeSpec{}, "1.0.0", false},
	}
	for _, c := range cases {
		if got := c.r.matches(c.v); got != c.want {
			t.Fatalf("%+v.matches(%q) = %v, want %v", c.r, c.v, got, c.want)
		}
	}
}

func TestFeedMergeAndLoad(t *testing.T) {
	feedJSON := `{
	 "schema":"qphpscanner-vuln-feed/1",
	 "php":[{"id":"CVE-9999-0001","severity":"high","title":"Test issue","affected":[{"branch":"8.3","lt":"8.3.99"}]}],
	 "cms":{"wordpress":[{"id":"WP-TEST","severity":"medium","title":"wp test","affected":[{"lt":"9.9.9"}]}]},
	 "eol":{"8.3":"2000-01-01"}
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.json")
	if err := os.WriteFile(path, []byte(feedJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	feed, err := LoadFeed(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := DefaultCatalog()
	c.Merge(feed)

	if len(c.CorrelatePHP("PHP", "8.3.50")) == 0 {
		t.Fatal("merged PHP feed entry should match 8.3.50")
	}
	if len(c.CorrelateCMS("wordpress", "9.0.0")) == 0 {
		t.Fatal("merged CMS feed entry should match")
	}
	// Overridden EOL date makes 8.3 end-of-life.
	if eol, _ := c.EOL("PHP", "8.3.1"); !eol {
		t.Fatal("feed EOL override should mark 8.3 end of life")
	}
}

func TestParseFeedErrors(t *testing.T) {
	if _, err := ParseFeed([]byte("not json")); err == nil {
		t.Fatal("expected parse error")
	}
	if _, err := ParseFeed([]byte(`{"schema":"wrong/9"}`)); err == nil {
		t.Fatal("expected schema error")
	}
	if _, err := LoadFeed(context.Background(), "/no/such/feed.json", nil); err == nil {
		t.Fatal("expected read error")
	}
}

func TestCompareAndSeverity(t *testing.T) {
	if compareVersion("8.1.2", "8.1.10") >= 0 {
		t.Fatal("8.1.2 < 8.1.10")
	}
	if compareVersion("8.2.0", "8.1.99") <= 0 {
		t.Fatal("8.2.0 > 8.1.99")
	}
	if compareVersion("7.4.3", "7.4.3") != 0 {
		t.Fatal("equal")
	}
	if SeverityRank("critical") <= SeverityRank("high") || SeverityRank("bogus") != 0 {
		t.Fatal("severity ranking")
	}
}

func TestFaviconHash(t *testing.T) {
	// Deterministic: same input → same hash, different input → different.
	h1 := faviconHash([]byte("hello world favicon bytes"))
	h2 := faviconHash([]byte("hello world favicon bytes"))
	h3 := faviconHash([]byte("different bytes entirely!"))
	if h1 != h2 {
		t.Fatal("favicon hash not deterministic")
	}
	if h1 == h3 {
		t.Fatal("different inputs should differ")
	}
	// murmur3 known vector: hash of empty string with seed 0 is 0.
	if murmur3_32(nil, 0) != 0 {
		t.Fatalf("mmh3('') = %d, want 0", murmur3_32(nil, 0))
	}
}

func TestCMSVersionDetection(t *testing.T) {
	root := resp(200, nil, nil, `<html><head><meta name="generator" content="WordPress 5.8.0"></head></html>`)
	in := Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      root,
		Extra: map[string]*probe.Response{
			"http://h/administrator/manifests/files/joomla.xml": resp(200, nil, nil, `<extension><version>3.4.5</version></extension>`),
			"http://h/CHANGELOG.txt":                            resp(200, nil, nil, "Drupal 7.57, 2018-03-28\n- fixed stuff"),
		},
	}
	d := Analyze(in)
	if d.FrameworkVersions["WordPress"] != "5.8.0" {
		t.Fatalf("WordPress version: %v", d.FrameworkVersions)
	}
	if d.FrameworkVersions["Joomla"] != "3.4.5" {
		t.Fatalf("Joomla version: %v", d.FrameworkVersions)
	}
	if d.FrameworkVersions["Drupal"] != "7.57" {
		t.Fatalf("Drupal version: %v", d.FrameworkVersions)
	}
	// CMS vulns should be correlated (WP 5.8.0, Joomla 3.4.5, Drupal 7.57 all vulnerable).
	if len(d.Vulnerabilities) == 0 {
		t.Fatal("expected CMS vuln leads")
	}
}
