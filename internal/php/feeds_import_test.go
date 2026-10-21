package php

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const osvSingle = `{
  "id":"GHSA-aaaa-bbbb-cccc",
  "aliases":["CVE-2023-1234"],
  "summary":"XSS in Drupal core",
  "details":"A cross-site scripting issue.",
  "affected":[{"package":{"ecosystem":"Packagist","name":"drupal/core"},
    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"9.0.0"},{"fixed":"9.5.3"}]}]}],
  "references":[{"type":"ADVISORY","url":"https://example/advisory"}],
  "database_specific":{"severity":"HIGH"}
}`

const osvPHPArray = `[{
  "id":"CVE-2024-5555","summary":"PHP core bug",
  "affected":[{"package":{"ecosystem":"PHP","name":"php"},
    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"8.1.0"},{"fixed":"8.1.20"}]}]}],
  "database_specific":{"severity":"critical"}
}]`

func TestDetectFeedFormat(t *testing.T) {
	cases := map[string]feedFormat{
		osvSingle:   feedOSV,
		osvPHPArray: feedOSV,
		`{"document":{"title":"x"},"vulnerabilities":[]}`: feedCSAF,
		`{"schema":"qphpscanner-vuln-feed/1","php":[]}`:   feedNative,
		`{"schema":"qphpscanner-vuln-feed/1","cms":{}}`:   feedNative,
	}
	for data, want := range cases {
		if got := detectFeedFormat([]byte(data)); got != want {
			t.Errorf("detectFeedFormat(%.30s) = %d, want %d", data, got, want)
		}
	}
}

func TestConvertOSVDrupal(t *testing.T) {
	f, err := ParseFeed([]byte(osvSingle))
	if err != nil {
		t.Fatal(err)
	}
	entries := f.CMS["drupal"]
	if len(entries) != 1 {
		t.Fatalf("want 1 drupal entry, got %d (%+v)", len(entries), f.CMS)
	}
	e := entries[0]
	if e.ID != "CVE-2023-1234" {
		t.Errorf("id = %q, want the CVE alias", e.ID)
	}
	if e.Severity != "high" {
		t.Errorf("severity = %q, want high", e.Severity)
	}

	cat := &Catalog{cms: map[string][]FeedEntry{}, eol: map[string]string{}}
	cat.Merge(f)
	leads := cat.CorrelateCMS("drupal", "9.2.0")
	if len(leads) == 0 {
		t.Fatal("expected a correlated lead for Drupal 9.2.0")
	}
	if got := cat.CorrelateCMS("drupal", "9.6.0"); len(got) != 0 {
		t.Errorf("9.6.0 is past the fix, want no lead, got %d", len(got))
	}
}

func TestConvertOSVPHPArray(t *testing.T) {
	f, err := ParseFeed([]byte(osvPHPArray))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.PHP) != 1 {
		t.Fatalf("want 1 PHP entry, got %d", len(f.PHP))
	}
	cat := &Catalog{cms: map[string][]FeedEntry{}, eol: map[string]string{}}
	cat.Merge(f)
	if leads := cat.CorrelatePHP("PHP", "8.1.5"); len(leads) == 0 {
		t.Fatal("expected a correlated PHP lead for 8.1.5")
	}
	if leads := cat.CorrelatePHP("PHP", "8.1.25"); len(leads) != 0 {
		t.Error("8.1.25 is past the fix, want no lead")
	}
}

const csafDocJSON = `{
  "document":{"title":"Example advisory","tracking":{"id":"EX-2023-01"}},
  "product_tree":{"branches":[
    {"category":"vendor","name":"Example","branches":[
      {"category":"product_name","name":"Laravel","branches":[
        {"category":"product_version","name":"9.5.0","product":{"name":"Laravel 9.5.0","product_id":"PID-1"}}
      ]}
    ]}
  ]},
  "vulnerabilities":[{"cve":"CVE-2023-9999","title":"RCE in Example",
    "scores":[{"cvss_v3":{"baseSeverity":"CRITICAL","baseScore":9.8}}],
    "product_status":{"known_affected":["PID-1"]},
    "references":[{"url":"https://example/csaf"}]}]
}`

func TestConvertCSAF(t *testing.T) {
	f, err := ParseFeed([]byte(csafDocJSON))
	if err != nil {
		t.Fatal(err)
	}
	entries := f.CMS["laravel"]
	if len(entries) != 1 {
		t.Fatalf("want 1 laravel entry, got %d (%+v)", len(entries), f.CMS)
	}
	if entries[0].ID != "CVE-2023-9999" || entries[0].Severity != "critical" {
		t.Errorf("bad entry: %+v", entries[0])
	}
	cat := &Catalog{cms: map[string][]FeedEntry{}, eol: map[string]string{}}
	cat.Merge(f)
	if leads := cat.CorrelateCMS("laravel", "9.5.0"); len(leads) == 0 {
		t.Fatal("expected a lead for Laravel 9.5.0 (exact match)")
	}
	if leads := cat.CorrelateCMS("laravel", "9.5.1"); len(leads) != 0 {
		t.Error("9.5.1 should not match an exact-9.5.0 CSAF product")
	}
}

func TestParseComparatorRange(t *testing.T) {
	spec := parseComparatorRange("vers:composer/>=1.0.0|<2.0.0")
	if spec.Introduced != "1.0.0" || spec.Fixed != "2.0.0" {
		t.Fatalf("range parse: %+v", spec)
	}
	if !spec.matches("1.5.0") || spec.matches("2.0.0") {
		t.Error("comparator range match wrong")
	}
}

func TestLoadFeedAutoDetect(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "osv.json")
	if err := os.WriteFile(path, []byte(osvSingle), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := LoadFeed(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.CMS["drupal"]) == 0 {
		t.Fatal("LoadFeed did not auto-detect OSV")
	}
}
