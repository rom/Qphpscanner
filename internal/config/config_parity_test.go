package config

import "testing"

func TestExtendedOptionsParsed(t *testing.T) {
	yaml := `
rate: 12.5
per_host_concurrency: 4
host_concurrency: 8
jitter: 250ms
retries: 2
resolve_dns: true
banners: yes
cookie: "sid=abc"
bearer: "tok"
basic: "u:p"
vhost: "example.com"
proxy: "socks5://127.0.0.1:9050"
fail_on: high
resume: /tmp/cp.ndjson
verify_subdomains: true
no_dns_enum: true
targets_file: hosts.txt
pcap: scan.pcap
log: scan.log
vuln_feeds:
  - a.json
  - https://example/b.json
favicon_catalogs:
  - fav.json
headers:
  - "X-A: 1"
  - "X-B: 2"
web:
  auth: "admin:pw"
`
	c, err := loadString(t, yaml)
	if err != nil {
		t.Fatal(err)
	}
	if c.Rate != 12.5 {
		t.Errorf("rate = %v", c.Rate)
	}
	if c.PerHostConcurrency != 4 || c.HostConcurrency != 8 || c.Retries != 2 {
		t.Errorf("ints: %+v", c)
	}
	if c.Jitter != "250ms" {
		t.Errorf("jitter = %q", c.Jitter)
	}
	if c.ResolveDNS == nil || !*c.ResolveDNS || c.Banners == nil || !*c.Banners {
		t.Errorf("bool enrichment not parsed: %+v %+v", c.ResolveDNS, c.Banners)
	}
	if c.Cookie != "sid=abc" || c.Bearer != "tok" || c.Basic != "u:p" || c.Vhost != "example.com" || c.Proxy == "" {
		t.Errorf("shaping: %+v", c)
	}
	if c.FailOn != "high" || c.Resume == "" || c.TargetsFile != "hosts.txt" {
		t.Errorf("data/resume: %+v", c)
	}
	if c.VerifySubdomains == nil || !*c.VerifySubdomains || c.NoDNSEnum == nil || !*c.NoDNSEnum {
		t.Errorf("verify/nodns not parsed")
	}
	if c.PCAP != "scan.pcap" || c.Log != "scan.log" {
		t.Errorf("audit: %+v", c)
	}
	if len(c.VulnFeeds) != 2 || len(c.FaviconCatalogs) != 1 {
		t.Errorf("feeds: %+v %+v", c.VulnFeeds, c.FaviconCatalogs)
	}
	if len(c.Headers) != 2 {
		t.Errorf("headers = %+v", c.Headers)
	}
	if c.Web.Auth != "admin:pw" {
		t.Errorf("web auth = %q", c.Web.Auth)
	}
}

func TestHeadersAsMap(t *testing.T) {
	c, err := loadString(t, "headers:\n  X-One: a\n  X-Two: b\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Headers) != 2 {
		t.Fatalf("map headers = %+v", c.Headers)
	}
}

func TestBadNumericConfig(t *testing.T) {
	if _, err := loadString(t, "rate: notanumber\n"); err == nil {
		t.Error("expected error for non-numeric rate")
	}
	if _, err := loadString(t, "host_concurrency: lots\n"); err == nil {
		t.Error("expected error for non-numeric host_concurrency")
	}
}
