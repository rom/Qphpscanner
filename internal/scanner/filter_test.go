package scanner

import (
	"testing"

	"github.com/rom/qphpscanner/internal/target"
)

func hosts(eps []target.Endpoint) []string {
	var out []string
	for _, e := range eps {
		out = append(out, e.Host)
	}
	return out
}

func TestFilterEndpointsAllowBlock(t *testing.T) {
	eps := []target.Endpoint{
		{Host: "a.example.com"},
		{Host: "b.example.com"},
		{Host: "c.other.com"},
		{Host: "10.0.0.5"},
		{Host: "10.0.1.9"},
	}

	// Allow only example.com subdomains and 10.0.0.0/24; block b.example.com.
	got := filterEndpoints(eps, Options{
		Allowlist: []string{"*.example.com", "10.0.0.0/24"},
		Blocklist: []string{"b.example.com"},
	})
	want := map[string]bool{"a.example.com": true, "10.0.0.5": true}
	if len(got) != len(want) {
		t.Fatalf("got hosts %v, want %v", hosts(got), want)
	}
	for _, e := range got {
		if !want[e.Host] {
			t.Errorf("unexpected host kept: %s", e.Host)
		}
	}
}

func TestFilterEndpointsBlockOnly(t *testing.T) {
	eps := []target.Endpoint{{Host: "keep.com"}, {Host: "evil.test"}}
	got := filterEndpoints(eps, Options{Blocklist: []string{".test"}})
	if len(got) != 1 || got[0].Host != "keep.com" {
		t.Fatalf("block-only filter wrong: %v", hosts(got))
	}
}

func TestFilterEndpointsNoLists(t *testing.T) {
	eps := []target.Endpoint{{Host: "a"}, {Host: "b"}}
	if got := filterEndpoints(eps, Options{}); len(got) != 2 {
		t.Fatalf("no lists should keep all, got %v", hosts(got))
	}
}

func TestMatchAnyCIDRAndExact(t *testing.T) {
	pats := compilePatterns([]string{"192.168.0.0/16", "exact.host"})
	if !matchAny("192.168.5.5", pats) {
		t.Error("CIDR should match")
	}
	if matchAny("10.0.0.1", pats) {
		t.Error("outside CIDR should not match")
	}
	if !matchAny("exact.host", pats) || !matchAny("EXACT.HOST", pats) {
		t.Error("exact host match (case-insensitive) failed")
	}
}
