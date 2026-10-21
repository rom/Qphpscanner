package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rom/qphpscanner/internal/scanner"
)

func TestCORSPreflight(t *testing.T) {
	srv := httptest.NewServer(NewServer("x").Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodOptions, srv.URL+"/api/scan", nil)
	req.Header.Set("Origin", "https://preview.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight => %d, want 204", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://preview.example" {
		t.Errorf("ACAO = %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("missing Access-Control-Allow-Methods")
	}
}

// A preflight carries no credentials, so it must be answered even when Basic
// auth is enabled — otherwise the browser blocks the real request.
func TestCORSPreflightBypassesAuth(t *testing.T) {
	s := NewServer("x")
	s.SetAuth("admin", "pw")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodOptions, srv.URL+"/api/scan", nil)
	req.Header.Set("Origin", "https://preview.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("authed preflight => %d, want 204", resp.StatusCode)
	}
}

func TestCrossOriginPostGetsCORSHeader(t *testing.T) {
	target := phpTarget()
	defer target.Close()
	srv := httptest.NewServer(NewServer("x").Handler())
	defer srv.Close()

	body := `{"targets_text":"` + target.URL + `","mode":"detect"}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/scan", strings.NewReader(body))
	req.Header.Set("Origin", "https://preview.example")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("POST => %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://preview.example" {
		t.Errorf("ACAO = %q", got)
	}
}

func TestAPIFallbackWrongMethod(t *testing.T) {
	srv := httptest.NewServer(NewServer("x").Handler())
	defer srv.Close()

	// A known endpoint reached with the wrong method → clean JSON 405.
	resp, err := http.Get(srv.URL + "/api/scan")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/scan => %d, want 405", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got == "" {
		t.Error("405 should carry an Allow header")
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("fallback Content-Type = %q, want application/json", ct)
	}
}

func TestAPIFallbackUnknownPath(t *testing.T) {
	srv := httptest.NewServer(NewServer("x").Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown api path => %d, want 404", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestDownloadNameTimestamped(t *testing.T) {
	res := &scanner.ScanResult{}
	res.Meta.FinishedAt = time.Date(2026, 10, 21, 13, 5, 7, 0, time.UTC)
	got := downloadName(res, "scan-3", "json", true)
	if got != "qphpscan-20261021-130507-scan-3.json" {
		t.Errorf("output name = %q", got)
	}
	rep := downloadName(res, "", "pdf", false)
	if rep != "qphpscan-20261021-130507-report.pdf" {
		t.Errorf("report name = %q", rep)
	}
	// A dodgy scan id is sanitised.
	if n := downloadName(res, "../../etc/passwd", "csv", true); n != "qphpscan-20261021-130507-etcpasswd.csv" {
		t.Errorf("unsanitised name = %q", n)
	}
}
