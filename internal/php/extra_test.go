package php

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/qphpscanner/internal/probe"
)

func TestFaviconCatalogLookupAndRegister(t *testing.T) {
	// A built-in entry resolves.
	if _, ok := faviconLookup("-1961736892"); !ok {
		t.Error("expected a built-in phpMyAdmin favicon entry")
	}
	if _, ok := faviconLookup(""); ok {
		t.Error("empty hash should not match")
	}
	before := FaviconCatalogCount()
	RegisterFavicons([]FaviconEntry{
		{Hash: "424242", Product: "Acme PHP App", Framework: "AcmeCMS", PHP: true},
		{Hash: "", Product: "ignored"},
	})
	if FaviconCatalogCount() != before+1 {
		t.Fatalf("count = %d, want %d", FaviconCatalogCount(), before+1)
	}
	e, ok := faviconLookup("424242")
	if !ok || e.Product != "Acme PHP App" {
		t.Fatalf("custom entry lookup failed: %+v ok=%v", e, ok)
	}
}

func TestFaviconCatalogEvidence(t *testing.T) {
	RegisterFavicons([]FaviconEntry{{Hash: faviconHash([]byte("ACMEICON")), Product: "Acme Shop", Framework: "AcmeCMS", PHP: true}})
	in := Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      resp(200, nil, nil, "<html></html>"),
		Favicon:   resp(200, map[string]string{"Content-Type": "image/x-icon"}, nil, "ACMEICON"),
	}
	d := Analyze(in)
	if !hasEvidence(d, "favicon.catalog") {
		t.Fatalf("expected favicon.catalog evidence, got %+v", d.Evidence)
	}
	if !hasStr(d.Frameworks, "AcmeCMS") {
		t.Errorf("framework from favicon missing: %v", d.Frameworks)
	}
}

func TestParseFaviconCatalog(t *testing.T) {
	good := `{"schema":"qphpscanner-favicon-catalog/1","favicons":[{"hash":"123","product":"X","php":true}]}`
	c, err := ParseFaviconCatalog([]byte(good))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(c.Favicons) != 1 || c.Favicons[0].Product != "X" {
		t.Fatalf("bad parse: %+v", c)
	}
	if _, err := ParseFaviconCatalog([]byte(`{"schema":"other/9","favicons":[]}`)); err == nil {
		t.Error("expected schema mismatch error")
	}
	if _, err := ParseFaviconCatalog([]byte(`not json`)); err == nil {
		t.Error("expected json error")
	}
}

func TestLoadFaviconCatalogFileAndURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fav.json")
	if err := os.WriteFile(path, []byte(`{"favicons":[{"hash":"999001","product":"FileApp"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := LoadFaviconCatalog(context.Background(), path, nil)
	if err != nil || n != 1 {
		t.Fatalf("load file: n=%d err=%v", n, err)
	}
	if _, ok := faviconLookup("999001"); !ok {
		t.Error("file entry not registered")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"favicons":[{"hash":"999002","product":"URLApp"}]}`))
	}))
	defer srv.Close()
	n, err = LoadFaviconCatalog(context.Background(), srv.URL, srv.Client())
	if err != nil || n != 1 {
		t.Fatalf("load url: n=%d err=%v", n, err)
	}
	if _, ok := faviconLookup("999002"); !ok {
		t.Error("url entry not registered")
	}
}

func TestQuirkDetections(t *testing.T) {
	in := Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      resp(200, map[string]string{"X-Powered-By": "PHP/8.2.0"}, nil, "<html></html>"),
		Extra: map[string]*probe.Response{
			"http://h/.env":       resp(200, nil, nil, "APP_KEY=base64:abc\nDB_CONNECTION=mysql\nDB_PASSWORD=secret"),
			"http://h/telescope":  resp(200, nil, nil, "<title>Telescope</title> Laravel"),
			"http://h/_profiler/": resp(200, nil, nil, `<div class="sf-toolbar">Symfony Profiler</div>`),
			"http://h/status.php": resp(200, nil, nil, `{"installed":true,"version":"27.1.0"}`),
			"http://h/fpm":        resp(200, nil, nil, "pool:  www\nprocess manager: dynamic\naccepted conn: 42"),
		},
	}
	d := Analyze(in)
	for _, sig := range []string{"diag.dotenv", "diag.telescope", "diag.symfony-profiler", "diag.nextcloud-status", "diag.fpm-status"} {
		if !hasEvidence(d, sig) {
			t.Errorf("missing quirk evidence %q", sig)
		}
	}
	if !hasStr(d.Frameworks, "Laravel") {
		t.Errorf("Laravel not detected from .env/telescope: %v", d.Frameworks)
	}
	if !hasStr(d.Addons, "Laravel Telescope") {
		t.Errorf("Laravel Telescope addon missing: %v", d.Addons)
	}
}

func TestExtraBodySignatures(t *testing.T) {
	cases := map[string]string{
		"body.php-headers-sent": "Warning: Cannot modify header information - headers already sent by (output started at /var/www/index.php:3)",
		"body.ci-error":         "<p>A PHP Error was encountered</p> system/core/Loader.php",
		"body.php-open-basedir": "open_basedir restriction in effect. File(/etc/passwd) is not within the allowed path(s)",
		"body.xmlrpc":           "XML-RPC server accepts POST requests only.",
	}
	for sig, body := range cases {
		d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, nil, nil, body)})
		if !hasEvidence(d, sig) {
			t.Errorf("body signature %q not matched for %q", sig, body)
		}
	}
}
