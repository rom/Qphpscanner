package php

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// acmePack is a small, valid pack exercising all three matcher categories.
const acmePack = `{
  "schema": "qphpscanner-signature-pack/1",
  "id": "acme",
  "version": "2026.10",
  "headers": [
    {"header": "X-Acme-Runtime", "framework": "AcmeCMS", "php": true, "weight": 60, "detail": "Acme runtime header"}
  ],
  "cookies": [
    {"name": "ACMESESSID", "match": "exact", "framework": "AcmeCMS", "weight": 55, "detail": "Acme session cookie"}
  ],
  "bodies": [
    {"id": "body.acme-engine", "regex": "(?i)acme-engine/\\d", "framework": "AcmeCMS", "php": true, "weight": 50, "detail": "Acme engine marker"}
  ]
}`

func TestSignaturePackRegistersWorkingSignatures(t *testing.T) {
	p, err := ParseSignaturePack([]byte(acmePack))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := RegisterSignaturePack(p); err != nil {
		t.Fatalf("register: %v", err)
	}

	in := Input{
		TargetURL: "http://host/",
		Deep:      true,
		Root: resp(200,
			map[string]string{"X-Acme-Runtime": "1"},
			[]string{"ACMESESSID"},
			"<html>powered by acme-engine/7</html>"),
	}
	d := Analyze(in)
	if d == nil || !d.IsPHP {
		t.Fatalf("expected PHP detection from pack signatures, got %+v", d)
	}
	for _, sig := range []string{"header.x-acme-runtime", "cookie.acmesessid", "body.acme-engine"} {
		if !hasEvidence(d, sig) {
			t.Errorf("expected evidence %q from signature pack, got %+v", sig, d.Evidence)
		}
	}
	if !hasStr(d.Frameworks, "AcmeCMS") {
		t.Errorf("framework from pack missing: %v", d.Frameworks)
	}
}

func TestSignaturePackProvenanceLabel(t *testing.T) {
	p, err := ParseSignaturePack([]byte(`{"id":"prov-pack","version":"3.1","headers":[{"header":"X-Prov","weight":10}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := RegisterSignaturePack(p); err != nil {
		t.Fatalf("register: %v", err)
	}
	if !hasStr(SignaturePacks(), "prov-pack@3.1") {
		t.Fatalf("provenance missing pack label, got %v", SignaturePacks())
	}

	// A pack without a version is labelled by id alone.
	np, _ := ParseSignaturePack([]byte(`{"id":"noversion","cookies":[{"name":"X"}]}`))
	_ = RegisterSignaturePack(np)
	if !hasStr(SignaturePacks(), "noversion") {
		t.Fatalf("unversioned pack label missing, got %v", SignaturePacks())
	}
}

func TestSignaturePackRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{"not json", `not json`},
		{"bad schema", `{"schema":"other/9","id":"x"}`},
		{"missing id", `{"headers":[{"header":"X","weight":1}]}`},
		{"blank id", `{"id":"   "}`},
		{"empty header name", `{"id":"x","headers":[{"header":"","weight":1}]}`},
		{"empty cookie name", `{"id":"x","cookies":[{"name":""}]}`},
		{"bad cookie match", `{"id":"x","cookies":[{"name":"S","match":"regex"}]}`},
		{"empty body id", `{"id":"x","bodies":[{"id":"","regex":"a"}]}`},
		{"empty body regex", `{"id":"x","bodies":[{"id":"b","regex":""}]}`},
		{"invalid body regex", `{"id":"x","bodies":[{"id":"b","regex":"a("}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSignaturePack([]byte(tc.doc))
			if err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
			if err.Error() == "" {
				t.Fatalf("rejection for %s has an empty message", tc.name)
			}
		})
	}
	// A validation (not JSON) failure is reported through the packError type.
	if _, err := ParseSignaturePack([]byte(`{"id":""}`)); err == nil || !strings.Contains(err.Error(), "invalid signature pack") {
		t.Fatalf("want a packError message, got %v", err)
	}
}

func TestSignaturePackRejectsOversized(t *testing.T) {
	// Regex longer than the per-matcher cap.
	long := strings.Repeat("a", maxRegexLen+1)
	doc := `{"id":"x","bodies":[{"id":"b","regex":"` + long + `"}]}`
	if _, err := ParseSignaturePack([]byte(doc)); err == nil {
		t.Fatal("expected rejection for an over-length regex")
	}

	// More header entries than the per-category cap.
	var b strings.Builder
	b.WriteString(`{"id":"x","headers":[`)
	for i := 0; i <= maxPackEntries; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"header":"X","weight":1}`)
	}
	b.WriteString(`]}`)
	if _, err := ParseSignaturePack([]byte(b.String())); err == nil {
		t.Fatal("expected rejection for too many entries")
	}
}

func TestSignaturePackClampsWeight(t *testing.T) {
	p, err := ParseSignaturePack([]byte(`{"id":"x","headers":[{"header":"A","weight":9999},{"header":"B","weight":-5}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	hdr, _, _, err := p.build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if hdr[0].weight != 100 || hdr[1].weight != 0 {
		t.Fatalf("weights not clamped: %d %d", hdr[0].weight, hdr[1].weight)
	}
}

func TestLoadSignaturePackFileAndURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pack.json")
	if err := os.WriteFile(path, []byte(`{"id":"file-pack","bodies":[{"id":"body.filepack","regex":"filepack-marker","php":true,"weight":40}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := LoadSignaturePack(context.Background(), path, nil)
	if err != nil || n != 1 {
		t.Fatalf("load file: n=%d err=%v", n, err)
	}
	if !hasStr(SignaturePacks(), "file-pack") {
		t.Errorf("file pack not recorded in provenance: %v", SignaturePacks())
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"url-pack","headers":[{"header":"X-URL-Pack","php":true,"weight":30}]}`))
	}))
	defer srv.Close()
	n, err = LoadSignaturePack(context.Background(), srv.URL, srv.Client())
	if err != nil || n != 1 {
		t.Fatalf("load url: n=%d err=%v", n, err)
	}
	if !hasStr(SignaturePacks(), "url-pack") {
		t.Errorf("url pack not recorded in provenance: %v", SignaturePacks())
	}

	// A missing local file is an error, not a silent no-op.
	if _, err := LoadSignaturePack(context.Background(), filepath.Join(dir, "nope.json"), nil); err == nil {
		t.Error("expected error for a missing pack file")
	}

	// A fetch that 404s is an error, not a silent no-op.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer bad.Close()
	if _, err := LoadSignaturePack(context.Background(), bad.URL, bad.Client()); err == nil {
		t.Error("expected error on HTTP 404")
	}
}
