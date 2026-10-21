package php

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodPack = `{
  "schema": "qphpscanner-signature-pack/1",
  "id": "acme",
  "version": "2026.10",
  "headers": [
    {"header": "X-Acme-App", "contains": "acme", "framework": "AcmeCMS", "php": true, "weight": 60, "detail": "Acme header"}
  ],
  "cookies": [
    {"name": "acme_sess", "match": "exact", "framework": "AcmeCMS", "weight": 55, "detail": "Acme cookie"}
  ],
  "body": [
    {"id": "body.acme", "pattern": "(?i)acme-powered", "framework": "AcmeCMS", "php": true, "weight": 50, "detail": "Acme body marker"}
  ]
}`

func TestSignaturePackParsesAndDetects(t *testing.T) {
	pack, err := ParseSignaturePack([]byte(goodPack))
	if err != nil {
		t.Fatalf("ParseSignaturePack: %v", err)
	}
	if pack.ID != "acme" || pack.Version != "2026.10" {
		t.Fatalf("pack id/version: %q %q", pack.ID, pack.Version)
	}
	if pack.Count() != 3 {
		t.Fatalf("pack count = %d, want 3", pack.Count())
	}

	sigs := DefaultSignatureSet()
	before := sigs.Refs()
	if len(before) != 1 || before[0].ID != BuiltinPackID {
		t.Fatalf("default refs = %+v", before)
	}
	sigs.Merge(pack)
	refs := sigs.Refs()
	if len(refs) != 2 || refs[1].ID != "acme" || refs[1].Version != "2026.10" || refs[1].Sigs != 3 {
		t.Fatalf("merged refs = %+v", refs)
	}
	// Merge must not have mutated the built-in globals.
	if len(DefaultSignatureSet().Refs()) != 1 {
		t.Fatal("merging a pack leaked into the built-in default set")
	}

	// A header-only match from the pack drives detection.
	d := Analyze(Input{
		TargetURL:  "http://h/",
		Signatures: sigs,
		Root:       resp(200, map[string]string{"X-Acme-App": "acme/1.0"}, nil, ""),
	})
	if !d.IsPHP || !hasStr(d.Frameworks, "AcmeCMS") {
		t.Fatalf("pack header signature did not detect AcmeCMS: %+v", d)
	}
	if !hasEvidence(d, "header.x-acme-app") {
		t.Fatalf("missing pack header evidence: %+v", d.Evidence)
	}

	// A body-only match from the pack also works.
	d2 := Analyze(Input{
		TargetURL:  "http://h/",
		Signatures: sigs,
		Root:       resp(200, nil, nil, "<html>acme-powered site</html>"),
	})
	if !hasEvidence(d2, "body.acme") || !hasStr(d2.Frameworks, "AcmeCMS") {
		t.Fatalf("pack body signature did not fire: %+v", d2)
	}

	// A cookie-only match from the pack works too.
	d3 := Analyze(Input{
		TargetURL:  "http://h/",
		Signatures: sigs,
		Root:       resp(200, nil, []string{"acme_sess"}, ""),
	})
	if !hasEvidence(d3, "cookie.acme_sess") {
		t.Fatalf("pack cookie signature did not fire: %+v", d3)
	}

	// Without the pack the same response is not AcmeCMS.
	plain := Analyze(Input{TargetURL: "http://h/", Root: resp(200, map[string]string{"X-Acme-App": "acme/1.0"}, nil, "")})
	if hasStr(plain.Frameworks, "AcmeCMS") {
		t.Fatal("built-ins should not know AcmeCMS")
	}
}

func TestNilSignatureSetUsesBuiltins(t *testing.T) {
	var s *SignatureSet
	if len(s.headerSigs()) != len(headerSigs) || len(s.cookieSigs()) != len(cookieSigs) || len(s.bodySigs()) != len(bodySigs) {
		t.Fatal("nil set should fall back to built-ins")
	}
	if refs := s.Refs(); len(refs) != 1 || refs[0].ID != BuiltinPackID {
		t.Fatalf("nil set refs = %+v", refs)
	}
	// A nil pack merge is a no-op.
	set := DefaultSignatureSet()
	set.Merge(nil)
	if len(set.Refs()) != 1 {
		t.Fatal("merging nil pack should change nothing")
	}
}

func TestSignaturePackRejectsMalformed(t *testing.T) {
	bad := map[string]string{
		"not json":         `{`,
		"wrong schema":     `{"schema":"nope","id":"x","version":"1","headers":[{"header":"A","weight":10}]}`,
		"missing id":       `{"schema":"qphpscanner-signature-pack/1","version":"1","headers":[{"header":"A","weight":10}]}`,
		"missing version":  `{"schema":"qphpscanner-signature-pack/1","id":"x","headers":[{"header":"A","weight":10}]}`,
		"empty":            `{"schema":"qphpscanner-signature-pack/1","id":"x","version":"1"}`,
		"unknown field":    `{"schema":"qphpscanner-signature-pack/1","id":"x","version":"1","bogus":true,"headers":[{"header":"A","weight":10}]}`,
		"bad regex":        `{"schema":"qphpscanner-signature-pack/1","id":"x","version":"1","body":[{"id":"b","pattern":"(","weight":10}]}`,
		"empty pattern":    `{"schema":"qphpscanner-signature-pack/1","id":"x","version":"1","body":[{"id":"b","pattern":"","weight":10}]}`,
		"header no name":   `{"schema":"qphpscanner-signature-pack/1","id":"x","version":"1","headers":[{"header":"","weight":10}]}`,
		"cookie no name":   `{"schema":"qphpscanner-signature-pack/1","id":"x","version":"1","cookies":[{"name":"","weight":10}]}`,
		"body no id":       `{"schema":"qphpscanner-signature-pack/1","id":"x","version":"1","body":[{"id":"","pattern":"a","weight":10}]}`,
		"bad cookie match": `{"schema":"qphpscanner-signature-pack/1","id":"x","version":"1","cookies":[{"name":"c","match":"fuzzy","weight":10}]}`,
		"weight too high":  `{"schema":"qphpscanner-signature-pack/1","id":"x","version":"1","headers":[{"header":"A","weight":200}]}`,
		"weight negative":  `{"schema":"qphpscanner-signature-pack/1","id":"x","version":"1","headers":[{"header":"A","weight":-5}]}`,
	}
	for name, src := range bad {
		if _, err := ParseSignaturePack([]byte(src)); err == nil {
			t.Errorf("%s: expected an error, got none", name)
		}
	}
}

func TestSignaturePackRejectsOversizedPattern(t *testing.T) {
	long := strings.Repeat("a", maxPatternLen+1)
	src := fmt.Sprintf(`{"schema":%q,"id":"x","version":"1","body":[{"id":"b","pattern":%q,"weight":10}]}`,
		SignaturePackSchema, long)
	if _, err := ParseSignaturePack([]byte(src)); err == nil {
		t.Fatal("expected an over-long pattern to be rejected")
	}
}

func TestSignaturePackRejectsTooLargeAndTooMany(t *testing.T) {
	if _, err := ParseSignaturePack([]byte(strings.Repeat("a", maxPackBytes+1))); err == nil {
		t.Fatal("expected an over-large pack to be rejected")
	}
	var b strings.Builder
	fmt.Fprintf(&b, `{"schema":%q,"id":"x","version":"1","headers":[`, SignaturePackSchema)
	for i := 0; i <= maxPackSignatures; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"header":"H%d","weight":10}`, i)
	}
	b.WriteString(`]}`)
	if _, err := ParseSignaturePack([]byte(b.String())); err == nil {
		t.Fatal("expected a pack with too many matchers to be rejected")
	}
}

func TestLoadSignaturePackFromFileAndURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pack.json")
	if err := os.WriteFile(path, []byte(goodPack), 0o644); err != nil {
		t.Fatal(err)
	}
	pack, err := LoadSignaturePack(context.Background(), path, nil)
	if err != nil || pack.ID != "acme" {
		t.Fatalf("load from file: %v %+v", err, pack)
	}
	if _, err := LoadSignaturePack(context.Background(), filepath.Join(dir, "nope.json"), nil); err == nil {
		t.Fatal("missing file should error")
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/404") {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(goodPack))
	}))
	defer ts.Close()
	p2, err := LoadSignaturePack(context.Background(), ts.URL+"/pack.json", ts.Client())
	if err != nil || p2.Version != "2026.10" {
		t.Fatalf("load from URL: %v %+v", err, p2)
	}
	if _, err := LoadSignaturePack(context.Background(), ts.URL+"/404", ts.Client()); err == nil {
		t.Fatal("HTTP 404 should error")
	}
}
