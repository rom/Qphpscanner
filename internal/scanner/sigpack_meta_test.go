package scanner

import (
	"io"
	"net/http"
	"testing"

	"github.com/rom/qphpscanner/internal/php"
)

// TestSignaturePacksStampedIntoMeta confirms a registered detection-signature
// pack is both applied during analysis and recorded in the scan provenance.
func TestSignaturePacksStampedIntoMeta(t *testing.T) {
	t.Setenv("NO_PROXY", "*")

	p, err := php.ParseSignaturePack([]byte(`{
		"id": "meta-pack",
		"version": "9.9",
		"headers": [{"header": "X-Meta-Pack", "framework": "MetaCMS", "php": true, "weight": 80, "detail": "meta-pack header"}]
	}`))
	if err != nil {
		t.Fatalf("parse pack: %v", err)
	}
	if err := php.RegisterSignaturePack(p); err != nil {
		t.Fatalf("register pack: %v", err)
	}

	ts, _, port := recordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Meta-Pack", "on")
		_, _ = io.WriteString(w, "<html>ok</html>")
	})
	defer ts.Close()

	res := deepScan(t, port, Options{})

	found := false
	for _, id := range res.Meta.SignaturePacks {
		if id == "meta-pack@9.9" {
			found = true
		}
	}
	if !found {
		t.Fatalf("scan Meta.SignaturePacks = %v, want it to include meta-pack@9.9", res.Meta.SignaturePacks)
	}

	svc := res.Targets[0].Services[0]
	if svc.PHP == nil || !svc.PHP.IsPHP {
		t.Fatalf("pack header should have driven a PHP verdict, got %+v", svc.PHP)
	}
}
