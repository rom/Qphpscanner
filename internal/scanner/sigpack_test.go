package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rom/qphpscanner/internal/php"
)

const scannerPack = `{
  "schema": "qphpscanner-signature-pack/1",
  "id": "acme",
  "version": "9.9",
  "headers": [
    {"header": "X-Acme-App", "contains": "acme", "framework": "AcmeCMS", "php": true, "weight": 70, "detail": "Acme"}
  ]
}`

func TestSignaturePackWiredThroughScan(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	pack, err := php.ParseSignaturePack([]byte(scannerPack))
	if err != nil {
		t.Fatal(err)
	}
	sigs := php.DefaultSignatureSet()
	sigs.Merge(pack)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Acme-App", "acme/2.0")
		_, _ = w.Write([]byte("<title>acme</title>"))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := Scan(ctx, []string{ts.URL}, Options{
		Mode: ModeDeep, TLSMode: TLSOff, Timeout: 5 * time.Second, Signatures: sigs,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// The pack signature must drive detection.
	svc := res.Targets[0].Services[0]
	if svc.PHP == nil {
		t.Fatal("no PHP detection")
	}
	found := false
	for _, f := range svc.PHP.Frameworks {
		if f == "AcmeCMS" {
			found = true
		}
	}
	if !found {
		t.Fatalf("pack framework not detected: %v", svc.PHP.Frameworks)
	}
	// The active packs must be stamped into provenance (built-in + loaded).
	packs := res.Meta.SignaturePacks
	if len(packs) != 2 || packs[0].ID != php.BuiltinPackID || packs[1].ID != "acme" || packs[1].Version != "9.9" {
		t.Fatalf("Meta.SignaturePacks = %+v", packs)
	}
}

func TestNoSignaturePackLeavesMetaEmpty(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2.0")
		_, _ = w.Write([]byte("<title>t</title>"))
	}))
	defer ts.Close()
	res, err := Scan(context.Background(), []string{ts.URL}, Options{
		Mode: ModeDetect, TLSMode: TLSOff, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta.SignaturePacks != nil {
		t.Fatalf("expected no pack provenance by default, got %+v", res.Meta.SignaturePacks)
	}
}
