package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const webPack = `{"schema":"qphpscanner-signature-pack/1","id":"acme","version":"1",` +
	`"headers":[{"header":"X-Acme","contains":"acme","framework":"AcmeCMS","php":true,"weight":60}]}`

func TestBuildSignatureSet(t *testing.T) {
	if sigs, err := buildSignatureSet(nil); err != nil || sigs != nil {
		t.Fatalf("no packs => nil set, got %v %v", sigs, err)
	}
	if sigs, err := buildSignatureSet([]string{"", "   "}); err != nil || sigs != nil {
		t.Fatalf("blank packs => nil set, got %v %v", sigs, err)
	}
	sigs, err := buildSignatureSet([]string{webPack})
	if err != nil || sigs == nil {
		t.Fatalf("good pack => set, got %v %v", sigs, err)
	}
	if refs := sigs.Refs(); len(refs) != 2 || refs[1].ID != "acme" {
		t.Fatalf("refs = %+v", refs)
	}
	if _, err := buildSignatureSet([]string{"{not-json"}); err == nil {
		t.Fatal("malformed pack should error")
	}
}

func TestScanRejectsBadSignaturePack(t *testing.T) {
	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	body := `{"targets":["example.test"],"signature_packs":["{bad json"]}`
	resp, err := http.Post(srv.URL+"/api/scan", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed signature pack => %d, want 400", resp.StatusCode)
	}
}
