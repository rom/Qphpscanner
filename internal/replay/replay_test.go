package replay

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/qphpscanner/internal/php"
	"github.com/rom/qphpscanner/internal/probe"
)

// expectation is the detection outcome a fixture corpus should replay to.
type expectation struct {
	isPHP          bool
	wantFrameworks []string
	notFrameworks  []string
	wantEvidence   []string
}

// TestReplayFixtures is the offline regression harness: every corpus in
// testdata/ is replayed through the detection pipeline with no network and
// checked against its expected verdict.
func TestReplayFixtures(t *testing.T) {
	want := map[string]expectation{
		"wordpress.json":     {isPHP: true, wantFrameworks: []string{"WordPress"}},
		"static.json":        {isPHP: false},
		"login.json":         {isPHP: false},
		"waf-challenge.json": {isPHP: false},
		"soft404.json":       {isPHP: false, notFrameworks: []string{"phpMyAdmin"}},
		"dotenv.json":        {isPHP: true, wantFrameworks: []string{"Laravel"}, wantEvidence: []string{"diag.dotenv"}},
	}

	for name, exp := range want {
		t.Run(name, func(t *testing.T) {
			c, err := Load(filepath.Join("testdata", name))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			results := Replay(c, Options{})
			if len(results) != 1 {
				t.Fatalf("want 1 origin, got %d", len(results))
			}
			d := results[0].Detection
			if d == nil {
				t.Fatal("nil detection")
			}
			if d.IsPHP != exp.isPHP {
				t.Errorf("IsPHP = %v, want %v (verdict %s, conf %d)", d.IsPHP, exp.isPHP, d.Verdict, d.Confidence)
			}
			for _, f := range exp.wantFrameworks {
				if !containsString(d.Frameworks, f) && !containsString(d.Addons, f) {
					t.Errorf("missing framework %q (got fw %v / addons %v)", f, d.Frameworks, d.Addons)
				}
			}
			for _, f := range exp.notFrameworks {
				if containsString(d.Frameworks, f) || containsString(d.Addons, f) {
					t.Errorf("framework %q should not be detected (fw %v / addons %v)", f, d.Frameworks, d.Addons)
				}
			}
			for _, sig := range exp.wantEvidence {
				if !hasEvidence(d, sig) {
					t.Errorf("missing evidence %q", sig)
				}
			}
		})
	}
}

func TestReplayAppliesSignaturePack(t *testing.T) {
	pack, err := php.ParseSignaturePack([]byte(
		`{"schema":"qphpscanner-signature-pack/1","id":"acme","version":"1",` +
			`"headers":[{"header":"X-Acme","contains":"acme","framework":"AcmeCMS","php":true,"weight":70}]}`))
	if err != nil {
		t.Fatal(err)
	}
	sigs := php.DefaultSignatureSet()
	sigs.Merge(pack)

	c := &Corpus{Schema: CorpusSchema, Exchanges: []Exchange{{
		Method: "GET", URL: "http://a.test:80/", Status: 200,
		Headers: map[string][]string{"X-Acme": {"acme/1"}},
	}}}
	// Without the pack: not AcmeCMS.
	plain := Replay(c, Options{})
	if len(plain) != 1 || containsString(plain[0].Detection.Frameworks, "AcmeCMS") {
		t.Fatalf("built-ins should not detect AcmeCMS: %+v", plain)
	}
	// With the pack: detected, validating new signatures against the corpus.
	withPack := Replay(c, Options{Signatures: sigs})
	if !containsString(withPack[0].Detection.Frameworks, "AcmeCMS") {
		t.Fatalf("pack signature should detect AcmeCMS on replay: %+v", withPack[0].Detection)
	}
}

func TestSanitizeDropsSecrets(t *testing.T) {
	ex := probe.Exchange{
		Method: "GET", URL: "http://h/.env", Status: 200,
		RespHeaders: http.Header{
			"Set-Cookie":    {"PHPSESSID=deadbeefsecret; Path=/; HttpOnly", "laravel_session=topsecretvalue"},
			"Authorization": {"Bearer sk_live_supersecrettoken"},
			"Content-Type":  {"text/plain"},
		},
		RespBody: []byte("APP_ENV=production\nAPP_KEY=base64:REALSECRETKEYVALUE\nDB_PASSWORD=hunter2\n" +
			`{"api_secret":"abcd1234secret","name":"ok"}`),
	}
	out := sanitize(ex)

	joined := out.Body + " " + strings.Join(out.Headers["Set-Cookie"], " ") + " " + strings.Join(out.Headers["Authorization"], " ")
	for _, secret := range []string{"deadbeefsecret", "topsecretvalue", "sk_live_supersecrettoken", "REALSECRETKEYVALUE", "hunter2", "abcd1234secret"} {
		if strings.Contains(joined, secret) {
			t.Errorf("secret %q leaked into the corpus", secret)
		}
	}
	// Markers detection needs must survive.
	for _, marker := range []string{"PHPSESSID=", "laravel_session=", "APP_KEY=", "DB_PASSWORD=", "APP_ENV=production", "\"name\":\"ok\""} {
		if !strings.Contains(joined, marker) {
			t.Errorf("marker %q was lost during sanitisation", marker)
		}
	}
	// Reconstructed cookies keep their names for detection.
	r := toResponse(out)
	names := map[string]bool{}
	for _, c := range r.Cookies {
		names[c.Name] = true
		if c.Value != "" {
			t.Errorf("cookie %q kept a value %q", c.Name, c.Value)
		}
	}
	if !names["PHPSESSID"] || !names["laravel_session"] {
		t.Errorf("cookie names lost: %v", names)
	}
}

func TestSanitizeBoundsBody(t *testing.T) {
	big := strings.Repeat("A", maxCorpusBodyBytes+5000)
	out := sanitize(probe.Exchange{Method: "GET", URL: "http://h/", Status: 200, RespBody: []byte(big)})
	if len(out.Body) != maxCorpusBodyBytes {
		t.Fatalf("body = %d bytes, want capped at %d", len(out.Body), maxCorpusBodyBytes)
	}
}

func TestRecorderBoundsExchanges(t *testing.T) {
	r := NewRecorder()
	for i := 0; i < maxCorpusExchanges+10; i++ {
		r.Record(probe.Exchange{Method: "GET", URL: "http://h/", Status: 200})
	}
	c := r.Corpus()
	if len(c.Exchanges) != maxCorpusExchanges {
		t.Fatalf("exchanges = %d, want capped at %d", len(c.Exchanges), maxCorpusExchanges)
	}
	if !c.Truncated {
		t.Error("corpus should be flagged truncated")
	}
	if c.Schema != CorpusSchema {
		t.Errorf("schema = %q", c.Schema)
	}
}

func TestRecorderWriteAndLoadRoundTrip(t *testing.T) {
	r := NewRecorder()
	r.Record(probe.Exchange{
		Method: "GET", URL: "http://rt.test:80/", Status: 200,
		RespHeaders: http.Header{"X-Powered-By": {"PHP/8.2.0"}},
		RespBody:    []byte("<title>hi</title>"),
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "corpus.json")
	if err := r.WriteFile(path); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.Exchanges) != 1 || c.Exchanges[0].URL != "http://rt.test:80/" {
		t.Fatalf("round-trip mismatch: %+v", c.Exchanges)
	}
	res := Replay(c, Options{})
	if len(res) != 1 || res[0].Detection == nil || !res[0].Detection.IsPHP {
		t.Fatalf("replayed round-trip should detect PHP: %+v", res)
	}
}

func TestParseRejectsBad(t *testing.T) {
	if _, err := Parse([]byte("{not json")); err == nil {
		t.Error("bad json should error")
	}
	if _, err := Parse([]byte(`{"schema":"wrong","exchanges":[]}`)); err == nil {
		t.Error("wrong schema should error")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("missing file should error")
	}
}

func TestReplayNilAndUnparseableOrigins(t *testing.T) {
	if Replay(nil, Options{}) != nil {
		t.Error("nil corpus should replay to nothing")
	}
	// An exchange with no parseable origin is skipped, not fatal.
	c := &Corpus{Schema: CorpusSchema, Exchanges: []Exchange{{Method: "GET", URL: "::::bad", Status: 200}}}
	if r := Replay(c, Options{}); len(r) != 0 {
		t.Errorf("unparseable origin should be skipped, got %+v", r)
	}
}

func TestLoadRejectsOversizeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.json")
	// A sparse-ish oversize file: write just over the cap.
	if err := os.WriteFile(path, make([]byte, maxCorpusBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("oversize corpus should be rejected")
	}
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func hasEvidence(d *php.Detection, signal string) bool {
	for _, e := range d.Evidence {
		if e.Signal == signal {
			return true
		}
	}
	return false
}
