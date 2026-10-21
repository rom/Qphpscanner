package corpus

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/rom/qphpscanner/internal/probe"
)

func sampleResponse() *probe.Response {
	h := http.Header{}
	h.Set("X-Powered-By", "PHP/8.2.0")
	h.Add("Set-Cookie", "PHPSESSID=deadbeefsecret; Path=/; HttpOnly")
	h.Add("Set-Cookie", "tracking=abc123")
	h.Set("Authorization", "Bearer super-secret-token")
	return &probe.Response{
		RequestURL: "http://h/",
		FinalURL:   "http://h/index.php",
		Status:     200,
		Proto:      "HTTP/1.1",
		Header:     h,
		Cookies: []*http.Cookie{
			{Name: "PHPSESSID", Value: "deadbeefsecret"},
		},
		Body: []byte{0x00, 0xff, 0xfe, 'P', 'H', 'P'},
		Hops: 1,
	}
}

func TestResponseRoundTripPreservesBinaryBody(t *testing.T) {
	orig := sampleResponse()
	wire := FromResponse(orig)
	back := wire.ToResponse()

	if !bytes.Equal(back.Body, orig.Body) {
		t.Fatalf("body not preserved: %v vs %v", back.Body, orig.Body)
	}
	if back.Status != 200 || back.Proto != "HTTP/1.1" || back.FinalURL != "http://h/index.php" || back.Hops != 1 {
		t.Fatalf("scalar fields not preserved: %+v", back)
	}
	if got := back.Header.Values("Set-Cookie"); len(got) != 2 {
		t.Fatalf("multi-value header lost: %v", got)
	}
	if len(back.Cookies) != 1 || back.Cookies[0].Name != "PHPSESSID" {
		t.Fatalf("cookies not preserved: %+v", back.Cookies)
	}
	// FromResponse must copy, not alias, the original's slices.
	wire.Body[0] = 0x42
	if orig.Body[0] == 0x42 {
		t.Fatal("FromResponse aliased the original body")
	}
}

func TestRecorderSanitizesSecrets(t *testing.T) {
	r := NewRecorder()
	r.Add(Service{Target: "http://h/", Root: FromResponse(sampleResponse())})
	c := r.Corpus("qphpscanner", "test")

	if len(c.Services) != 1 || c.Schema != Schema {
		t.Fatalf("corpus shape: %+v", c)
	}
	root := c.Services[0].Root

	// Authorization value is gone; the header name stays.
	if got := root.Headers["Authorization"]; len(got) != 1 || got[0] != redacted {
		t.Errorf("Authorization not redacted: %v", got)
	}
	// Set-Cookie keeps the cookie name and attributes but drops the value.
	sc := root.Headers["Set-Cookie"]
	if len(sc) != 2 {
		t.Fatalf("set-cookie count: %v", sc)
	}
	if sc[0] != "PHPSESSID=REDACTED; Path=/; HttpOnly" {
		t.Errorf("set-cookie value not redacted while keeping name/attrs: %q", sc[0])
	}
	// The raw secret must not survive anywhere in the cookie headers.
	for _, v := range sc {
		if bytes.Contains([]byte(v), []byte("deadbeefsecret")) {
			t.Errorf("secret leaked into set-cookie: %q", v)
		}
	}
	// Parsed cookie keeps its name (a detection signal) but not its value.
	if len(root.Cookies) != 1 || root.Cookies[0].Name != "PHPSESSID" || root.Cookies[0].Value != redacted {
		t.Errorf("parsed cookie not sanitised: %+v", root.Cookies)
	}
	// The original passed to Add is untouched by sanitisation (copy semantics).
	if sampleResponse().Cookies[0].Value != "deadbeefsecret" {
		t.Error("sanitisation reached beyond the corpus copy")
	}
}

func TestWriteLoadRoundTrip(t *testing.T) {
	r := NewRecorder()
	r.Add(Service{Target: "http://h/", Deep: true, Root: FromResponse(sampleResponse())})
	var buf bytes.Buffer
	if err := Write(&buf, r.Corpus("t", "v")); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := Load(buf.Bytes())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.Services) != 1 || !c.Services[0].Deep || c.Services[0].Target != "http://h/" {
		t.Fatalf("reloaded corpus wrong: %+v", c)
	}
	if !bytes.Equal(c.Services[0].Root.ToResponse().Body, sampleResponse().Body) {
		t.Error("body not preserved through write/load")
	}
}

func TestLoadRejectsBadInput(t *testing.T) {
	if _, err := Load([]byte(`not json`)); err == nil {
		t.Error("expected json error")
	}
	if _, err := Load([]byte(`{"schema":"other/9","services":[]}`)); err == nil {
		t.Error("expected schema mismatch error")
	}
	// An empty schema is accepted for brevity.
	if _, err := Load([]byte(`{"services":[]}`)); err != nil {
		t.Errorf("empty schema should be accepted: %v", err)
	}
}
