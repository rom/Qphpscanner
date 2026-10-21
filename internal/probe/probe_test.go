package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	os.Setenv("NO_PROXY", "*")
	os.Setenv("HTTP_PROXY", "")
	os.Setenv("http_proxy", "")
	os.Exit(m.Run())
}

func hostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	u := strings.TrimPrefix(strings.TrimPrefix(raw, "http://"), "https://")
	host, portStr, err := net.SplitHostPort(u)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(portStr)
	return host, p
}

func TestCheckPortOpen(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	host, port := hostPort(t, ts.URL)
	st := CheckPort(context.Background(), host, port, 2*time.Second)
	if !st.Open {
		t.Fatalf("expected open port, got err=%v", st.Err)
	}
}

func TestCheckPortClosed(t *testing.T) {
	st := CheckPort(context.Background(), "127.0.0.1", 1, 300*time.Millisecond)
	if st.Open {
		t.Fatal("port 1 should be closed")
	}
	if st.Err == nil {
		t.Fatal("expected an error for closed port")
	}
}

func TestFetchBasic(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2.0")
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "x"})
		_, _ = w.Write([]byte("<title>Hi</title>body"))
	}))
	defer ts.Close()

	f := NewFetcher(FetcherConfig{Timeout: 3 * time.Second})
	r := f.Get(context.Background(), ts.URL)
	if r.Err != "" {
		t.Fatalf("unexpected error: %s", r.Err)
	}
	if r.Status != 200 {
		t.Fatalf("status %d", r.Status)
	}
	if r.HeaderGet("X-Powered-By") != "PHP/8.2.0" {
		t.Fatalf("powered-by missing: %v", r.Header)
	}
	if len(r.Cookies) == 0 || r.Cookies[0].Name != "PHPSESSID" {
		t.Fatalf("cookie missing: %v", r.Cookies)
	}
	if !strings.Contains(r.BodyString(), "body") {
		t.Fatalf("body missing")
	}
	if vals := r.HeaderValues("X-Powered-By"); len(vals) != 1 {
		t.Fatalf("header values: %v", vals)
	}
}

func TestFetchRedirectAggregatesCookies(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "hop", Value: "1"})
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("done"))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	f := NewFetcher(FetcherConfig{Timeout: 3 * time.Second, FollowRedirects: true})
	r := f.Get(context.Background(), ts.URL+"/a")
	if r.Status != 200 || r.Hops < 1 {
		t.Fatalf("expected followed redirect, status=%d hops=%d", r.Status, r.Hops)
	}
	found := false
	for _, c := range r.Cookies {
		if c.Name == "hop" {
			found = true
		}
	}
	if !found {
		t.Fatalf("intermediate hop cookie not aggregated: %v", r.Cookies)
	}
}

func TestFetchNoFollow(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusMovedPermanently)
	}))
	defer ts.Close()
	f := NewFetcher(FetcherConfig{Timeout: 3 * time.Second, FollowRedirects: false})
	r := f.Get(context.Background(), ts.URL)
	if r.Status != http.StatusMovedPermanently {
		t.Fatalf("expected 301 without following, got %d", r.Status)
	}
}

func TestFetchRedirectLoop(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path, http.StatusFound)
	}))
	defer ts.Close()
	f := NewFetcher(FetcherConfig{Timeout: 3 * time.Second, FollowRedirects: true})
	r := f.Get(context.Background(), ts.URL+"/loop")
	if r.Err == "" {
		t.Fatal("expected redirect loop error")
	}
}

func TestFetchBodyCap(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("A", 10000)))
	}))
	defer ts.Close()
	f := NewFetcher(FetcherConfig{Timeout: 3 * time.Second, MaxBodyBytes: 100})
	r := f.Get(context.Background(), ts.URL)
	if len(r.Body) != 100 {
		t.Fatalf("expected body capped to 100, got %d", len(r.Body))
	}
}

func TestFetchTLS(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test")
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()
	f := NewFetcher(FetcherConfig{Timeout: 3 * time.Second, Insecure: true})
	r := f.Get(context.Background(), ts.URL)
	if r.Err != "" {
		t.Fatalf("tls fetch error: %s", r.Err)
	}
	if r.TLS == nil || r.TLS.Version == "" {
		t.Fatalf("expected TLS info, got %+v", r.TLS)
	}
}

func TestFetchError(t *testing.T) {
	f := NewFetcher(FetcherConfig{Timeout: 300 * time.Millisecond})
	r := f.Get(context.Background(), "http://127.0.0.1:1/")
	if r.Err == "" {
		t.Fatal("expected connection error")
	}
}

func TestResponseNilSafe(t *testing.T) {
	var r *Response
	if r.BodyString() != "" || r.HeaderGet("x") != "" || r.HeaderValues("x") != nil {
		t.Fatal("nil Response accessors should be safe")
	}
}

func TestTLSVersionName(t *testing.T) {
	if tlsVersionName(0x0304) != "TLS 1.3" {
		t.Fatal("1.3")
	}
	if !strings.HasPrefix(tlsVersionName(0x9999), "0x") {
		t.Fatal("unknown version should hex-format")
	}
}

func TestParseResolveRule(t *testing.T) {
	r, err := ParseResolveRule("example.com:443:203.0.113.10")
	if err != nil || r.Host != "example.com" || r.Port != 443 || r.Addr != "203.0.113.10" {
		t.Fatalf("parse v4: %+v err=%v", r, err)
	}
	// An IPv6 address keeps its colons.
	r6, err := ParseResolveRule("example.com:443:2001:db8::1")
	if err != nil || r6.Addr != "2001:db8::1" {
		t.Fatalf("parse v6: %+v err=%v", r6, err)
	}
	for _, bad := range []string{"", "example.com", "example.com:443", "example.com:nope:1.2.3.4", "example.com::1.2.3.4"} {
		if _, err := ParseResolveRule(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestResolveAddr(t *testing.T) {
	rules := []ResolveRule{{Host: "example.com", Port: 443, Addr: "203.0.113.10"}}
	if got := resolveAddr(rules, "example.com:443"); got != "203.0.113.10:443" {
		t.Errorf("v4 pin = %q", got)
	}
	if got := resolveAddr(rules, "example.com:80"); got != "" {
		t.Errorf("non-matching port should not pin, got %q", got)
	}
	// Port 0 matches any port; an IPv6 addr is bracketed with the request port.
	any := []ResolveRule{{Host: "h", Port: 0, Addr: "2001:db8::1"}}
	if got := resolveAddr(any, "h:8443"); got != "[2001:db8::1]:8443" {
		t.Errorf("v6 any-port pin = %q", got)
	}
}

func TestResolvePinsDial(t *testing.T) {
	var gotHost string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()
	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	port, _ := strconv.Atoi(portStr)

	// "example.test" does not resolve; only the pin makes the request succeed,
	// and the URL host is preserved in the Host header.
	f := NewFetcher(FetcherConfig{
		Timeout: 3 * time.Second,
		Resolve: []ResolveRule{{Host: "example.test", Port: port, Addr: "127.0.0.1"}},
	})
	r := f.Get(context.Background(), "http://example.test:"+portStr+"/")
	if r.Err != "" {
		t.Fatalf("pinned fetch error: %s", r.Err)
	}
	if r.BodyString() != "ok" {
		t.Fatalf("body = %q", r.BodyString())
	}
	if gotHost != "example.test:"+portStr {
		t.Errorf("Host header = %q, want example.test:%s", gotHost, portStr)
	}

	// Without the pin, the unresolvable host fails.
	f2 := NewFetcher(FetcherConfig{Timeout: time.Second})
	if r2 := f2.Get(context.Background(), "http://example.test:"+portStr+"/"); r2.Err == "" {
		t.Error("expected failure without a resolve pin")
	}
}

func TestSNIOverride(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := ""
		if r.TLS != nil {
			name = r.TLS.ServerName
		}
		_, _ = w.Write([]byte(name))
	}))
	defer ts.Close()

	// Dialing an IP literal sends no SNI by default (RFC 6066).
	def := NewFetcher(FetcherConfig{Timeout: 3 * time.Second, Insecure: true})
	if r := def.Get(context.Background(), ts.URL); r.Err != "" || r.BodyString() != "" {
		t.Fatalf("default SNI: err=%q body=%q (want empty)", r.Err, r.BodyString())
	}

	// With an override, the chosen name is sent as SNI.
	f := NewFetcher(FetcherConfig{Timeout: 3 * time.Second, Insecure: true, SNIServerName: "my.sni.test"})
	r := f.Get(context.Background(), ts.URL)
	if r.Err != "" {
		t.Fatalf("sni fetch error: %s", r.Err)
	}
	if r.BodyString() != "my.sni.test" {
		t.Errorf("server saw SNI %q, want my.sni.test", r.BodyString())
	}
}
