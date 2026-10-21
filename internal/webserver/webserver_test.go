package webserver

import (
	"net/http"
	"testing"

	"github.com/rom/qphpscanner/internal/probe"
)

func mkResp(status int, headers map[string]string, cookies []string, body string) *probe.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Add(k, v)
	}
	r := &probe.Response{Status: status, Header: h, Body: []byte(body)}
	for _, c := range cookies {
		r.Cookies = append(r.Cookies, &http.Cookie{Name: c, Value: "x"})
	}
	return r
}

func has(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestServerFromHeader(t *testing.T) {
	res := Analyze(mkResp(200, map[string]string{"Server": "nginx/1.25.3"}, nil, ""), nil)
	if res.Server.Product != "nginx" || res.Server.Version != "1.25.3" {
		t.Fatalf("server: %+v", res.Server)
	}
	if res.Proxy.Present {
		t.Fatal("plain nginx should not look proxied")
	}
}

func TestServerModulesAndOS(t *testing.T) {
	root := mkResp(200, map[string]string{
		"Server": "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f mod_perl/2.0.11 PHP/7.4.3",
	}, nil, "")
	res := Analyze(root, nil)
	s := res.Server
	if s.Product != "Apache" || s.Version != "2.4.41" {
		t.Fatalf("product/version: %+v", s)
	}
	if s.OS != "Ubuntu" {
		t.Fatalf("os: %q", s.OS)
	}
	for _, m := range []string{"OpenSSL/1.1.1f", "mod_perl/2.0.11", "PHP/7.4.3"} {
		if !has(s.Modules, m) {
			t.Fatalf("missing module %q in %v", m, s.Modules)
		}
	}
}

func TestNginxStubStatusAndVersionRecovery(t *testing.T) {
	// server_tokens off: bare "nginx" header, version recovered from a page.
	root := mkResp(200, map[string]string{"Server": "nginx"}, nil, "")
	status := mkResp(200, nil, nil, "Active connections: 43 \nserver accepts handled requests\n 12 12 60\nReading: 0 Writing: 1 Waiting: 42\n")
	errPage := mkResp(404, map[string]string{"Content-Type": "text/html"}, nil, "<center>nginx/1.27.1</center>")
	res := Analyze(root, []*probe.Response{status, errPage})
	s := res.Server
	if s.Product != "nginx" {
		t.Fatalf("product: %+v", s)
	}
	if s.Version != "1.27.1" {
		t.Fatalf("version recovered from page = %q, want 1.27.1", s.Version)
	}
	if !has(s.Modules, "ngx_http_stub_status_module") {
		t.Fatalf("stub_status module not detected: %v", s.Modules)
	}
}

func TestNginxOpenRestyAndXAccel(t *testing.T) {
	root := mkResp(200, map[string]string{"Server": "openresty/1.25.3.1", "X-Accel-Buffering": "no"}, nil, "")
	s := Analyze(root, nil).Server
	if s.Product != "OpenResty" || s.Version != "1.25.3.1" {
		t.Fatalf("product/version: %+v", s)
	}
	if !has(s.Modules, "LuaJIT (OpenResty)") {
		t.Fatalf("LuaJIT runtime not noted: %v", s.Modules)
	}
	if !has(s.Modules, "ngx X-Accel offload") {
		t.Fatalf("X-Accel offload not detected: %v", s.Modules)
	}
}

func TestCDNDetection(t *testing.T) {
	res := Analyze(mkResp(200, map[string]string{"CF-RAY": "abc123", "Server": "cloudflare"}, nil, ""), nil)
	if !res.Proxy.Present || !res.Proxy.Concealed {
		t.Fatalf("expected proxied/concealed: %+v", res.Proxy)
	}
	if !has(res.Proxy.CDN, "Cloudflare") {
		t.Fatalf("CDN: %v", res.Proxy.CDN)
	}
	if res.Proxy.Note == "" {
		t.Fatal("expected a proxy note")
	}
	// Origin server is concealed behind the CDN.
	if res.Server.Product != "" {
		t.Fatalf("origin server should be concealed, got %q", res.Server.Product)
	}
}

func TestWAFHeaderAndNote(t *testing.T) {
	res := Analyze(mkResp(200, map[string]string{"X-Sucuri-ID": "123", "Server": "Sucuri/Cloudproxy"}, nil, ""), nil)
	if !has(res.Proxy.WAF, "Sucuri") {
		t.Fatalf("WAF: %v", res.Proxy.WAF)
	}
	if res.Proxy.Note == "" || !contains(res.Proxy.Note, "WAF") {
		t.Fatalf("note should mention WAF: %q", res.Proxy.Note)
	}
}

func TestWAFCookieAndBlockPage(t *testing.T) {
	c := Analyze(mkResp(200, nil, []string{"incap_ses_123_456"}, ""), nil)
	if !has(c.Proxy.WAF, "Imperva Incapsula") {
		t.Fatalf("incapsula cookie: %v", c.Proxy.WAF)
	}
	b := Analyze(mkResp(403, nil, nil, "<html><title>Attention Required! | Cloudflare</title></html>"), nil)
	if !has(b.Proxy.WAF, "Cloudflare") {
		t.Fatalf("cloudflare block page: %v", b.Proxy.WAF)
	}
}

func TestLoadBalancerCookie(t *testing.T) {
	res := Analyze(mkResp(200, map[string]string{"Server": "nginx"}, []string{"AWSALB"}, ""), nil)
	if !has(res.Proxy.LoadBalancers, "AWS ELB/ALB") {
		t.Fatalf("LB: %v", res.Proxy.LoadBalancers)
	}
}

func TestGenericProxy(t *testing.T) {
	res := Analyze(mkResp(200, map[string]string{"Via": "1.1 vegur", "X-Cache": "HIT"}, nil, ""), nil)
	if !res.Proxy.Present {
		t.Fatal("Via/X-Cache should flag an intermediary")
	}
}

func TestServerErrorPageFallback(t *testing.T) {
	root := mkResp(200, nil, nil, "")
	errPage := mkResp(404, nil, nil, "<html><body><center>404</center><hr><center>nginx/1.18.0</center></body></html>")
	res := Analyze(root, []*probe.Response{errPage})
	if res.Server.Product != "nginx" || res.Server.Version != "1.18.0" {
		t.Fatalf("error-page server: %+v", res.Server)
	}
}

func TestModuleHeadersAndDAV(t *testing.T) {
	root := mkResp(200, map[string]string{"Server": "Microsoft-IIS/10.0", "X-AspNet-Version": "4.0.30319"}, nil, "")
	options := mkResp(200, map[string]string{"DAV": "1,2", "Allow": "OPTIONS,GET,HEAD"}, nil, "")
	res := Analyze(root, []*probe.Response{options})
	if res.Server.Product != "Microsoft IIS" {
		t.Fatalf("iis product: %q", res.Server.Product)
	}
	if !has(res.Server.Modules, "ASP.NET 4.0.30319") {
		t.Fatalf("aspnet module: %v", res.Server.Modules)
	}
	if !has(res.Server.Modules, "WebDAV") {
		t.Fatalf("webdav module: %v", res.Server.Modules)
	}
}

func TestTier(t *testing.T) {
	if Tier(80) != "high" || Tier(50) != "medium" || Tier(10) != "low" {
		t.Fatal("tier mapping")
	}
}

func contains(h, n string) bool { return len(n) == 0 || (len(h) >= len(n) && indexOf(h, n) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
