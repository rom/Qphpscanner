package probe

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	if NewRateLimiter(0, 0) != nil {
		t.Fatal("rate <= 0 should yield a nil limiter")
	}
	lim := NewRateLimiter(1000, 5)
	for i := 0; i < 5; i++ {
		if err := lim.Wait(context.Background()); err != nil {
			t.Fatalf("Wait: %v", err)
		}
	}
	// Exhaust a slow bucket then verify context cancellation is honoured.
	slow := NewRateLimiter(1, 1)
	_ = slow.Wait(context.Background()) // consume the single token
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := slow.Wait(ctx); err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func TestGrabBanner(t *testing.T) {
	// Server that announces itself immediately.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
		c.Close()
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	_, _ = fmtSscan(portStr, &port)
	b := GrabBanner(context.Background(), "127.0.0.1", port, 2*time.Second)
	if !strings.Contains(b, "OpenSSH_9.6") {
		t.Fatalf("banner: %q", b)
	}
}

func TestGrabBannerNudge(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 16)
		_, _ = c.Read(buf) // wait for the CRLF nudge
		_, _ = c.Write([]byte("PONG"))
		c.Close()
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	_, _ = fmtSscan(portStr, &port)
	b := GrabBanner(context.Background(), "127.0.0.1", port, 2*time.Second)
	if b != "PONG" {
		t.Fatalf("nudge banner: %q", b)
	}
}

func TestCustomHeadersAndAuth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "X-Test="+r.Header.Get("X-Test")+
			";Cookie="+r.Header.Get("Cookie")+
			";Auth="+r.Header.Get("Authorization")+
			";Host="+r.Host)
	}))
	defer ts.Close()

	f := NewFetcher(FetcherConfig{
		Timeout:     3 * time.Second,
		Headers:     map[string]string{"X-Test": "abc"},
		Cookie:      "sid=1",
		BearerToken: "tok",
		HostHeader:  "vhost.example",
	})
	r := f.Get(context.Background(), ts.URL)
	body := r.BodyString()
	for _, want := range []string{"X-Test=abc", "Cookie=sid=1", "Auth=Bearer tok", "Host=vhost.example"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in %q", want, body)
		}
	}
}

func TestBasicAuth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		io.WriteString(w, u+":"+p)
	}))
	defer ts.Close()
	f := NewFetcher(FetcherConfig{Timeout: 3 * time.Second, BasicUser: "user", BasicPass: "pass"})
	r := f.Get(context.Background(), ts.URL)
	if r.BodyString() != "user:pass" {
		t.Fatalf("basic auth not sent: %q", r.BodyString())
	}
}

func TestCredentialsNotSentCrossHost(t *testing.T) {
	// Target B lives on a different loopback host than A; a redirect A→B must
	// not forward the cookie or Authorization configured for A.
	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("127.0.0.2 not available in this environment: %v", err)
	}
	var gotCookie, gotAuth, gotBasic string
	srvB := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		gotAuth = r.Header.Get("Authorization")
		if u, _, ok := r.BasicAuth(); ok {
			gotBasic = u
		}
		io.WriteString(w, "B")
	})}
	go func() { _ = srvB.Serve(ln) }()
	defer srvB.Close()
	bURL := "http://" + ln.Addr().String() + "/landing"

	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, bURL, http.StatusFound)
	}))
	defer srvA.Close()

	f := NewFetcher(FetcherConfig{
		Timeout: 3 * time.Second, FollowRedirects: true,
		Cookie: "sid=secret", BearerToken: "tok", BasicUser: "user", BasicPass: "pass",
	})
	r := f.Get(context.Background(), srvA.URL+"/")
	if r.Err != "" {
		t.Fatalf("fetch error: %s", r.Err)
	}
	if gotCookie != "" {
		t.Errorf("cookie leaked to another host: %q", gotCookie)
	}
	if gotAuth != "" || gotBasic != "" {
		t.Errorf("Authorization leaked to another host: auth=%q basic=%q", gotAuth, gotBasic)
	}
}

func TestCredentialsFollowSameHostRedirect(t *testing.T) {
	var gotCookie string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/b" {
			gotCookie = r.Header.Get("Cookie")
			io.WriteString(w, "B")
			return
		}
		http.Redirect(w, r, "/b", http.StatusFound)
	}))
	defer ts.Close()
	f := NewFetcher(FetcherConfig{Timeout: 3 * time.Second, FollowRedirects: true, Cookie: "sid=keepme"})
	r := f.Get(context.Background(), ts.URL+"/a")
	if r.Err != "" {
		t.Fatalf("fetch error: %s", r.Err)
	}
	if gotCookie != "sid=keepme" {
		t.Errorf("same-host redirect should keep the cookie, got %q", gotCookie)
	}
}

func TestProxyBadScheme(t *testing.T) {
	f := NewFetcher(FetcherConfig{Timeout: time.Second, ProxyURL: "gopher://nope"})
	r := f.Get(context.Background(), "http://127.0.0.1:1/")
	if r.Err == "" {
		t.Fatal("expected error from unsupported proxy scheme")
	}
}

func TestSOCKS5Proxy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "via-socks")
	}))
	defer target.Close()

	proxyAddr, stop := startSOCKS5(t)
	defer stop()

	f := NewFetcher(FetcherConfig{Timeout: 5 * time.Second, ProxyURL: "socks5://" + proxyAddr})
	r := f.Get(context.Background(), target.URL)
	if r.Err != "" {
		t.Fatalf("socks fetch error: %s", r.Err)
	}
	if r.BodyString() != "via-socks" {
		t.Fatalf("unexpected body via socks: %q", r.BodyString())
	}
}

func TestHTTPProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "proxied")
	}))
	defer proxy.Close()
	f := NewFetcher(FetcherConfig{Timeout: 3 * time.Second, ProxyURL: proxy.URL})
	r := f.Get(context.Background(), "http://example.invalid/")
	if r.Err != "" || r.BodyString() != "proxied" {
		t.Fatalf("http proxy: err=%q body=%q", r.Err, r.BodyString())
	}
}

func TestRetryOnClosedPort(t *testing.T) {
	f := NewFetcher(FetcherConfig{Timeout: 200 * time.Millisecond, Retries: 2, RetryBackoff: time.Millisecond})
	r := f.Get(context.Background(), "http://127.0.0.1:1/")
	if r.Err == "" {
		t.Fatal("expected error after retries against a closed port")
	}
}

func TestSOCKS5Auth(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "authed-socks")
	}))
	defer target.Close()
	addr, stop := startSOCKS5Auth(t, "bob", "secret")
	defer stop()

	f := NewFetcher(FetcherConfig{Timeout: 5 * time.Second, ProxyURL: "socks5://bob:secret@" + addr})
	r := f.Get(context.Background(), target.URL)
	if r.Err != "" || r.BodyString() != "authed-socks" {
		t.Fatalf("socks auth: err=%q body=%q", r.Err, r.BodyString())
	}

	// Wrong credentials must fail.
	bad := NewFetcher(FetcherConfig{Timeout: 3 * time.Second, ProxyURL: "socks5://bob:wrong@" + addr})
	if rb := bad.Get(context.Background(), target.URL); rb.Err == "" {
		t.Fatal("expected auth failure with wrong credentials")
	}
}

func TestTransientErr(t *testing.T) {
	if !transientErr("dial tcp: i/o timeout") || !transientErr("connection refused") {
		t.Fatal("should be transient")
	}
	if transientErr("redirect loop detected") {
		t.Fatal("logical errors are not transient")
	}
}

// --- helpers ---

func fmtSscan(s string, out *int) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	*out = n
	return 1, nil
}

// startSOCKS5 runs a minimal no-auth SOCKS5 relay for testing.
func startSOCKS5(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSOCKS5(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func serveSOCKS5(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		return
	}
	nmethods := int(buf[1])
	if _, err := io.ReadFull(c, make([]byte, nmethods)); err != nil {
		return
	}
	c.Write([]byte{0x05, 0x00}) // no-auth

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	var host string
	switch head[3] {
	case 0x01:
		b := make([]byte, 4)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		io.ReadFull(c, l)
		d := make([]byte, int(l[0]))
		io.ReadFull(c, d)
		host = string(d)
	case 0x04:
		b := make([]byte, 16)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	}
	portb := make([]byte, 2)
	io.ReadFull(c, portb)
	port := int(portb[0])<<8 | int(portb[1])
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // success

	up, err := net.Dial("tcp", net.JoinHostPort(host, itoa(port)))
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }()
	go func() { io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// startSOCKS5Auth runs a SOCKS5 relay requiring username/password auth.
func startSOCKS5Auth(t *testing.T, user, pass string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSOCKS5WithAuth(c, user, pass)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func serveSOCKS5WithAuth(c net.Conn, user, pass string) {
	defer c.Close()
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		return
	}
	methods := make([]byte, int(buf[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	c.Write([]byte{0x05, 0x02}) // require username/password

	// RFC 1929 auth negotiation.
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	u := make([]byte, int(hdr[1]))
	io.ReadFull(c, u)
	pl := make([]byte, 1)
	io.ReadFull(c, pl)
	p := make([]byte, int(pl[0]))
	io.ReadFull(c, p)
	if string(u) != user || string(p) != pass {
		c.Write([]byte{0x01, 0x01}) // auth failure
		return
	}
	c.Write([]byte{0x01, 0x00}) // auth success

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	var host string
	switch head[3] {
	case 0x01:
		b := make([]byte, 4)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		io.ReadFull(c, l)
		d := make([]byte, int(l[0]))
		io.ReadFull(c, d)
		host = string(d)
	case 0x04:
		b := make([]byte, 16)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	}
	portb := make([]byte, 2)
	io.ReadFull(c, portb)
	port := int(portb[0])<<8 | int(portb[1])
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	up, err := net.Dial("tcp", net.JoinHostPort(host, itoa(port)))
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }()
	go func() { io.Copy(c, up); done <- struct{}{} }()
	<-done
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
