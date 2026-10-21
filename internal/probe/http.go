package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultMaxBodyBytes bounds how much of a response body is read for analysis.
const DefaultMaxBodyBytes int64 = 512 * 1024

// DefaultUserAgent identifies the scanner honestly in request logs.
const DefaultUserAgent = "qphpscanner/0.1 (+https://github.com/rom/qphpscanner)"

// TLSInfo summarises the negotiated TLS parameters of a connection.
type TLSInfo struct {
	Version     string   `json:"version"`
	CipherSuite string   `json:"cipher_suite"`
	ServerName  string   `json:"server_name,omitempty"`
	PeerCN      string   `json:"peer_cn,omitempty"`
	PeerDNS     []string `json:"peer_dns,omitempty"`
	// ALPN is the application protocol negotiated over TLS ("h2",
	// "http/1.1", or empty when the server did not use ALPN).
	ALPN string `json:"alpn,omitempty"`
}

// Response is the aggregated result of fetching a URL, including evidence
// collected across any redirect hops that were followed.
type Response struct {
	RequestURL string         `json:"request_url"`
	FinalURL   string         `json:"final_url"`
	Status     int            `json:"status"`
	Proto      string         `json:"proto"`
	Header     http.Header    `json:"-"`
	Cookies    []*http.Cookie `json:"-"`
	Body       []byte         `json:"-"`
	TLS        *TLSInfo       `json:"tls,omitempty"`
	Hops       int            `json:"hops"`
	Elapsed    time.Duration  `json:"-"`
	Err        string         `json:"error,omitempty"`
}

// BodyString returns the response body as a string.
func (r *Response) BodyString() string {
	if r == nil {
		return ""
	}
	return string(r.Body)
}

// HeaderGet is a nil-safe accessor for a single header value.
func (r *Response) HeaderGet(key string) string {
	if r == nil || r.Header == nil {
		return ""
	}
	return r.Header.Get(key)
}

// HeaderValues returns every value seen for a header across all hops.
func (r *Response) HeaderValues(key string) []string {
	if r == nil || r.Header == nil {
		return nil
	}
	return r.Header.Values(key)
}

// Exchange is a single request/response hop, handed to a Recorder for audit
// trails (PCAP, session log).
type Exchange struct {
	Time        time.Time
	Method      string
	URL         string
	Host        string
	Port        int
	TLS         bool
	ReqHost     string // Host header actually sent
	ReqHeaders  http.Header
	Status      int
	Proto       string
	RespHeaders http.Header
	RespBody    []byte
	Err         string
}

// Recorder receives every HTTP exchange the Fetcher performs. Implementations
// must be safe for concurrent use.
type Recorder interface {
	Record(Exchange)
}

// Fetcher issues HTTP(S) requests with a fixed policy.
type Fetcher struct {
	client       *http.Client
	userAgent    string
	maxBody      int64
	follow       bool
	maxRedirects int
	headers      map[string]string
	cookie       string
	bearer       string
	basicUser    string
	basicPass    string
	hostHeader   string
	retries      int
	retryBackoff time.Duration
	limiter      Limiter
	recorder     Recorder
}

// FetcherConfig configures a Fetcher.
type FetcherConfig struct {
	Timeout         time.Duration
	Insecure        bool
	FollowRedirects bool
	UserAgent       string
	MaxBodyBytes    int64
	MaxRedirects    int

	// Headers are extra request headers applied to every request (they
	// override the defaults but not the per-request auth/cookie below).
	Headers map[string]string
	// Cookie is a raw Cookie header value.
	Cookie string
	// BearerToken sets "Authorization: Bearer <token>".
	BearerToken string
	// BasicUser/BasicPass set HTTP Basic auth.
	BasicUser string
	BasicPass string
	// HostHeader overrides the Host header on the initial request (vhost
	// scanning); it is not carried across redirects to other hosts.
	HostHeader string
	// ProxyURL routes requests through an http(s):// or socks5(h):// proxy.
	// Empty uses the environment proxy settings.
	ProxyURL string
	// Retries is the number of extra attempts on a transient network error.
	Retries int
	// RetryBackoff is the base backoff between retries (doubled each attempt).
	RetryBackoff time.Duration
	// Limiter, when set, gates every outbound request (global rate limiting).
	Limiter Limiter
	// Recorder, when set, receives every request/response for audit trails.
	Recorder Recorder
}

// NewFetcher builds a Fetcher. The underlying transport never follows
// redirects automatically; Get walks them explicitly so headers and cookies
// from intermediate hops are preserved as evidence.
func NewFetcher(cfg FetcherConfig) *Fetcher {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = DefaultUserAgent
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.MaxRedirects <= 0 {
		cfg.MaxRedirects = 10
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 300 * time.Millisecond
	}

	baseDialer := &net.Dialer{Timeout: cfg.Timeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:       http.ProxyFromEnvironment,
		DialContext: baseDialer.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Insecure, //nolint:gosec // opt-in for self-signed scan targets
			MinVersion:         tls.VersionTLS10,
			// Offer HTTP/2 via ALPN so the negotiated protocol is observable.
			NextProtos: []string{"h2", "http/1.1"},
		},
		// Attempt HTTP/2 even with a custom dialer/TLS config, so h2-only
		// origins are reached and the negotiated protocol is recorded.
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		DisableCompression:    false,
	}
	if cfg.ProxyURL != "" {
		if err := applyProxy(transport, baseDialer, cfg.ProxyURL); err != nil {
			// Fall back to a resolver that errors on use, so the misconfig is
			// visible per-request rather than panicking at construction.
			transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
				return nil, err
			}
		}
	}

	return &Fetcher{
		client: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
			// Never auto-follow: Get does it manually.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		userAgent:    cfg.UserAgent,
		maxBody:      cfg.MaxBodyBytes,
		follow:       cfg.FollowRedirects,
		maxRedirects: cfg.MaxRedirects,
		headers:      cfg.Headers,
		cookie:       cfg.Cookie,
		bearer:       cfg.BearerToken,
		basicUser:    cfg.BasicUser,
		basicPass:    cfg.BasicPass,
		hostHeader:   cfg.HostHeader,
		retries:      cfg.Retries,
		retryBackoff: cfg.RetryBackoff,
		limiter:      cfg.Limiter,
		recorder:     cfg.Recorder,
	}
}

func (f *Fetcher) record(req *http.Request, resp *http.Response, body []byte, errStr string, ts time.Time) {
	if f.recorder == nil {
		return
	}
	ex := Exchange{
		Time: ts, Method: req.Method, URL: req.URL.String(),
		Host: req.URL.Hostname(), Port: portOf(req.URL),
		TLS: req.URL.Scheme == "https", ReqHeaders: req.Header.Clone(), Err: errStr,
	}
	ex.ReqHost = req.Host
	if ex.ReqHost == "" {
		ex.ReqHost = req.URL.Host
	}
	if resp != nil {
		ex.Status = resp.StatusCode
		ex.Proto = resp.Proto
		ex.RespHeaders = resp.Header.Clone()
		ex.RespBody = body
	}
	f.recorder.Record(ex)
}

func portOf(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

// applyProxy configures the transport for an http(s) or socks5 proxy.
func applyProxy(t *http.Transport, base *net.Dialer, proxyURL string) error {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		t.Proxy = func(*http.Request) (*url.URL, error) { return u, nil }
		return nil
	case "socks5", "socks5h":
		d := &socks5Dialer{proxyAddr: u.Host, base: base}
		if u.User != nil {
			d.user = u.User.Username()
			d.pass, _ = u.User.Password()
		}
		t.DialContext = d.DialContext
		// A SOCKS proxy supersedes any environment HTTP proxy.
		t.Proxy = nil
		return nil
	default:
		return fmt.Errorf("unsupported proxy scheme %q (want http, https or socks5)", u.Scheme)
	}
}

// Get fetches rawURL with the GET method.
func (f *Fetcher) Get(ctx context.Context, rawURL string) *Response {
	return f.Request(ctx, http.MethodGet, rawURL)
}

// Request fetches rawURL with the given method, following redirects (when
// enabled) up to the configured limit and aggregating evidence across hops.
// Transient network failures are retried with exponential backoff.
func (f *Fetcher) Request(ctx context.Context, method, rawURL string) *Response {
	var out *Response
	for attempt := 0; ; attempt++ {
		out = f.do(ctx, method, rawURL)
		if out.Err == "" || !transientErr(out.Err) || attempt >= f.retries {
			return out
		}
		backoff := f.retryBackoff << attempt
		select {
		case <-ctx.Done():
			return out
		case <-time.After(backoff):
		}
	}
}

func transientErr(msg string) bool {
	m := strings.ToLower(msg)
	for _, s := range []string{"timeout", "timed out", "connection refused", "connection reset", "reset by peer", "eof", "no route to host", "temporarily", "broken pipe", "i/o timeout"} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

func (f *Fetcher) do(ctx context.Context, method, rawURL string) *Response {
	start := time.Now()
	out := &Response{RequestURL: rawURL, Header: http.Header{}}

	cur := rawURL
	seen := map[string]bool{}
	for hop := 0; hop <= f.maxRedirects; hop++ {
		hopStart := time.Now()
		out.Hops = hop
		req, err := http.NewRequestWithContext(ctx, method, cur, nil)
		if err != nil {
			out.Err = fmt.Sprintf("build request: %v", err)
			out.Elapsed = time.Since(start)
			return out
		}
		req.Header.Set("User-Agent", f.userAgent)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Encoding", "identity")
		for k, v := range f.headers {
			req.Header.Set(k, v)
		}
		if f.cookie != "" {
			req.Header.Set("Cookie", f.cookie)
		}
		if f.bearer != "" {
			req.Header.Set("Authorization", "Bearer "+f.bearer)
		}
		if f.basicUser != "" || f.basicPass != "" {
			req.SetBasicAuth(f.basicUser, f.basicPass)
		}
		// Host override applies only to the initial request, not to any host
		// a redirect sends us to.
		if f.hostHeader != "" && hop == 0 {
			req.Host = f.hostHeader
		}

		if f.limiter != nil {
			if err := f.limiter.Wait(ctx); err != nil {
				out.Err = cleanErr(err)
				out.Elapsed = time.Since(start)
				return out
			}
		}

		resp, err := f.client.Do(req)
		if err != nil {
			out.Err = cleanErr(err)
			f.record(req, nil, nil, out.Err, hopStart)
			out.Elapsed = time.Since(start)
			return out
		}

		// Merge evidence from this hop.
		mergeHeaders(out.Header, resp.Header)
		out.Cookies = append(out.Cookies, resp.Cookies()...)
		out.Status = resp.StatusCode
		out.Proto = resp.Proto
		out.FinalURL = cur
		if resp.TLS != nil && out.TLS == nil {
			out.TLS = describeTLS(resp.TLS)
		}

		location := resp.Header.Get("Location")
		isRedirect := resp.StatusCode >= 300 && resp.StatusCode < 400 && location != ""

		if !isRedirect || !f.follow {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, f.maxBody))
			_ = resp.Body.Close()
			out.Body = body
			f.record(req, resp, body, "", hopStart)
			out.Elapsed = time.Since(start)
			return out
		}

		// Redirect: capture a bounded prefix for the audit trail, then move on.
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		f.record(req, resp, rb, "", hopStart)

		next, err := resolveLocation(cur, location)
		if err != nil {
			out.Err = fmt.Sprintf("bad redirect target %q: %v", location, err)
			out.Elapsed = time.Since(start)
			return out
		}
		if seen[next] {
			out.Err = "redirect loop detected"
			out.Elapsed = time.Since(start)
			return out
		}
		seen[cur] = true
		cur = next
	}

	out.Err = "too many redirects"
	out.Elapsed = time.Since(start)
	return out
}

func resolveLocation(base, loc string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	l, err := url.Parse(loc)
	if err != nil {
		return "", err
	}
	return b.ResolveReference(l).String(), nil
}

func mergeHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func cleanErr(err error) string {
	s := err.Error()
	// Trim the noisy URL-prefixed wrapper the http client adds.
	if i := strings.Index(s, ": "); i > 0 && strings.HasPrefix(s, "Get ") {
		return s[i+2:]
	}
	return s
}

func describeTLS(cs *tls.ConnectionState) *TLSInfo {
	info := &TLSInfo{
		Version:     tlsVersionName(cs.Version),
		CipherSuite: tls.CipherSuiteName(cs.CipherSuite),
		ServerName:  cs.ServerName,
		ALPN:        cs.NegotiatedProtocol,
	}
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		info.PeerCN = leaf.Subject.CommonName
		info.PeerDNS = leaf.DNSNames
	}
	return info
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
