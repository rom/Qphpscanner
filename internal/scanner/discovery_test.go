package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rom/qphpscanner/internal/php"
)

// pathRecorder is an httptest handler that records every requested path and
// serves a configurable response, for driving adaptive discovery without a real
// network or real targets.
type pathRecorder struct {
	mu    sync.Mutex
	paths map[string]int
	// handler returns (status, body, extraHeaders) for a given method+path.
	handler func(method, path string) (int, string, map[string]string)
}

func newPathRecorder(h func(method, path string) (int, string, map[string]string)) *pathRecorder {
	return &pathRecorder{paths: map[string]int{}, handler: h}
}

func (p *pathRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.paths[r.URL.Path]++
	p.mu.Unlock()
	status, body, hdrs := p.handler(r.Method, r.URL.Path)
	for k, v := range hdrs {
		w.Header().Set(k, v)
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (p *pathRecorder) requested(path string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.paths[path] > 0
}

func (p *pathRecorder) total() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, c := range p.paths {
		n += c
	}
	return n
}

// wordpressRoot serves a WordPress landing page on "/" and a plain 404 for
// anything else — so detection triggers WordPress from the root, and the deep
// probes resolve to 404s we can still observe as "requested".
func wordpressRoot(method, path string) (int, string, map[string]string) {
	if path == "/" {
		return 200, `<html><head><meta name="generator" content="WordPress 6.4.2">` +
				`</head><body><link href="/wp-content/themes/x/style.css"></body></html>`,
			map[string]string{"X-Powered-By": "PHP/8.2.4", "Content-Type": "text/html"}
	}
	return 404, "not found", nil
}

func TestAdaptiveDiscoveryIssuesAppProbesOnlyAfterTrigger(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	rec := newPathRecorder(wordpressRoot)
	ts := httptest.NewServer(rec)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := Scan(ctx, []string{ts.URL}, Options{
		Mode: ModeDeep, TLSMode: TLSOff, Timeout: 5 * time.Second, Concurrency: 4,
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// WordPress showed itself at the root, so its conditional probes must fire.
	for _, p := range []string{"/wp-login.php", "/wp-json/", "/xmlrpc.php", "/readme.html"} {
		if !rec.requested(p) {
			t.Errorf("expected WordPress-triggered probe %q to be issued", p)
		}
	}
	// Apps that never showed themselves must NOT be probed.
	for _, p := range []string{"/magento_version", "/telescope", "/horizon", "/administrator/", "/phpmyadmin/", "/adminer.php"} {
		if rec.requested(p) {
			t.Errorf("probe %q should not be issued without a trigger signal", p)
		}
	}
	// The generic core set is always issued.
	for _, p := range []string{"/composer.json", "/.env", "/opcache.php", php.ControlProbePath} {
		if !rec.requested(p) {
			t.Errorf("expected core probe %q to be issued", p)
		}
	}
}

func TestRequestBudgetCapsAndRecords(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	rec := newPathRecorder(wordpressRoot)
	ts := httptest.NewServer(rec)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := Scan(ctx, []string{ts.URL}, Options{
		Mode: ModeDeep, TLSMode: TLSOff, Timeout: 5 * time.Second,
		RequestBudget: 3,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Meta.RequestBudget != 3 {
		t.Errorf("Meta.RequestBudget = %d, want 3", res.Meta.RequestBudget)
	}
	svc := res.Targets[0].Services[0]
	if svc.Discovery == nil {
		t.Fatal("expected Discovery to be recorded under a budget")
	}
	if svc.Discovery.Limited != "budget" {
		t.Errorf("Discovery.Limited = %q, want budget", svc.Discovery.Limited)
	}
	if svc.Discovery.Budget != 3 || svc.Discovery.ProbesIssued != 3 {
		t.Errorf("Discovery = %+v, want budget 3 / issued 3", svc.Discovery)
	}
	// The host saw at most the root plus the budgeted probes — never the whole
	// deep catalogue.
	if n := rec.total(); n > 1+3 {
		t.Errorf("host received %d requests, budget should cap it at %d", n, 1+3)
	}
	// WordPress-triggered probes never got a chance (budget spent in phase 1).
	if rec.requested("/wp-login.php") {
		t.Error("app probe issued despite an exhausted budget")
	}
}

func TestRetryAfterShortCircuitsOptionalProbes(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	rec := newPathRecorder(func(method, path string) (int, string, map[string]string) {
		switch {
		case path == "/":
			return 200, `<html><body><link href="/wp-content/x.css"></body></html>`,
				map[string]string{"X-Powered-By": "PHP/8.2.4"}
		case path == "/server-status":
			// First optional probe pushes back with a Retry-After.
			return 503, "busy", map[string]string{"Retry-After": "5"}
		default:
			return 404, "nope", nil
		}
	})
	ts := httptest.NewServer(rec)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := Scan(ctx, []string{ts.URL}, Options{
		Mode: ModeDeep, TLSMode: TLSOff, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	svc := res.Targets[0].Services[0]
	if svc.Discovery == nil || svc.Discovery.Limited != "retry-after" {
		t.Fatalf("expected retry-after limiting, got %+v", svc.Discovery)
	}
	if svc.Discovery.RetryAfterMS != 5000 {
		t.Errorf("RetryAfterMS = %d, want 5000", svc.Discovery.RetryAfterMS)
	}
	// Optional probes issued after the 503 must be skipped.
	for _, p := range []string{"/composer.json", "/.env", "/wp-login.php", "/favicon.ico"} {
		if rec.requested(p) {
			t.Errorf("probe %q should be skipped after a Retry-After back-off", p)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if d, ok := parseRetryAfter("7", now); !ok || d != 7*time.Second {
		t.Errorf("seconds: %v %v", d, ok)
	}
	if d, ok := parseRetryAfter("  12 ", now); !ok || d != 12*time.Second {
		t.Errorf("trimmed seconds: %v %v", d, ok)
	}
	if d, ok := parseRetryAfter("-3", now); !ok || d != 0 {
		t.Errorf("negative seconds should clamp to 0: %v %v", d, ok)
	}
	if _, ok := parseRetryAfter("", now); ok {
		t.Error("empty should be absent")
	}
	if _, ok := parseRetryAfter("not-a-date", now); ok {
		t.Error("garbage should be absent")
	}
	future := now.Add(30 * time.Second).UTC().Format(http.TimeFormat)
	if d, ok := parseRetryAfter(future, now); !ok || d != 30*time.Second {
		t.Errorf("http-date: %v %v", d, ok)
	}
	past := now.Add(-time.Hour).UTC().Format(http.TimeFormat)
	if d, ok := parseRetryAfter(past, now); !ok || d != 0 {
		t.Errorf("past http-date should clamp to 0: %v %v", d, ok)
	}
}

func TestDetectedApps(t *testing.T) {
	if len(detectedApps(nil)) != 0 {
		t.Error("nil detection should yield an empty set")
	}
	d := &php.Detection{Frameworks: []string{"WordPress"}, Addons: []string{"phpMyAdmin"}}
	apps := detectedApps(d)
	if !apps["wordpress"] || !apps["phpmyadmin"] {
		t.Fatalf("expected lowercased framework+addon set, got %v", apps)
	}
}
