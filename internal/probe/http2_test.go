package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchNegotiatesHTTP2(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	f := NewFetcher(FetcherConfig{Insecure: true, Timeout: 5 * time.Second})
	resp := f.Get(context.Background(), ts.URL)
	if resp.Err != "" {
		t.Fatalf("fetch error: %s", resp.Err)
	}
	if resp.TLS == nil {
		t.Fatal("expected TLS info")
	}
	if resp.TLS.ALPN != "h2" {
		t.Errorf("ALPN = %q, want h2", resp.TLS.ALPN)
	}
	if resp.Proto != "HTTP/2.0" {
		t.Errorf("Proto = %q, want HTTP/2.0", resp.Proto)
	}
}

func TestFetchHTTP11ALPN(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()
	// NewTLSServer (without EnableHTTP2) negotiates http/1.1.
	f := NewFetcher(FetcherConfig{Insecure: true, Timeout: 5 * time.Second})
	resp := f.Get(context.Background(), ts.URL)
	if resp.Err != "" {
		t.Fatalf("fetch error: %s", resp.Err)
	}
	if resp.TLS != nil && resp.TLS.ALPN != "" && resp.TLS.ALPN != "http/1.1" {
		t.Errorf("ALPN = %q, want http/1.1 or empty", resp.TLS.ALPN)
	}
}
