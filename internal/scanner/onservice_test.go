package scanner

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOnServiceStreamsAllOutcomes(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts := phpTestServer()
	defer ts.Close()
	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	openPort, _ := strconv.Atoi(portStr)

	// A reliably-closed port: bind then release.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	var mu sync.Mutex
	var got []ServiceResult
	_, err = Scan(context.Background(), []string{"127.0.0.1"}, Options{
		Mode: ModeDetect, TLSMode: TLSOff,
		Ports:   []int{openPort, closedPort},
		Timeout: 2 * time.Second,
		// IncludeClosed is false: the closed port is excluded from the final
		// output but OnService must still see it.
		OnService: func(r ServiceResult) {
			mu.Lock()
			got = append(got, r)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("OnService called %d times, want 2 (open + closed)", len(got))
	}
	var sawOpenHTTP, sawClosed bool
	for _, r := range got {
		if r.Port == openPort && r.PortOpen && r.HTTP != nil {
			sawOpenHTTP = true
		}
		if r.Port == closedPort && !r.PortOpen {
			sawClosed = true
		}
	}
	if !sawOpenHTTP {
		t.Error("expected an open HTTP service via OnService")
	}
	if !sawClosed {
		t.Error("expected the closed port reported via OnService (even with IncludeClosed off)")
	}
}

func TestOnHostResolvedAndCheckedAt(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts := phpTestServer()
	defer ts.Close()

	var mu sync.Mutex
	hostPTR := map[string][]string{}
	var svcCount, timed int

	before := time.Now().Add(-2 * time.Second)
	res, err := Scan(context.Background(), []string{ts.URL}, Options{
		Mode: ModeDetect, TLSMode: TLSOff, Timeout: 3 * time.Second,
		ResolveDNS: true,
		Resolver:   fakeDNS{ptr: map[string][]string{"127.0.0.1": {"localhost"}}},
		OnHostResolved: func(host string, _, ptr []string) {
			mu.Lock()
			hostPTR[host] = ptr
			mu.Unlock()
		},
		OnService: func(r ServiceResult) {
			mu.Lock()
			svcCount++
			if !r.CheckedAt.IsZero() {
				timed++
			}
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// The host's reverse name resolves and is streamed before its services —
	// this is what lets an IP target show its hostname during the scan.
	ptr, ok := hostPTR["127.0.0.1"]
	if !ok {
		t.Fatalf("OnHostResolved not called for 127.0.0.1; got %v", hostPTR)
	}
	if len(ptr) != 1 || ptr[0] != "localhost" {
		t.Fatalf("OnHostResolved ptr = %v, want [localhost]", ptr)
	}

	// Every streamed service carries a scan timestamp.
	if svcCount == 0 || timed != svcCount {
		t.Fatalf("CheckedAt set on %d/%d services, want all", timed, svcCount)
	}
	for _, tr := range res.Targets {
		for _, svc := range tr.Services {
			if svc.CheckedAt.IsZero() || svc.CheckedAt.Before(before) {
				t.Errorf("service %s:%d CheckedAt %v not within the scan window (>= %v)",
					svc.Host, svc.Port, svc.CheckedAt, before)
			}
		}
	}
}

func TestOnHostResolvedSkippedWithoutResolveDNS(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts := phpTestServer()
	defer ts.Close()

	called := false
	_, err := Scan(context.Background(), []string{ts.URL}, Options{
		Mode: ModeDetect, TLSMode: TLSOff, Timeout: 3 * time.Second,
		Resolver:       fakeDNS{ptr: map[string][]string{"127.0.0.1": {"localhost"}}},
		OnHostResolved: func(string, []string, []string) { called = true },
	})
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("OnHostResolved fired without ResolveDNS enabled")
	}
}
