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
