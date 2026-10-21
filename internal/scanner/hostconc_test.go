package scanner

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestHostConcurrencyCap verifies the host-level scheduler bounds how many
// distinct hosts are scanned at once. Loopback aliases 127.0.0.1-4 all reach a
// listener bound to 0.0.0.0, giving four distinct "hosts" sharing one server.
func TestHostConcurrencyCap(t *testing.T) {
	t.Setenv("NO_PROXY", "*")

	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skipf("cannot bind 0.0.0.0: %v", err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	var mu sync.Mutex
	var cur, max int
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		cur++
		if cur > max {
			max = cur
		}
		mu.Unlock()
		time.Sleep(120 * time.Millisecond)
		mu.Lock()
		cur--
		mu.Unlock()
		w.Header().Set("X-Powered-By", "PHP/8.2.0")
		_, _ = w.Write([]byte("<html></html>"))
	})
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	hosts := []string{"127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"}

	run := func(hostConc int) (peak, scanned int) {
		mu.Lock()
		cur, max = 0, 0
		mu.Unlock()
		res, err := Scan(context.Background(), hosts, Options{
			Mode: ModeDetect, TLSMode: TLSOff, Ports: []int{port},
			Timeout: 3 * time.Second, Concurrency: 10, HostConcurrency: hostConc,
		})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		mu.Lock()
		peak = max
		mu.Unlock()
		return peak, len(res.Targets)
	}

	// One host at a time: never two concurrent requests.
	if peak, scanned := run(1); peak != 1 || scanned != 4 {
		t.Fatalf("HostConcurrency=1: peak=%d (want 1), scanned=%d (want 4)", peak, scanned)
	}

	// Cap of 2: at most two hosts concurrently.
	if peak, scanned := run(2); peak > 2 || scanned != 4 {
		t.Fatalf("HostConcurrency=2: peak=%d (want <=2), scanned=%d (want 4)", peak, scanned)
	}

	// Unlimited: should actually run several hosts in parallel.
	if peak, scanned := run(0); peak < 2 || scanned != 4 {
		t.Fatalf("HostConcurrency=0: peak=%d (want >=2), scanned=%d (want 4)", peak, scanned)
	}
}
