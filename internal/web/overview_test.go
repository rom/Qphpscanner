package web

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// runScan drives one scan through the API and drains the NDJSON stream.
func runScan(t *testing.T, base, body string) {
	t.Helper()
	resp, err := http.Post(base+"/api/scan", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("scan status %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var msg streamMsg
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("bad NDJSON: %v", err)
		}
		if msg.Type == "error" {
			t.Fatalf("scan error: %s", msg.Error)
		}
	}
}

func getJSON(t *testing.T, url string, out interface{}) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if len(data) > 0 && out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("decode %s: %v (%s)", url, err, data)
		}
	}
	return resp.StatusCode
}

func TestOverviewAndDiff(t *testing.T) {
	target := phpTarget()
	defer target.Close()
	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	body := `{"targets":["` + target.URL + `"],"mode":"deep","tls":"off","security_txt":false}`
	runScan(t, srv.URL, body)
	runScan(t, srv.URL, body)

	// Overview aggregates across the two retained scans.
	var ov overview
	if code := getJSON(t, srv.URL+"/api/overview", &ov); code != 200 {
		t.Fatalf("overview status %d", code)
	}
	if ov.Stats.Scans != 2 {
		t.Errorf("stats.scans = %d, want 2", ov.Stats.Scans)
	}
	if ov.Stats.Services == 0 {
		t.Error("overview reported no services")
	}
	if ov.Stats.OldestPHP == nil || ov.Stats.OldestPHP.Version == "" {
		t.Error("overview missing oldest PHP version")
	}
	if len(ov.Stats.TopNetworks) == 0 {
		t.Error("overview missing top networks")
	}

	// Diff latest against itself: no changes.
	var d map[string]interface{}
	if code := getJSON(t, srv.URL+"/api/diff?a=latest&b=latest", &d); code != 200 {
		t.Fatalf("diff status %d", code)
	}
	if _, ok := d["diff"]; !ok {
		t.Errorf("diff response missing diff key: %v", d)
	}

	// Diff with a missing scan id is a clean 400.
	if code := getJSON(t, srv.URL+"/api/diff?a=latest&b=scan-does-not-exist", nil); code != 400 {
		t.Errorf("diff with bad id => %d, want 400", code)
	}
}

func TestScanBlockListDropsTarget(t *testing.T) {
	target := phpTarget()
	defer target.Close()
	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// Block everything via a catch-all suffix so no service is scanned.
	host := strings.TrimPrefix(target.URL, "http://")
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	body := `{"targets":["` + target.URL + `"],"mode":"detect","tls":"off","security_txt":false,"block":["` + host + `"]}`
	runScan(t, srv.URL, body)

	var ov overview
	getJSON(t, srv.URL+"/api/overview", &ov)
	// The most recent scan contributed no services (blocked), so the service
	// total should remain 0 for this fresh server.
	if ov.Stats.Services != 0 {
		t.Errorf("blocked scan still produced %d services", ov.Stats.Services)
	}
}
