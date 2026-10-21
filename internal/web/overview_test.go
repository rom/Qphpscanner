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

func TestVersionEndpoint(t *testing.T) {
	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	var v map[string]string
	if code := getJSON(t, srv.URL+"/api/version", &v); code != 200 {
		t.Fatalf("version status %d", code)
	}
	if v["name"] == "" || v["version"] == "" {
		t.Errorf("version payload incomplete: %+v", v)
	}

	// Wrong method on a known endpoint is a clean 405, not an opaque file-server
	// response.
	resp, err := http.Post(srv.URL+"/api/version", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Errorf("POST /api/version => %d, want 405", resp.StatusCode)
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

func TestScanStreamsServiceMessages(t *testing.T) {
	target := phpTarget()
	defer target.Close()
	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// Scan an open PHP target plus a closed port; both should stream as
	// "service" messages even though include_closed is off.
	host := strings.TrimPrefix(target.URL, "http://")
	h, portStr, _ := strings.Cut(host, ":")
	_ = portStr
	body := `{"targets":["` + h + `"],"ports":"` + portStr + `,1","mode":"detect","tls":"off","security_txt":false}`

	resp, err := http.Post(srv.URL+"/api/scan", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var services, open, closed int
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var msg streamMsg
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("bad NDJSON: %v", err)
		}
		if msg.Type == "service" && msg.Service != nil {
			services++
			if msg.Service.PortOpen {
				open++
			} else {
				closed++
			}
		}
	}
	if services < 2 {
		t.Fatalf("expected >=2 service messages, got %d", services)
	}
	if open == 0 || closed == 0 {
		t.Errorf("expected both open (%d) and closed (%d) services streamed", open, closed)
	}
}

func TestOverviewBreakdownsAndUploadDiff(t *testing.T) {
	target := phpTarget()
	defer target.Close()
	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	body := `{"targets":["` + target.URL + `"],"mode":"deep","tls":"off","security_txt":false}`
	runScan(t, srv.URL, body)

	// Overview now carries severity/verdict breakdowns for the charts.
	var ov overview
	getJSON(t, srv.URL+"/api/overview", &ov)
	if ov.Stats.VerdictBreakdown["confirmed"] == 0 {
		t.Errorf("verdict_breakdown missing confirmed: %+v", ov.Stats.VerdictBreakdown)
	}
	if len(ov.Stats.SeverityBreakdown) == 0 {
		t.Errorf("severity_breakdown empty: %+v", ov.Stats.SeverityBreakdown)
	}
	// PHP-per-port breakdown is keyed by scheme/port and totals the PHP services.
	if len(ov.Stats.PHPByPort) == 0 {
		t.Errorf("php_by_port empty: %+v", ov.Stats.PHPByPort)
	} else {
		total := 0
		for _, n := range ov.Stats.PHPByPort {
			total += n
		}
		if total != ov.Stats.PHPServices {
			t.Errorf("php_by_port totals %d, want php_services %d (%+v)", total, ov.Stats.PHPServices, ov.Stats.PHPByPort)
		}
	}

	// Download the scan as JSON, then diff that uploaded file against the
	// retained latest scan.
	dr, err := http.Get(srv.URL + "/api/download?format=json")
	if err != nil {
		t.Fatal(err)
	}
	saved, _ := io.ReadAll(dr.Body)
	dr.Body.Close()

	resp, err := http.Post(srv.URL+"/api/diff-upload?b=latest", "application/octet-stream", strings.NewReader(string(saved)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("diff-upload status %d", resp.StatusCode)
	}
	var d map[string]interface{}
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := d["diff"]; !ok {
		t.Errorf("diff-upload response missing diff: %s", data)
	}

	// Also accept the XML form.
	xr, _ := http.Get(srv.URL + "/api/download?format=xml")
	xdata, _ := io.ReadAll(xr.Body)
	xr.Body.Close()
	xresp, err := http.Post(srv.URL+"/api/diff-upload?b=latest", "application/xml", strings.NewReader(string(xdata)))
	if err != nil {
		t.Fatal(err)
	}
	defer xresp.Body.Close()
	if xresp.StatusCode != 200 {
		t.Fatalf("diff-upload (xml) status %d", xresp.StatusCode)
	}
}
