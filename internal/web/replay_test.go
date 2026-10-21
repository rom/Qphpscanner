package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const webCorpus = `{"schema":"qphpscanner-corpus/1","exchanges":[` +
	`{"method":"GET","url":"http://r.test:80/","status":200,"headers":{"X-Powered-By":["PHP/8.2.0"]},"body":"<title>t</title>"}]}`

func TestReplayEndpoint(t *testing.T) {
	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/replay", "application/json", strings.NewReader(webCorpus))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("replay => %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "\"result\"") || !strings.Contains(string(body), "\"is_php\":true") {
		t.Fatalf("replay result should carry a PHP detection: %s", body)
	}

	// The replayed scan is retained, so its JSON output is downloadable.
	dr, err := http.Get(srv.URL + "/api/download?format=json")
	if err != nil {
		t.Fatal(err)
	}
	defer dr.Body.Close()
	if dr.StatusCode != http.StatusOK {
		t.Fatalf("download of replayed scan => %d", dr.StatusCode)
	}
}

func TestReplayEndpointRejectsBadCorpus(t *testing.T) {
	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/api/replay", "application/json", strings.NewReader("{not a corpus"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad corpus => %d, want 400", resp.StatusCode)
	}
}

func TestCorpusDownloadAfterScan(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	// A live target so handleScan records a corpus.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2.0")
		_, _ = w.Write([]byte("<title>t</title>"))
	}))
	defer target.Close()

	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	scanResp, err := http.Post(srv.URL+"/api/scan", "application/json",
		strings.NewReader(`{"targets":["`+target.URL+`"],"mode":"deep","tls":"off"}`))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, scanResp.Body)
	scanResp.Body.Close()

	dr, err := http.Get(srv.URL + "/api/download?format=corpus")
	if err != nil {
		t.Fatal(err)
	}
	defer dr.Body.Close()
	if dr.StatusCode != http.StatusOK {
		t.Fatalf("corpus download => %d", dr.StatusCode)
	}
	body, _ := io.ReadAll(dr.Body)
	if !strings.Contains(string(body), "qphpscanner-corpus/1") {
		t.Fatalf("corpus download missing schema: %s", body)
	}
}
