package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/qphpscanner/internal/probe"
	"github.com/rom/qphpscanner/internal/replay"
)

func TestRecordThenReplayRoundTrip(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("X-Powered-By", "PHP/8.2.4")
			http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "supersecretsession"})
			_, _ = w.Write([]byte("<html><head><meta name='generator' content='WordPress 6.4'></head>" +
				"<body><link href='/wp-content/x.css'></body></html>"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	dir := t.TempDir()
	corpusPath := filepath.Join(dir, "corpus.json")
	logPath := filepath.Join(dir, "scan.log") // exercise the multi-recorder fan-out

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	live, err := Scan(ctx, []string{ts.URL}, Options{
		Mode: ModeDeep, TLSMode: TLSOff, Timeout: 5 * time.Second,
		RecordPath: corpusPath, LogPath: logPath,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	liveSvc := live.Targets[0].Services[0]
	if liveSvc.PHP == nil || !liveSvc.PHP.IsPHP {
		t.Fatalf("live scan should detect PHP: %+v", liveSvc.PHP)
	}

	// The corpus file was written and sanitised (no cookie value).
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	if strings.Contains(string(raw), "supersecretsession") {
		t.Error("cookie value leaked into the recorded corpus")
	}

	// Replay the corpus offline and confirm it reproduces the detection.
	corpus, err := replay.Load(corpusPath)
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	res, err := ReplayCorpus(corpus, Options{})
	if err != nil {
		t.Fatalf("ReplayCorpus: %v", err)
	}
	if len(res.Targets) != 1 {
		t.Fatalf("want 1 replayed target, got %d", len(res.Targets))
	}
	svc := res.Targets[0].Services[0]
	if svc.PHP == nil || !svc.PHP.IsPHP {
		t.Fatalf("replay should reproduce PHP detection: %+v", svc.PHP)
	}
	foundWP := false
	for _, f := range svc.PHP.Frameworks {
		if f == "WordPress" {
			foundWP = true
		}
	}
	if !foundWP {
		t.Errorf("replay should reproduce WordPress: %v", svc.PHP.Frameworks)
	}
	if res.Meta.Mode != ModeDeep || res.Summary.PHPConfirmed+res.Summary.PHPLikely < 1 {
		t.Errorf("replay ScanResult meta/summary unexpected: %+v %+v", res.Meta, res.Summary)
	}
}

func TestSplitOrigin(t *testing.T) {
	cases := []struct {
		origin string
		scheme string
		host   string
		port   int
	}{
		{"http://h:8080", "http", "h", 8080},
		{"https://h", "https", "h", 443},
		{"http://h", "http", "h", 80},
		{"https://[2001:db8::1]:9443", "https", "2001:db8::1", 9443},
	}
	for _, c := range cases {
		s, h, p := splitOrigin(c.origin)
		if s != c.scheme || h != c.host || p != c.port {
			t.Errorf("splitOrigin(%q) = %s/%s/%d, want %s/%s/%d", c.origin, s, h, p, c.scheme, c.host, c.port)
		}
	}
}

func TestCombineRecorders(t *testing.T) {
	if combineRecorders(nil) != nil {
		t.Error("no recorders => nil")
	}
	one := replay.NewRecorder()
	two := replay.NewRecorder()
	if combineRecorders([]probe.Recorder{one}) != one {
		t.Error("single recorder should be returned as-is")
	}
	m := combineRecorders([]probe.Recorder{one, two})
	if _, ok := m.(multiRecorder); !ok {
		t.Fatalf("multiple recorders should fan out, got %T", m)
	}
	// The fan-out delivers to every recorder.
	m.Record(probe.Exchange{Method: "GET", URL: "http://h/", Status: 200})
	if len(one.Corpus().Exchanges) != 1 || len(two.Corpus().Exchanges) != 1 {
		t.Error("fan-out did not reach every recorder")
	}
}
