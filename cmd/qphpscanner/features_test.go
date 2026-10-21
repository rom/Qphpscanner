package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadTargetsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(path, []byte("a.com\n# comment\n\n  b.com  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readTargetsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "a.com" || got[1] != "b.com" {
		t.Fatalf("file targets: %v", got)
	}
	if out, _ := readTargetsFile(""); out != nil {
		t.Fatal("empty path should yield nil")
	}
	if _, err := readTargetsFile("/no/such/file"); err == nil {
		t.Fatal("missing file should error")
	}
}

func TestReadTargetsStdin(t *testing.T) {
	r, w, _ := os.Pipe()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	go func() {
		_, _ = w.WriteString("x.com\nY.com\n")
		_ = w.Close()
	}()
	got, err := readTargetsFile("-")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "x.com" {
		t.Fatalf("stdin targets: %v", got)
	}
}

func TestSmallHelpers(t *testing.T) {
	m := parseHeaders(stringSlice{"X-A: 1", "Bad", "X-B:2"})
	if m["X-A"] != "1" || m["X-B"] != "2" || len(m) != 2 {
		t.Fatalf("parseHeaders: %v", m)
	}
	if parseHeaders(nil) != nil {
		t.Fatal("nil headers")
	}
	u, p := splitColon("user:pass:word")
	if u != "user" || p != "pass:word" {
		t.Fatalf("splitColon: %q %q", u, p)
	}
	u2, p2 := splitColon("solo")
	if u2 != "solo" || p2 != "" {
		t.Fatalf("splitColon solo: %q %q", u2, p2)
	}
	for _, ok := range []string{"", "low", "medium", "high", "critical", "eol"} {
		if err := validateFailOn(ok); err != nil {
			t.Fatalf("validateFailOn(%q): %v", ok, err)
		}
	}
	if validateFailOn("nope") == nil {
		t.Fatal("invalid fail-on should error")
	}
}

func TestRunTargetsFile(t *testing.T) {
	ts := phpServer()
	defer ts.Close()
	dir := t.TempDir()
	tf := filepath.Join(dir, "t.txt")
	_ = os.WriteFile(tf, []byte(ts.URL+"\n"), 0o644)
	out := filepath.Join(dir, "o.json")
	if err := run([]string{"--quiet", "--targets-file", tf, "--format", "json", "--out", out}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("no output written: %v", err)
	}
}

func TestRunOAll(t *testing.T) {
	ts := phpServer()
	defer ts.Close()
	dir := t.TempDir()
	base := filepath.Join(dir, "scan")
	if err := run([]string{"--quiet", "--oA", base, ts.URL}); err != nil {
		t.Fatal(err)
	}
	for _, ext := range []string{".json", ".xml", ".csv", ".sarif", ".txt", ".html"} {
		if _, err := os.Stat(base + ext); err != nil {
			t.Fatalf("missing %s: %v", ext, err)
		}
	}
}

func TestRunFailOn(t *testing.T) {
	ts := phpServer() // advertises PHP/8.2.0 → vulnerable to several leads
	defer ts.Close()
	dir := t.TempDir()
	out := filepath.Join(dir, "o.json")
	err := run([]string{"--quiet", "--mode", "deep", "--fail-on", "critical", "--out", out, ts.URL})
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 2 {
		t.Fatalf("expected exitError code 2, got %v", err)
	}
	// Output is still produced despite the gate.
	if _, serr := os.Stat(out); serr != nil {
		t.Fatalf("output should still be written: %v", serr)
	}
}

func TestRunDiff(t *testing.T) {
	ts := phpServer()
	defer ts.Close()
	dir := t.TempDir()
	base := filepath.Join(dir, "base.json")
	if err := run([]string{"--quiet", "--format", "json", "--out", base, ts.URL}); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := run([]string{"--quiet", "--diff", base, ts.URL}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "SCAN DIFF") {
		t.Fatalf("diff output missing header:\n%s", out)
	}
}

func TestRunVulnFeed(t *testing.T) {
	ts := phpServer()
	defer ts.Close()
	dir := t.TempDir()
	feed := filepath.Join(dir, "feed.json")
	_ = os.WriteFile(feed, []byte(`{"schema":"qphpscanner-vuln-feed/1","php":[{"id":"CVE-TEST","severity":"high","title":"t","affected":[{"branch":"8.2","lt":"8.2.99"}]}]}`), 0o644)
	out := filepath.Join(dir, "o.json")
	if err := run([]string{"--quiet", "--mode", "deep", "--vuln-feed", feed, "--format", "json", "--out", out, ts.URL}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out)
	if !strings.Contains(string(data), "CVE-TEST") {
		t.Fatal("feed-provided CVE should appear in output")
	}
}

func TestRunSignaturePack(t *testing.T) {
	ts := phpServer()
	defer ts.Close()
	dir := t.TempDir()
	pack := filepath.Join(dir, "pack.json")
	_ = os.WriteFile(pack, []byte(`{"schema":"qphpscanner-signature-pack/1","id":"cli-pack","version":"1.0","headers":[{"header":"X-Cli-Pack","php":true,"weight":40,"detail":"cli pack header"}]}`), 0o644)
	out := filepath.Join(dir, "o.json")
	if err := run([]string{"--quiet", "--signature-pack", pack, "--format", "json", "--out", out, ts.URL}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out)
	if !strings.Contains(string(data), "cli-pack@1.0") {
		t.Fatal("signature-pack id should be stamped into scan meta")
	}
	// A broken pack is a hard error, not a silent skip.
	if err := run([]string{"--quiet", "--signature-pack", "/no/such/pack.json", ts.URL}); err == nil {
		t.Fatal("expected error for a missing signature pack")
	}
}

func TestRunRecordAndReplayCorpus(t *testing.T) {
	ts := phpServer()
	defer ts.Close()
	dir := t.TempDir()
	corpusPath := filepath.Join(dir, "corpus.json")

	// Record a corpus during a live scan.
	if err := run([]string{"--quiet", "--mode", "deep", "--record-corpus", corpusPath, ts.URL}); err != nil {
		t.Fatalf("record: %v", err)
	}
	data, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("corpus not written: %v", err)
	}
	if !strings.Contains(string(data), "qphpscanner-replay-corpus/1") {
		t.Fatalf("corpus missing schema: %s", data)
	}

	// Replay it offline and confirm the PHP version is reproduced.
	out := filepath.Join(dir, "replay.json")
	if err := run([]string{"--quiet", "--replay-corpus", corpusPath, "--format", "json", "--out", out}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	replayed, _ := os.ReadFile(out)
	if !strings.Contains(string(replayed), "8.2.0") {
		t.Fatalf("replay output should reproduce the PHP version:\n%s", replayed)
	}

	// A malformed corpus is a hard error.
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte(`{"schema":"other/9"}`), 0o644)
	if err := run([]string{"--quiet", "--replay-corpus", bad}); err == nil {
		t.Fatal("expected error for a bad-schema corpus")
	}
}

func TestRunBadVulnFeed(t *testing.T) {
	ts := phpServer()
	defer ts.Close()
	if err := run([]string{"--quiet", "--vuln-feed", "/no/such/feed.json", ts.URL}); err == nil {
		t.Fatal("expected error for missing feed")
	}
	if err := run([]string{"--quiet", "--fail-on", "bogus", ts.URL}); err == nil {
		t.Fatal("expected error for invalid fail-on")
	}
}
