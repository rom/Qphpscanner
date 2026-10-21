package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestReadComposerFiles(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "composer.lock")
	if err := os.WriteFile(lock, []byte(`{"packages":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A blank entry is skipped; the real file is read with its path as the name.
	out, err := readComposerFiles([]string{lock, "  "})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Name != lock {
		t.Fatalf("read composer files: %+v", out)
	}
	if string(out[0].Data) != `{"packages":[]}` {
		t.Fatalf("content = %q", out[0].Data)
	}

	// A missing file is an error.
	if _, err := readComposerFiles([]string{filepath.Join(dir, "nope.json")}); err == nil {
		t.Fatal("expected an error for a missing composer file")
	}

	// An oversized file is rejected.
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, bytes.Repeat([]byte("x"), maxComposerFileBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readComposerFiles([]string{big}); err == nil {
		t.Fatal("expected an error for an oversized composer file")
	}
}

func TestRunComposerFile(t *testing.T) {
	ts := phpServer()
	defer ts.Close()
	dir := t.TempDir()
	lock := filepath.Join(dir, "composer.lock")
	_ = os.WriteFile(lock, []byte(`{"packages":[{"name":"guzzlehttp/guzzle","version":"7.4.0"}]}`), 0o644)
	out := filepath.Join(dir, "o.json")
	if err := run([]string{"--quiet", "--mode", "deep", "--composer-file", lock, "--format", "json", "--out", out, ts.URL}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out)
	if !bytes.Contains(data, []byte("guzzlehttp/guzzle")) {
		t.Fatalf("supplied composer package should appear in output:\n%s", data)
	}
	if !bytes.Contains(data, []byte("CVE-2022-31042")) {
		t.Fatal("expected a package advisory lead for guzzle 7.4.0 in output")
	}
}
