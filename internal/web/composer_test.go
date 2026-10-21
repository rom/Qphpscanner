package web

import "testing"

func TestComposerFilesFromUploads(t *testing.T) {
	out := composerFilesFromUploads([]composerUpload{
		{Name: "composer.lock", Content: `{"packages":[]}`},
		{Name: "", Content: "  "},                                                   // empty content → skipped
		{Name: "big.json", Content: string(make([]byte, maxComposerUploadBytes+1))}, // oversized → skipped
		{Name: "", Content: `{"require":{}}`},                                       // blank name → labelled "upload"
	})
	if len(out) != 2 {
		t.Fatalf("want 2 kept uploads, got %d (%+v)", len(out), out)
	}
	if out[0].Name != "composer.lock" {
		t.Errorf("first upload name = %q", out[0].Name)
	}
	if out[1].Name != "upload" {
		t.Errorf("blank name should default to 'upload', got %q", out[1].Name)
	}
}

func TestBuildOptionsComposerFiles(t *testing.T) {
	s := NewServer("127.0.0.1:0")
	opts, targets, err := s.buildOptions(scanRequest{
		Targets:       []string{"example.com"},
		Mode:          "deep",
		ComposerFiles: []composerUpload{{Name: "composer.json", Content: `{"require":{"php":"^8.1"}}`}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("targets = %v", targets)
	}
	if len(opts.ComposerFiles) != 1 || opts.ComposerFiles[0].Name != "composer.json" {
		t.Fatalf("composer files not threaded into options: %+v", opts.ComposerFiles)
	}
}
