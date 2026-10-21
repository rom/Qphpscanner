package main

import (
	"flag"
	"os"
	"strings"
	"testing"
)

// shorthands are single-letter or alias flags documented alongside their long
// form rather than on their own man-page line.
var shorthands = map[string]bool{"v": true, "q": true, "iL": true}

func flagNames() []string {
	fs := newFlagSet()
	_ = bindFlags(fs)
	var names []string
	fs.VisitAll(func(fl *flag.Flag) { names = append(names, fl.Name) })
	return names
}

func TestCompletionGeneration(t *testing.T) {
	fs := newFlagSet()
	_ = bindFlags(fs)
	for _, shell := range completionShells {
		script, err := generateCompletion(shell, fs)
		if err != nil {
			t.Fatalf("%s: %v", shell, err)
		}
		if script == "" {
			t.Fatalf("%s: empty script", shell)
		}
		// Every long flag must appear in each generated script.
		fs.VisitAll(func(fl *flag.Flag) {
			if len(fl.Name) == 1 {
				return
			}
			if !strings.Contains(script, fl.Name) {
				t.Errorf("%s completion missing flag %q", shell, fl.Name)
			}
		})
	}
	if _, err := generateCompletion("powershell", fs); err == nil {
		t.Error("expected error for an unsupported shell")
	}
}

func TestManPageDocumentsEveryFlag(t *testing.T) {
	data, err := os.ReadFile("../../docs/qphpscanner.1")
	if err != nil {
		t.Fatalf("read man page: %v", err)
	}
	// De-escape roff hyphens so "\-\-foo" reads as "--foo".
	man := strings.ReplaceAll(string(data), `\-`, "-")

	var missing []string
	for _, name := range flagNames() {
		if shorthands[name] {
			continue
		}
		if !strings.Contains(man, "--"+name) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("man page docs/qphpscanner.1 is missing flags: %s", strings.Join(missing, ", "))
	}
}

func TestHelpListsEveryFlag(t *testing.T) {
	fs := newFlagSet()
	_ = bindFlags(fs)
	var buf strings.Builder
	fs.SetOutput(&buf)
	fs.PrintDefaults()
	help := buf.String()
	for _, name := range flagNames() {
		if !strings.Contains(help, "-"+name) {
			t.Errorf("--help is missing flag %q", name)
		}
	}
}
