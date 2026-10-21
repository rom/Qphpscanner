package main

import (
	"flag"
	"fmt"
	"sort"
	"strings"
)

// completionShells lists the shells for which --completion can emit a script.
var completionShells = []string{"bash", "zsh", "fish"}

type flagDoc struct {
	name  string
	usage string
}

// collectFlagDocs returns every registered flag, sorted by name.
func collectFlagDocs(fs *flag.FlagSet) []flagDoc {
	var out []flagDoc
	fs.VisitAll(func(fl *flag.Flag) {
		out = append(out, flagDoc{name: fl.Name, usage: firstLine(fl.Usage)})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// generateCompletion renders a completion script for the given shell from the
// live flag set, so it never drifts from the actual options.
func generateCompletion(shell string, fs *flag.FlagSet) (string, error) {
	docs := collectFlagDocs(fs)
	switch shell {
	case "bash":
		return bashCompletion(docs), nil
	case "zsh":
		return zshCompletion(docs), nil
	case "fish":
		return fishCompletion(docs), nil
	default:
		return "", fmt.Errorf("unsupported shell %q (want %s)", shell, strings.Join(completionShells, ", "))
	}
}

func longOpts(docs []flagDoc) []string {
	var opts []string
	for _, d := range docs {
		if len(d.name) == 1 {
			opts = append(opts, "-"+d.name)
		} else {
			opts = append(opts, "--"+d.name)
		}
	}
	return opts
}

func bashCompletion(docs []flagDoc) string {
	opts := strings.Join(longOpts(docs), " ")
	return `# bash completion for qphpscanner
# install: source <(qphpscanner --completion bash)
_qphpscanner() {
    local cur opts
    cur="${COMP_WORDS[COMP_CWORD]}"
    opts="` + opts + `"
    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
        return 0
    fi
    COMPREPLY=( $(compgen -f -- "$cur") )
}
complete -o default -F _qphpscanner qphpscanner
`
}

func zshCompletion(docs []flagDoc) string {
	var b strings.Builder
	b.WriteString("#compdef qphpscanner\n")
	b.WriteString("# zsh completion for qphpscanner\n")
	b.WriteString("# install: qphpscanner --completion zsh > \"${fpath[1]}/_qphpscanner\"\n")
	b.WriteString("_qphpscanner() {\n  local -a opts\n  opts=(\n")
	for _, d := range docs {
		flagName := "--" + d.name
		if len(d.name) == 1 {
			flagName = "-" + d.name
		}
		b.WriteString("    '" + flagName + "[" + zshEscape(d.usage) + "]'\n")
	}
	b.WriteString("  )\n  _arguments -s $opts '*:target or file:_files'\n}\n_qphpscanner \"$@\"\n")
	return b.String()
}

func zshEscape(s string) string {
	r := strings.NewReplacer("'", "", "[", "(", "]", ")", ":", ";")
	return r.Replace(s)
}

func fishCompletion(docs []flagDoc) string {
	var b strings.Builder
	b.WriteString("# fish completion for qphpscanner\n")
	b.WriteString("# install: qphpscanner --completion fish > ~/.config/fish/completions/qphpscanner.fish\n")
	for _, d := range docs {
		line := "complete -c qphpscanner"
		if len(d.name) == 1 {
			line += " -s " + d.name
		} else {
			line += " -l " + d.name
		}
		if d.usage != "" {
			line += " -d '" + strings.ReplaceAll(d.usage, "'", "") + "'"
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}
