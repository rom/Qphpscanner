package php

import (
	"html"
	"regexp"
	"strings"
)

// PHPInfoFacts holds values read directly from an exposed phpinfo() page. These
// are OBSERVED (straight from the page), as opposed to the inferred guesses the
// rest of detection makes from headers — the two are kept separate on purpose.
// Only an allow-list of security-relevant ini directives is captured, and
// values that look like credentials are redacted, so secrets are not retained.
type PHPInfoFacts struct {
	// SAPI is the observed "Server API" (e.g. "FPM/FastCGI", "apache2handler").
	SAPI string `json:"sapi,omitempty" xml:"sapi,omitempty"`
	// System is the uname line (may disclose OS/kernel/architecture).
	System string `json:"system,omitempty" xml:"system,omitempty"`
	// BuildDate is the interpreter build date.
	BuildDate string `json:"build_date,omitempty" xml:"build_date,omitempty"`
	// Architecture is the build/host architecture (e.g. "x86_64", "x64").
	Architecture string `json:"architecture,omitempty" xml:"architecture,omitempty"`
	// ThreadSafety is "enabled" (ZTS) or "disabled" (NTS) as reported.
	ThreadSafety string `json:"thread_safety,omitempty" xml:"thread_safety,omitempty"`
	// LoadedConfigFile is the active php.ini path.
	LoadedConfigFile string `json:"loaded_config_file,omitempty" xml:"loaded_config_file,omitempty"`
	// ScanDir is the directory scanned for additional .ini files.
	ScanDir string `json:"additional_ini_dir,omitempty" xml:"additional_ini_dir,omitempty"`
	// AdditionalIni lists the additional .ini files that were parsed.
	AdditionalIni string `json:"additional_ini_files,omitempty" xml:"additional_ini_files,omitempty"`
	// Directives are notable, security-relevant ini directives (local/master).
	Directives []PHPInfoDirective `json:"directives,omitempty" xml:"directives>directive,omitempty"`
	// ExtensionVersions maps notable extensions to their observed version.
	ExtensionVersions map[string]string `json:"extension_versions,omitempty" xml:"-"`
	// Observations are short, human-readable notes derived from the above.
	Observations []string `json:"observations,omitempty" xml:"observations>observation,omitempty"`
}

// PHPInfoDirective is one observed ini directive and its local/master values.
type PHPInfoDirective struct {
	Name   string `json:"name" xml:"name,attr"`
	Local  string `json:"local,omitempty" xml:"local,omitempty"`
	Master string `json:"master,omitempty" xml:"master,omitempty"`
	// Risk flags a value that weakens the service's security posture.
	Risk bool `json:"risk,omitempty" xml:"risk,attr,omitempty"`
}

var (
	rePHPInfoTR = regexp.MustCompile(`(?is)<tr[^>]*>(.*?)</tr>`)
	rePHPInfoTD = regexp.MustCompile(`(?is)<t[dh][^>]*>(.*?)</t[dh]>`)
	reHTMLTag   = regexp.MustCompile(`(?s)<[^>]+>`)
	reXdebugVer = regexp.MustCompile(`(?i)Xdebug\s+v?(\d+\.\d+\.\d+)`)
	reArchToken = regexp.MustCompile(`(?i)\b(x86_64|amd64|aarch64|arm64|x64|i[3-6]86|armv7l|ppc64le|s390x)\b`)
)

// phpInfoNotable is the allow-list of ini directives worth surfacing. Capturing
// an allow-list (rather than every directive) keeps output bounded and avoids
// retaining incidental values; credential-shaped values are redacted on top.
var phpInfoNotable = map[string]bool{
	"display_errors":                  true,
	"display_startup_errors":          true,
	"expose_php":                      true,
	"allow_url_fopen":                 true,
	"allow_url_include":               true,
	"enable_dl":                       true,
	"register_globals":                true,
	"short_open_tag":                  true,
	"file_uploads":                    true,
	"session.upload_progress.enabled": true,
	"assert.active":                   true,
	"open_basedir":                    true,
	"disable_functions":               true,
	"disable_classes":                 true,
	"mysqli.default_user":             true,
	"mysqli.default_pw":               true,
}

// parsePHPInfo extracts structured facts from a phpinfo() page body. It returns
// nil when nothing useful could be read.
func parsePHPInfo(body string) *PHPInfoFacts {
	general := map[string]string{}
	f := &PHPInfoFacts{}

	for _, tr := range rePHPInfoTR.FindAllStringSubmatch(body, -1) {
		cells := rePHPInfoTD.FindAllStringSubmatch(tr[1], -1)
		if len(cells) < 2 {
			continue
		}
		vals := make([]string, len(cells))
		for i, c := range cells {
			vals[i] = cleanCell(c[1])
		}
		key := vals[0]
		if key == "" {
			continue
		}
		// A three-column row is an ini directive (name, local, master); the
		// two-column rows are the general-information section.
		if len(vals) >= 3 && !strings.EqualFold(key, "Directive") {
			lk := strings.ToLower(key)
			if phpInfoNotable[lk] {
				f.Directives = append(f.Directives, PHPInfoDirective{
					Name:   key,
					Local:  clampLen(phpInfoRedact(key, vals[1]), 300),
					Master: clampLen(phpInfoRedact(key, vals[2]), 300),
					Risk:   phpInfoDirectiveRisky(lk, vals[1]),
				})
			}
			continue
		}
		if _, ok := general[key]; !ok {
			general[key] = vals[1]
		}
	}

	f.SAPI = general["Server API"]
	f.System = general["System"]
	f.BuildDate = general["Build Date"]
	f.LoadedConfigFile = general["Loaded Configuration File"]
	f.ScanDir = general["Scan this dir for additional .ini files"]
	f.AdditionalIni = general["Additional .ini files parsed"]
	if ts := general["Thread Safety"]; ts != "" {
		f.ThreadSafety = strings.ToLower(ts)
	}
	if arch := general["Architecture"]; arch != "" {
		f.Architecture = arch
	} else if m := reArchToken.FindString(f.System); m != "" {
		f.Architecture = m
	}
	if m := reXdebugVer.FindStringSubmatch(body); m != nil {
		f.ExtensionVersions = map[string]string{"Xdebug": m[1]}
	}

	f.Observations = phpInfoObservations(f)

	if f.SAPI == "" && f.System == "" && f.LoadedConfigFile == "" &&
		len(f.Directives) == 0 && len(f.ExtensionVersions) == 0 {
		return nil
	}
	return f
}

// cleanCell strips tags, unescapes entities and collapses whitespace in a cell.
func cleanCell(s string) string {
	s = reHTMLTag.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return strings.TrimSpace(strings.Join(strings.Fields(s), " "))
}

// phpInfoRedact replaces credential-shaped directive values with a placeholder,
// keyed on both the directive name (e.g. a "*_pw" / "*password*" directive) and
// obvious secret markers in the value itself.
func phpInfoRedact(name, val string) string {
	n := strings.ToLower(name)
	if strings.HasSuffix(n, "_pw") || strings.HasSuffix(n, ".pw") ||
		strings.Contains(n, "password") || strings.Contains(n, "passwd") ||
		strings.Contains(n, "secret") || strings.Contains(n, "private") {
		if val != "" && !strings.EqualFold(val, "no value") {
			return "[redacted]"
		}
		return val
	}
	v := strings.ToLower(val)
	for _, marker := range []string{"password=", "passwd=", "secret=", "api_key", "apikey", "token=", "bearer "} {
		if strings.Contains(v, marker) {
			return "[redacted]"
		}
	}
	return val
}

func phpInfoIsOn(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "1", "true", "enabled", "yes":
		return true
	default:
		return false
	}
}

// phpInfoDirectiveRisky flags directive values that weaken security posture.
func phpInfoDirectiveRisky(nameLower, local string) bool {
	switch nameLower {
	case "display_errors", "display_startup_errors", "expose_php",
		"allow_url_include", "allow_url_fopen", "enable_dl",
		"register_globals", "session.upload_progress.enabled",
		"assert.active", "short_open_tag":
		return phpInfoIsOn(local)
	default:
		return false
	}
}

func phpInfoObservations(f *PHPInfoFacts) []string {
	var obs []string
	if f.SAPI != "" {
		if strings.Contains(strings.ToLower(f.SAPI), "fpm") {
			obs = append(obs, "PHP-FPM confirmed (SAPI: "+f.SAPI+")")
		} else {
			obs = append(obs, "Server API: "+f.SAPI)
		}
	}
	if f.ThreadSafety != "" {
		obs = append(obs, "Thread safety: "+f.ThreadSafety)
	}
	for _, d := range f.Directives {
		if d.Risk {
			obs = append(obs, d.Name+" = "+d.Local)
		}
	}
	if ver, ok := f.ExtensionVersions["Xdebug"]; ok {
		obs = append(obs, "Xdebug enabled ("+ver+")")
	}
	return obs
}

func clampLen(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
