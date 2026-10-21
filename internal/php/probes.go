package php

// Deep-mode probe definitions. The scanner fetches these and hands the
// responses back to Analyze. Keeping the catalogue here lets the detection
// logic and the scanner agree on what is collected.

// EasterEggCredits is the classic expose_php query string that returns the
// PHP credits page on installations where it is enabled. The GUID easter eggs
// were removed in PHP 5.5, so a hit also bounds the version.
const EasterEggCredits = "?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000"

// EasterEggLogo returns the embedded PHP logo image on the same old,
// expose_php-enabled installations.
const EasterEggLogo = "?=PHPE9568F34-D428-11d2-A769-00AA001ACF42"

// ControlProbePath is the guaranteed-nonexistent URL fetched in deep mode to
// learn the soft-404 / catch-all baseline (and harvest any PHP version an error
// page leaks). It must never collide with a real endpoint.
const ControlProbePath = "/qphpscanner_probe_404"

// CoreProbePaths are the always-safe, generic deep-mode probes issued in
// phase 1 regardless of what the service looks like: generic PHP diagnostics
// (phpinfo dumps, opcode-cache dashboards), project metadata (Composer files)
// and common leaks (.env, robots.txt). They are read-only GETs tied to no one
// application, so they are worth issuing before any app has shown itself.
func CoreProbePaths() []string {
	return []string{
		"/index.php",
		"/info.php",
		"/phpinfo.php",
		"/test.php",
		"/php_info.php",
		"/i.php",
		"/index.php?s=/",
		"/composer.json",
		"/composer.lock",
		// Extension/opcode-cache status dashboards (generic PHP give-aways).
		"/opcache.php",
		"/apc.php",
		"/apcu.php",
		"/robots.txt",
		// Composer artefacts: a readable manifest/package list means a PHP
		// project; vendor/autoload.php often leaks source when not executed.
		"/vendor/composer/installed.json",
		"/vendor/autoload.php",
		// Exposed secrets / status (read-only GETs).
		"/.env",
		"/status.php",
	}
}

// AppProbes maps a detection trigger — a framework/app/tool name exactly as
// Analyze reports it in Frameworks or Addons — to the extra, app-specific
// probe paths that become worth issuing only once that app has shown itself in
// phase 1 (via a header, cookie, generator tag, body marker or core probe).
type AppProbes struct {
	// Trigger is the canonical app name to match (case-insensitively) against
	// the phase-1 detection's frameworks/addons.
	Trigger string
	// Paths are the read-only GET probes to issue once Trigger is seen.
	Paths []string
}

// ConditionalProbes is the data-driven phase-2 schedule: evidence-gated,
// app-specific probe paths. Adaptive discovery only issues an app's paths after
// phase 1 shows evidence of that app, so a host is never asked for WordPress,
// Joomla, Laravel, … endpoints it shows no sign of running. This list is the
// single source of truth and is exercised directly by tests (no network).
func ConditionalProbes() []AppProbes {
	return []AppProbes{
		{"WordPress", []string{"/wp-login.php", "/readme.html", "/xmlrpc.php", "/wp-json/"}},
		{"Joomla", []string{"/administrator/", "/administrator/manifests/files/joomla.xml"}},
		{"Drupal", []string{"/user/login", "/CHANGELOG.txt", "/core/CHANGELOG.txt"}},
		{"Symfony", []string{"/app_dev.php", "/web/app_dev.php", "/_profiler/"}},
		{"Laravel", []string{"/telescope", "/horizon"}},
		{"Magento", []string{"/magento_version"}},
		{"phpMyAdmin", []string{"/phpmyadmin/"}},
		{"Adminer", []string{"/adminer.php"}},
	}
}

// DeepProbePaths is the full, fixed catalogue of deep-mode probe paths: the
// core set plus every conditional set, unioned and de-duplicated. The scanner
// no longer issues this list wholesale (it schedules it adaptively via
// CoreProbePaths/ConditionalProbes), but it remains the authoritative inventory
// of everything deep mode may fetch — useful for documentation, tests and
// callers that want the complete set.
func DeepProbePaths() []string {
	out := []string{"/"}
	seen := map[string]bool{"/": true}
	add := func(paths []string) {
		for _, p := range paths {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	add(CoreProbePaths())
	for _, ap := range ConditionalProbes() {
		add(ap.Paths)
	}
	return out
}

// PathInfoProbe is appended to index.php to test PHP PATH_INFO handling.
const PathInfoProbe = "/index.php/qphpscanner_pathinfo"

// isPHPInfo reports whether a body looks like phpinfo() output.
func isPHPInfo(body string) bool {
	if body == "" {
		return false
	}
	hasTitle := contains(body, "<title>phpinfo()") || contains(body, ">phpinfo()<")
	hasVersion := rePHPInfoVersion.MatchString(body)
	hasZend := contains(body, "Zend Engine")
	return hasTitle || (hasVersion && hasZend)
}
