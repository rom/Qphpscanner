package php

import "strings"

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

// GenericDeepProbePaths are generic PHP diagnostic/project discovery probes,
// issued when a service plausibly runs PHP. They are read-only GET requests;
// none submit data or attempt exploitation.
func GenericDeepProbePaths() []string {
	return []string{
		"/index.php",
		"/info.php",
		"/phpinfo.php",
		"/test.php",
		"/php_info.php",
		"/i.php",
		"/index.php?s=/",
		"/opcache.php",
		"/apc.php",
		"/apcu.php",
		"/adminer.php",
		"/phpmyadmin/",
		"/robots.txt",
		"/readme.html",
		"/CHANGELOG.txt",
		// Composer artefacts: a readable manifest/package list means a PHP
		// project; vendor/autoload.php often leaks source when not executed.
		"/composer.json",
		"/composer.lock",
		"/vendor/composer/installed.json",
		"/vendor/autoload.php",
		// Exposed secrets / status (read-only GETs).
		"/.env",
		"/status.php",
		"/xmlrpc.php",
	}
}

// ProbeGroup is an application-specific set of probe paths gated by a trigger
// over the evidence seen so far, so an app's endpoints are only requested once
// something already hints at that app (adaptive discovery).
type ProbeGroup struct {
	Name    string
	Trigger func(*Detection) bool
	Paths   []string
}

// hasFramework reports whether a detection already names a framework (case-
// insensitive substring), used as a probe-group trigger.
func hasFramework(d *Detection, name string) bool {
	if d == nil {
		return false
	}
	name = strings.ToLower(name)
	for _, f := range d.Frameworks {
		if strings.Contains(strings.ToLower(f), name) {
			return true
		}
	}
	return false
}

// ConditionalProbeGroups are framework-specific probe sets issued only after
// the base/core responses show evidence of that framework.
func ConditionalProbeGroups() []ProbeGroup {
	return []ProbeGroup{
		{Name: "wordpress", Trigger: func(d *Detection) bool { return hasFramework(d, "WordPress") },
			Paths: []string{"/wp-login.php", "/wp-json/"}},
		{Name: "joomla", Trigger: func(d *Detection) bool { return hasFramework(d, "Joomla") },
			Paths: []string{"/administrator/", "/administrator/manifests/files/joomla.xml"}},
		{Name: "drupal", Trigger: func(d *Detection) bool { return hasFramework(d, "Drupal") },
			Paths: []string{"/user/login", "/core/CHANGELOG.txt"}},
		{Name: "laravel", Trigger: func(d *Detection) bool { return hasFramework(d, "Laravel") || hasFramework(d, "Symfony") },
			Paths: []string{"/telescope", "/horizon", "/_profiler/", "/app_dev.php", "/web/app_dev.php"}},
		{Name: "magento", Trigger: func(d *Detection) bool { return hasFramework(d, "Magento") },
			Paths: []string{"/magento_version"}},
	}
}

// DeepProbePaths is the full union of generic and all conditional probe paths
// (the non-adaptive set). Retained for callers that want everything.
func DeepProbePaths() []string {
	paths := append([]string{}, GenericDeepProbePaths()...)
	for _, g := range ConditionalProbeGroups() {
		paths = append(paths, g.Paths...)
	}
	return paths
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
