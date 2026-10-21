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

// DeepProbePaths are appended to the base URL (host + port) in deep mode to
// look for exposed diagnostics and framework entry points. They are read-only
// GET requests; none of them submit data or attempt exploitation.
func DeepProbePaths() []string {
	return []string{
		"/",
		"/index.php",
		"/info.php",
		"/phpinfo.php",
		"/test.php",
		"/php_info.php",
		"/i.php",
		"/composer.json",
		"/composer.lock",
		"/wp-login.php",
		"/administrator/",
		"/user/login",
		"/index.php?s=/",
		"/readme.html",
		"/CHANGELOG.txt",
		"/core/CHANGELOG.txt",
		"/administrator/manifests/files/joomla.xml",
		// Extension/addon status dashboards and tooling.
		"/opcache.php",
		"/apc.php",
		"/apcu.php",
		"/adminer.php",
		"/phpmyadmin/",
		"/robots.txt",
		// Composer artefacts: a readable manifest/package list means a PHP
		// project; vendor/autoload.php often leaks source when not executed.
		"/vendor/composer/installed.json",
		"/vendor/autoload.php",
		// Framework debug/dev endpoints and exposed secrets (read-only GETs).
		"/.env",
		"/app_dev.php",
		"/web/app_dev.php",
		"/_profiler/",
		"/telescope",
		"/horizon",
		"/status.php",
		"/xmlrpc.php",
		"/wp-json/",
	}
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
