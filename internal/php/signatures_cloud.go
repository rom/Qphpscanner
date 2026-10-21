package php

import "regexp"

// Focused detection for the ownCloud / Nextcloud family. Nextcloud and ownCloud
// are PHP codebases (phpImplied). OpenCloud / Infinite Scale (oCIS) is a Go
// rewrite, so it is detected as an application but must NOT boost PHP
// confidence — it is matched with phpImplied=false.
func init() {
	cookieSigs = append(cookieSigs, cloudCookieSigs...)
	headerSigs = append(headerSigs, cloudHeaderSigs...)
	bodySigs = append(bodySigs, cloudBodySigs...)
}

var cloudCookieSigs = []cookieSig{
	{"nc_session_id", matchExact, "Nextcloud", 60, "Nextcloud session cookie"},
	{"nc_token", matchExact, "Nextcloud", 55, "Nextcloud remember-me token"},
	{"nc_username", matchExact, "Nextcloud", 55, "Nextcloud username cookie"},
	{"oc_token", matchExact, "ownCloud/Nextcloud", 55, "ownCloud/Nextcloud remember-me token"},
	{"oc_username", matchExact, "ownCloud/Nextcloud", 55, "ownCloud/Nextcloud username cookie"},
	// ownCloud/Nextcloud name their session cookie with a 32-char hex id; the
	// stable, low-risk markers above are preferred over matching that.
}

var cloudHeaderSigs = []headerSig{
	// Nextcloud/ownCloud WebDAV/OCS surface commonly carries these.
	{"X-Nextcloud-Version", "", "Nextcloud", true, "", 65, "Nextcloud version header"},
	{"X-Owncloud-Version", "", "ownCloud", true, "", 65, "ownCloud version header"},
	{"X-Ocis-Version", "", "OpenCloud/oCIS", false, "", 45, "OpenCloud / Infinite Scale (oCIS) version header"},
}

var cloudBodySigs = []bodySig{
	{"body.nextcloud2", regexp.MustCompile(`(?i)id="nextcloud"|data-requesttoken=|href="https://nextcloud\.com|<a[^>]+nextcloud\.com`), "Nextcloud", true, 55, "Nextcloud login/app markers"},
	// Deliberately specific UI markers: the bare word "ownCloud" also appears in
	// the oCIS ("ownCloud Infinite Scale") product name, which is not PHP.
	{"body.owncloud", regexp.MustCompile(`(?i)oc-login|data-owncloud|id="owncloud"|href="https://owncloud\.(org|com)`), "ownCloud", true, 50, "ownCloud UI markers"},
	{"body.cloud-apps", regexp.MustCompile(`(?i)/apps/(files|dashboard|settings)/|oc-dialog|OCA\.`), "Nextcloud/ownCloud", true, 45, "Nextcloud/ownCloud app-framework markers"},
	// OpenCloud (oCIS) — Go rewrite, detected but not counted as PHP.
	{"body.opencloud", regexp.MustCompile(`(?i)OpenCloud|Infinite Scale|ownCloud Web\b|\boCIS\b`), "OpenCloud/oCIS", false, 35, "OpenCloud / oCIS (Infinite Scale) markers"},
}
