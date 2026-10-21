package php

// Built-in, curated vulnerability data. This is a non-exhaustive catalogue of
// high-signal, version-correlatable issues. Matches are informational leads
// derived from a detected version — not confirmed, exploited findings. Extend
// or override it at runtime with external feeds (see catalog.go / --vuln-feed).

// br is an affected range limited to a major.minor branch, below `lt`.
func br(branch, lt string) RangeSpec { return RangeSpec{Branch: branch, LessThan: lt} }

// lo is an open-ended "less than" range across all branches.
func lo(v string) RangeSpec { return RangeSpec{LessThan: v} }

// rng is a half-open [introduced, fixed) range.
func rng(introduced, fixed string) RangeSpec { return RangeSpec{Introduced: introduced, Fixed: fixed} }

const nvd = "https://nvd.nist.gov/vuln/detail/"

// builtinPHP is the curated PHP-core CVE catalogue.
var builtinPHP = []FeedEntry{
	// ---- "php2shell" (October 2026) ----
	// Two critical PHP-core RCEs disclosed and patched out-of-band on
	// 2026-10-21. Affected-version data is sourced from public reporting
	// (Sansec/Unit 42/Tenable) and is provisional until the php.net advisory
	// is confirmed; version-correlation here is an informational lead.
	{
		ID: "CVE-2026-109618", Severity: "critical",
		Title: "PHP core remote code execution (\"php2shell\")",
		Description: "Critical PHP-core RCE: out-of-memory handling via longjmp() leaves " +
			"request memory uninitialised, which can be steered to reliable remote code " +
			"execution. Mitigate with session.upload_progress.enabled=0 until patched.",
		Reference: nvd + "CVE-2026-109618",
		Note:      "PHP core; CVSS v4.0 9.2; patched in 8.2.35/8.3.36/8.4.27/8.5.12; EOL branches unpatched; version list provisional (confirm at php.net)",
		Affected:  []RangeSpec{rng("5.4.0", "8.2.0"), br("8.2", "8.2.35"), br("8.3", "8.3.36"), br("8.4", "8.4.27"), br("8.5", "8.5.12")},
		Prereqs:   []Prereq{{Kind: "config", Want: "session.upload_progress.enabled", Value: "on", Detail: "reachable via session upload-progress processing (session.upload_progress.enabled = On)"}},
	},
	{
		ID: "CVE-2026-109619", Severity: "critical",
		Title: "PHP core remote code execution (\"php2shell\")",
		Description: "Critical PHP-core RCE: longjmp() fatal-error handling leaves global state " +
			"referencing freed memory (use-after-free), reachable via multipart request / " +
			"session upload-progress processing. Mitigate with session.upload_progress.enabled=0 until patched.",
		Reference: nvd + "CVE-2026-109619",
		Note:      "PHP core; CVSS v4.0 9.2; patched in 8.2.35/8.3.36/8.4.27/8.5.12; EOL branches unpatched; version list provisional (confirm at php.net)",
		Affected:  []RangeSpec{rng("5.4.0", "8.2.0"), br("8.2", "8.2.35"), br("8.3", "8.3.36"), br("8.4", "8.4.27"), br("8.5", "8.5.12")},
		Prereqs:   []Prereq{{Kind: "config", Want: "session.upload_progress.enabled", Value: "on", Detail: "reachable via multipart / session upload-progress processing (session.upload_progress.enabled = On)"}},
	},

	// ---- 8.1 / 8.2 / 8.3 era ----
	{
		ID: "CVE-2024-5585", Severity: "critical",
		Title:       "php-cgi argument injection (BatBadBut follow-up to CVE-2024-4577)",
		Description: "An incomplete fix for CVE-2024-4577 left php-cgi on Windows still passing crafted query strings as interpreter arguments.",
		Reference:   nvd + "CVE-2024-5585", Note: "Windows php-cgi deployments only",
		Affected: []RangeSpec{br("8.1", "8.1.29"), br("8.2", "8.2.20"), br("8.3", "8.3.8")},
		Prereqs:  []Prereq{{Kind: "sapi", Want: "cgi"}, {Kind: "os", Want: "windows"}},
	},
	{
		ID: "CVE-2024-4577", Severity: "critical",
		Title:       "PHP-CGI argument injection (regression of CVE-2012-1823)",
		Description: "Argument injection in php-cgi on Windows allows passing options to the PHP interpreter, leading to source disclosure or remote code execution. Exploited in the wild.",
		Reference:   nvd + "CVE-2024-4577", Note: "Windows php-cgi deployments only",
		Affected: []RangeSpec{br("8.1", "8.1.29"), br("8.2", "8.2.20"), br("8.3", "8.3.8"), lo("8.1.0")},
		Prereqs:  []Prereq{{Kind: "sapi", Want: "cgi"}, {Kind: "os", Want: "windows"}},
	},
	{
		ID: "CVE-2024-11236", Severity: "critical",
		Title:       "Integer overflow in pdo_firebird / pgsql leading to memory corruption",
		Description: "An integer overflow when handling oversized values in the firebird/pgsql drivers can corrupt memory.",
		Reference:   nvd + "CVE-2024-11236",
		Affected:    []RangeSpec{br("8.1", "8.1.31"), br("8.2", "8.2.26"), br("8.3", "8.3.14")},
	},
	{
		ID: "CVE-2024-11233", Severity: "high",
		Title:       "convert.quoted-printable-decode buffer overread",
		Description: "A single-byte out-of-bounds read in the quoted-printable stream filter.",
		Reference:   nvd + "CVE-2024-11233",
		Affected:    []RangeSpec{br("8.1", "8.1.31"), br("8.2", "8.2.26"), br("8.3", "8.3.14")},
	},
	{
		ID: "CVE-2024-11234", Severity: "medium",
		Title:       "Stream proxy request CRLF injection via configuration",
		Description: "A CRLF injection in the HTTP stream wrapper when a request_fulluri proxy is configured.",
		Reference:   nvd + "CVE-2024-11234",
		Affected:    []RangeSpec{br("8.1", "8.1.31"), br("8.2", "8.2.26"), br("8.3", "8.3.14")},
	},
	{
		ID: "CVE-2024-8925", Severity: "medium",
		Title:       "Erroneous parsing of multipart/form-data boundaries",
		Description: "Malformed multipart boundaries can cause some POST parameters to be dropped.",
		Reference:   nvd + "CVE-2024-8925",
		Affected:    []RangeSpec{br("8.1", "8.1.30"), br("8.2", "8.2.24"), br("8.3", "8.3.12")},
	},
	{
		ID: "CVE-2024-8927", Severity: "low",
		Title:       "cgi.force_redirect bypass via HTTP_PROXY-style env",
		Description: "A configuration bypass in the CGI SAPI env handling.",
		Reference:   nvd + "CVE-2024-8927",
		Affected:    []RangeSpec{br("8.1", "8.1.30"), br("8.2", "8.2.24"), br("8.3", "8.3.12")},
	},
	{
		ID: "CVE-2024-9026", Severity: "low",
		Title:       "PHP-FPM log manipulation via unsanitised output",
		Description: "Unsanitised bytes written to FPM logs can hide or forge log lines.",
		Reference:   nvd + "CVE-2024-9026",
		Affected:    []RangeSpec{br("8.1", "8.1.30"), br("8.2", "8.2.24"), br("8.3", "8.3.12")},
	},
	{
		ID: "CVE-2024-5458", Severity: "medium",
		Title:       "filter_var FILTER_VALIDATE_URL path parsing inconsistency",
		Description: "A parsing inconsistency may let malformed URLs pass validation.",
		Reference:   nvd + "CVE-2024-5458",
		Affected:    []RangeSpec{br("8.1", "8.1.29"), br("8.2", "8.2.20"), br("8.3", "8.3.8")},
	},
	{
		ID: "CVE-2024-2756", Severity: "medium",
		Title:       "__Host-/__Secure- cookie prefix bypass",
		Description: "A flaw in cookie handling can let an attacker spoof security-prefixed cookies.",
		Reference:   nvd + "CVE-2024-2756",
		Affected:    []RangeSpec{br("8.1", "8.1.28"), br("8.2", "8.2.18"), br("8.3", "8.3.6")},
	},
	{
		ID: "CVE-2024-3096", Severity: "medium",
		Title:       "password_verify() accepts strings with a leading null byte",
		Description: "A password beginning with a null byte may be erroneously verified against some BCrypt hashes.",
		Reference:   nvd + "CVE-2024-3096",
		Affected:    []RangeSpec{br("8.1", "8.1.28"), br("8.2", "8.2.18"), br("8.3", "8.3.6")},
	},
	{
		ID: "CVE-2024-1874", Severity: "high",
		Title:       "proc_open() command injection via bat/cmd on Windows",
		Description: "Quoted program names with bat/cmd wrappers on Windows can inject commands.",
		Reference:   nvd + "CVE-2024-1874", Note: "Windows only",
		Affected: []RangeSpec{br("8.1", "8.1.28"), br("8.2", "8.2.18"), br("8.3", "8.3.6")},
	},

	// ---- 8.0 / 8.1 / 8.2 era ----
	{
		ID: "CVE-2023-3824", Severity: "critical",
		Title:       "Buffer overflow in phar directory parsing",
		Description: "A length-check error while loading phar files can cause a stack buffer overflow leading to memory corruption or RCE.",
		Reference:   nvd + "CVE-2023-3824",
		Affected:    []RangeSpec{br("8.0", "8.0.30"), br("8.1", "8.1.22"), br("8.2", "8.2.8")},
	},
	{
		ID: "CVE-2023-3823", Severity: "high",
		Title:       "XML external entity / information disclosure via libxml globals",
		Description: "Shared libxml global state can re-enable external entity loading, exposing local files.",
		Reference:   nvd + "CVE-2023-3823",
		Affected:    []RangeSpec{br("8.0", "8.0.30"), br("8.1", "8.1.22"), br("8.2", "8.2.8")},
	},
	{
		ID: "CVE-2023-0662", Severity: "high",
		Title:       "Denial of service via excessive HTTP file-upload parts",
		Description: "No limit on the number of parts in multipart requests enables resource exhaustion.",
		Reference:   nvd + "CVE-2023-0662",
		Affected:    []RangeSpec{br("8.0", "8.0.28"), br("8.1", "8.1.16"), br("8.2", "8.2.3")},
	},
	{
		ID: "CVE-2023-0568", Severity: "medium",
		Title:       "Core path-resolution one-byte buffer overread",
		Description: "A one-byte out-of-bounds read in the path-resolution code.",
		Reference:   nvd + "CVE-2023-0568",
		Affected:    []RangeSpec{br("8.0", "8.0.28"), br("8.1", "8.1.16"), br("8.2", "8.2.3")},
	},
	{
		ID: "CVE-2023-0567", Severity: "medium",
		Title:       "password_verify() mishandles certain malformed BCrypt hashes",
		Description: "Some invalid BCrypt hashes are treated as valid, weakening verification.",
		Reference:   nvd + "CVE-2023-0567",
		Affected:    []RangeSpec{br("8.0", "8.0.28"), br("8.1", "8.1.16"), br("8.2", "8.2.3")},
	},

	// ---- 7.4 / 8.0 / 8.1 era ----
	{
		ID: "CVE-2022-31626", Severity: "critical",
		Title:       "pdo_mysql buffer overflow (RCE)",
		Description: "A buffer overflow in pdo_mysql with an untrusted/malicious MySQL server can lead to remote code execution.",
		Reference:   nvd + "CVE-2022-31626",
		Affected:    []RangeSpec{br("7.4", "7.4.30"), br("8.0", "8.0.20"), br("8.1", "8.1.7")},
	},
	{
		ID: "CVE-2022-31625", Severity: "high",
		Title:       "pgsql/pdo_pgsql memory corruption via parameter arrays",
		Description: "Improper handling of parameter arrays in the pgsql/pdo_pgsql extensions can corrupt memory.",
		Reference:   nvd + "CVE-2022-31625",
		Affected:    []RangeSpec{br("7.4", "7.4.30"), br("8.0", "8.0.20"), br("8.1", "8.1.7")},
	},
	{
		ID: "CVE-2022-31628", Severity: "medium",
		Title:       "phar: infinite recursion / DoS via quines",
		Description: "Decompressing a crafted phar quine can exhaust resources.",
		Reference:   nvd + "CVE-2022-31628",
		Affected:    []RangeSpec{br("7.4", "7.4.31"), br("8.0", "8.0.24"), br("8.1", "8.1.11")},
	},
	{
		ID: "CVE-2022-31629", Severity: "medium",
		Title:       "Network-related cookie-name downgrade ($_COOKIE prefix)",
		Description: "Cookie names with a leading dot can bypass __Host-/__Secure- prefixes.",
		Reference:   nvd + "CVE-2022-31629",
		Affected:    []RangeSpec{br("7.4", "7.4.31"), br("8.0", "8.0.24"), br("8.1", "8.1.11")},
	},
	{
		ID: "CVE-2021-21708", Severity: "high",
		Title:       "filter_var FILTER_VALIDATE_FLOAT use-after-free",
		Description: "A use-after-free when validating floats with leading/trailing whitespace.",
		Reference:   nvd + "CVE-2021-21708",
		Affected:    []RangeSpec{br("7.4", "7.4.28"), br("8.0", "8.0.16"), br("8.1", "8.1.3")},
	},
	{
		ID: "CVE-2021-21707", Severity: "medium",
		Title:       "XML: special character truncation via null byte in path",
		Description: "simplexml/xml path handling can truncate on a null byte, confusing callers.",
		Reference:   nvd + "CVE-2021-21707",
		Affected:    []RangeSpec{br("7.3", "7.3.33"), br("7.4", "7.4.26"), br("8.0", "8.0.13")},
	},
	{
		ID: "CVE-2021-21705", Severity: "medium",
		Title:       "SSRF via FILTER_VALIDATE_URL accepting malformed URLs",
		Description: "URL validation can accept URLs that later resolve differently, enabling SSRF.",
		Reference:   nvd + "CVE-2021-21705",
		Affected:    []RangeSpec{br("7.3", "7.3.29"), br("7.4", "7.4.21"), br("8.0", "8.0.8")},
	},
	{
		ID: "CVE-2021-21702", Severity: "high",
		Title:       "SOAP null-pointer dereference (DoS)",
		Description: "A crafted SOAP response can crash the process.",
		Reference:   nvd + "CVE-2021-21702",
		Affected:    []RangeSpec{br("7.3", "7.3.27"), br("7.4", "7.4.15"), br("8.0", "8.0.2")},
	},

	// ---- 7.2 / 7.3 / 7.4 era ----
	{
		ID: "CVE-2020-7071", Severity: "medium",
		Title:       "FILTER_VALIDATE_URL inconsistency with userinfo",
		Description: "URL validation inconsistency can be abused for access-control bypass/SSRF.",
		Reference:   nvd + "CVE-2020-7071",
		Affected:    []RangeSpec{br("7.3", "7.3.26"), br("7.4", "7.4.14"), br("8.0", "8.0.1")},
	},
	{
		ID: "CVE-2020-7070", Severity: "medium",
		Title:       "Cookie name downgrade via $_COOKIE (prefix bypass)",
		Description: "Crafted cookie names bypass __Host-/__Secure- prefixes.",
		Reference:   nvd + "CVE-2020-7070",
		Affected:    []RangeSpec{br("7.2", "7.2.34"), br("7.3", "7.3.26"), br("7.4", "7.4.14")},
	},
	{
		ID: "CVE-2020-7069", Severity: "high",
		Title:       "openssl_encrypt AES-GCM AAD authentication weakness",
		Description: "The additional authenticated data (AAD) was not fully covered, weakening GCM integrity.",
		Reference:   nvd + "CVE-2020-7069",
		Affected:    []RangeSpec{br("7.2", "7.2.34"), br("7.3", "7.3.22"), br("7.4", "7.4.10")},
	},
	{
		ID: "CVE-2020-7068", Severity: "medium",
		Title:       "phar: buffer overread parsing crafted archives",
		Description: "An out-of-bounds read when parsing malformed phar files.",
		Reference:   nvd + "CVE-2020-7068",
		Affected:    []RangeSpec{br("7.2", "7.2.33"), br("7.3", "7.3.21"), br("7.4", "7.4.9")},
	},
	{
		ID: "CVE-2020-7067", Severity: "medium",
		Title:       "urldecode() out-of-bounds read",
		Description: "A buffer overread in urldecode with crafted input.",
		Reference:   nvd + "CVE-2020-7067",
		Affected:    []RangeSpec{br("7.2", "7.2.29"), br("7.3", "7.3.16"), br("7.4", "7.4.4")},
	},
	{
		ID: "CVE-2020-7066", Severity: "low",
		Title:       "get_headers() silently truncates on a null byte",
		Description: "URLs with a null byte are truncated, potentially contacting an unintended host.",
		Reference:   nvd + "CVE-2020-7066",
		Affected:    []RangeSpec{br("7.2", "7.2.29"), br("7.3", "7.3.16"), br("7.4", "7.4.4")},
	},

	// ---- 7.1 / 7.2 / 7.3 era ----
	{
		ID: "CVE-2019-11043", Severity: "critical",
		Title:       "PHP-FPM underflow RCE (env_path_info)",
		Description: "An underflow in fpm_main.c with certain nginx + PHP-FPM configurations allows remote code execution. Exploited in the wild.",
		Reference:   nvd + "CVE-2019-11043", Note: "nginx + PHP-FPM with a vulnerable fastcgi_split_path_info config",
		Affected: []RangeSpec{br("7.1", "7.1.33"), br("7.2", "7.2.24"), br("7.3", "7.3.11")},
		Prereqs:  []Prereq{{Kind: "sapi", Want: "fpm", Detail: "requires PHP-FPM (behind nginx with a vulnerable fastcgi_split_path_info)"}},
	},
	{
		ID: "CVE-2019-11050", Severity: "medium",
		Title:       "exif: use-after-free reading crafted images",
		Description: "A use-after-free in exif_read_data with malformed input.",
		Reference:   nvd + "CVE-2019-11050",
		Affected:    []RangeSpec{br("7.2", "7.2.34"), br("7.3", "7.3.26"), br("7.4", "7.4.14")},
	},
	{
		ID: "CVE-2019-11048", Severity: "low",
		Title:       "Denial of service via too many temporary upload files",
		Description: "No cap on temp files from a single request enables disk exhaustion.",
		Reference:   nvd + "CVE-2019-11048",
		Affected:    []RangeSpec{br("7.2", "7.2.31"), br("7.3", "7.3.18"), br("7.4", "7.4.6")},
	},
	{
		ID: "CVE-2019-9641", Severity: "medium",
		Title:       "exif: uninitialized read parsing crafted images",
		Description: "An uninitialized memory read in the exif extension.",
		Reference:   nvd + "CVE-2019-9641",
		Affected:    []RangeSpec{br("7.1", "7.1.27"), br("7.2", "7.2.16"), br("7.3", "7.3.3")},
	},

	{
		ID: "CVE-2019-11045", Severity: "medium",
		Title:       "rfc1867 file-upload path truncation via null byte",
		Description: "A null byte in a multipart filename could truncate the stored path.",
		Reference:   nvd + "CVE-2019-11045",
		Affected:    []RangeSpec{br("7.2", "7.2.27"), br("7.3", "7.3.14"), br("7.4", "7.4.2")},
	},

	// ---- 5.6 / 7.0 / 7.1 / 7.2 era ----
	{
		ID: "CVE-2018-10545", Severity: "medium",
		Title:       "PHP-FPM worker crash / dumpable state disclosure",
		Description: "A dumpable FPM worker could expose opcache memory to other local users.",
		Reference:   nvd + "CVE-2018-10545",
		Affected:    []RangeSpec{br("5.6", "5.6.36"), br("7.0", "7.0.30"), br("7.1", "7.1.17"), br("7.2", "7.2.5")},
	},
	{
		ID: "CVE-2018-10546", Severity: "medium",
		Title:       "iconv stream filter infinite loop (DoS)",
		Description: "A malformed multibyte sequence in the convert.iconv filter can hang the process.",
		Reference:   nvd + "CVE-2018-10546",
		Affected:    []RangeSpec{br("5.6", "5.6.36"), br("7.0", "7.0.30"), br("7.1", "7.1.17"), br("7.2", "7.2.5")},
	},
	{
		ID: "CVE-2018-10547", Severity: "medium",
		Title:       "phar: reflected XSS on the error page",
		Description: "An incomplete fix for CVE-2018-5712 left a reflected XSS in phar error output.",
		Reference:   nvd + "CVE-2018-10547",
		Affected:    []RangeSpec{br("5.6", "5.6.36"), br("7.0", "7.0.30"), br("7.1", "7.1.17"), br("7.2", "7.2.5")},
	},
	{
		ID: "CVE-2018-10548", Severity: "medium",
		Title:       "ldap_search() null pointer dereference (DoS)",
		Description: "A malicious LDAP server response can crash the client via a null dereference.",
		Reference:   nvd + "CVE-2018-10548",
		Affected:    []RangeSpec{br("5.6", "5.6.36"), br("7.0", "7.0.30"), br("7.1", "7.1.17"), br("7.2", "7.2.5")},
	},
	{
		ID: "CVE-2018-10549", Severity: "high",
		Title:       "exif: out-of-bounds read parsing crafted JPEG",
		Description: "An out-of-bounds read in exif_read_data with a crafted image.",
		Reference:   nvd + "CVE-2018-10549",
		Affected:    []RangeSpec{br("5.6", "5.6.36"), br("7.0", "7.0.30"), br("7.1", "7.1.17"), br("7.2", "7.2.5")},
	},

	// ---- 5.x / 7.0 era ----
	{
		ID: "CVE-2018-19935", Severity: "medium",
		Title:       "imap: null pointer dereference (DoS)",
		Description: "A crafted mailbox string can crash the imap extension.",
		Reference:   nvd + "CVE-2018-19935",
		Affected:    []RangeSpec{br("5.6", "5.6.39"), br("7.0", "7.0.33"), br("7.1", "7.1.25"), br("7.2", "7.2.13")},
	},
	{
		ID: "CVE-2018-17082", Severity: "medium",
		Title:       "XSS via Transfer-Encoding in the bundled Apache SAPI",
		Description: "The Apache2 component mishandles Transfer-Encoding, allowing cross-site scripting.",
		Reference:   nvd + "CVE-2018-17082",
		Affected:    []RangeSpec{br("5.6", "5.6.38"), br("7.0", "7.0.32"), br("7.1", "7.1.22"), br("7.2", "7.2.10")},
	},
	{
		ID: "CVE-2016-5385", Severity: "medium",
		Title:       "httpoxy: HTTP_PROXY trusted from request header",
		Description: "CGI/FPM set HTTP_PROXY from the client-controlled Proxy header, enabling SSRF of outbound requests.",
		Reference:   nvd + "CVE-2016-5385", Note: "CGI/FPM SAPIs making outbound requests",
		Affected: []RangeSpec{br("5.5", "5.5.38"), br("5.6", "5.6.24"), br("7.0", "7.0.9")},
	},
	{
		ID: "CVE-2015-4024", Severity: "high",
		Title:       "Multipart/form-data denial of service",
		Description: "Algorithmic complexity in multipart/form-data parsing enables a denial of service.",
		Reference:   nvd + "CVE-2015-4024",
		Affected:    []RangeSpec{br("5.4", "5.4.41"), br("5.5", "5.5.25"), br("5.6", "5.6.9")},
	},
	{
		ID: "CVE-2015-0273", Severity: "high",
		Title:       "DateTime use-after-free",
		Description: "A use-after-free in the date extension can be triggered by crafted input.",
		Reference:   nvd + "CVE-2015-0273",
		Affected:    []RangeSpec{br("5.4", "5.4.38"), br("5.5", "5.5.22"), br("5.6", "5.6.6")},
	},
	{
		ID: "CVE-2012-1823", Severity: "critical",
		Title:       "php-cgi query-string argument injection (RCE / source disclosure)",
		Description: "As a CGI, PHP treats query-string parameters without '=' as command-line arguments, enabling source disclosure and remote code execution.",
		Reference:   nvd + "CVE-2012-1823", Note: "php-cgi SAPI only",
		Affected: []RangeSpec{lo("5.3.12"), br("5.4", "5.4.2")},
	},
	{
		ID: "CVE-2011-4885", Severity: "high",
		Title:       "Hash-collision denial of service (max_input_vars)",
		Description: "Predictable form-field hashing enables CPU exhaustion; mitigated by the max_input_vars limit introduced in 5.3.9.",
		Reference:   nvd + "CVE-2011-4885",
		Affected:    []RangeSpec{lo("5.3.9")},
	},

	// ---- additional curated entries ----
	{
		ID: "CVE-2025-1217", Severity: "medium",
		Title:       "HTTP request stream wrapper header-folding parse error",
		Description: "The http:// stream wrapper mishandles folded (multi-line) response headers, which can desynchronise header parsing.",
		Reference:   nvd + "CVE-2025-1217", Note: "fixed in the March 2025 release line",
		Affected: []RangeSpec{br("8.1", "8.1.32"), br("8.2", "8.2.28"), br("8.3", "8.3.19"), br("8.4", "8.4.5")},
	},
	{
		ID: "CVE-2025-1219", Severity: "medium",
		Title:       "Wrong libxml parser selected from a mis-cased Content-Type",
		Description: "DOMDocument/SimpleXML may pick the wrong parser when the Content-Type header casing is unexpected, leading to incorrect or unsafe parsing.",
		Reference:   nvd + "CVE-2025-1219", Note: "fixed in the March 2025 release line",
		Affected: []RangeSpec{br("8.1", "8.1.32"), br("8.2", "8.2.28"), br("8.3", "8.3.19"), br("8.4", "8.4.5")},
	},
	{
		ID: "CVE-2024-8929", Severity: "medium",
		Title:       "mysqlnd heap buffer over-read (leak to a malicious MySQL server)",
		Description: "A hostile or compromised MySQL server can trigger a heap over-read in mysqlnd and read adjacent client memory.",
		Reference:   nvd + "CVE-2024-8929", Note: "applications using mysqlnd against an untrusted DB server",
		Affected: []RangeSpec{br("8.1", "8.1.31"), br("8.2", "8.2.26"), br("8.3", "8.3.14")},
	},
	{
		ID: "CVE-2022-37454", Severity: "high",
		Title:       "SHA-3 (Keccak/XKCP) buffer overflow in the hash extension",
		Description: "An integer overflow and resulting buffer overflow in the bundled SHA-3 (Keccak) reference implementation can corrupt memory when hashing attacker-sized input.",
		Reference:   nvd + "CVE-2022-37454",
		Affected:    []RangeSpec{br("8.0", "8.0.24"), br("8.1", "8.1.11")},
	},
}

// builtinCMS holds a small set of famous, accurately-bounded CMS core issues,
// keyed by framework name (lowercase).
var builtinCMS = map[string][]FeedEntry{
	"wordpress": {
		{
			ID: "CVE-2024-31210", Severity: "high",
			Title:       "WordPress: RCE via plugin upload (authenticated)",
			Description: "An authenticated admin could upload a PHP file via the plugin uploader in affected versions.",
			Reference:   nvd + "CVE-2024-31210",
			Affected:    []RangeSpec{lo("6.5.2")},
		},
		{
			ID: "CVE-2023-2745", Severity: "medium",
			Title:       "WordPress: directory traversal exposing drafts via block themes",
			Description: "A path-handling flaw could disclose unpublished content.",
			Reference:   nvd + "CVE-2023-2745",
			Affected:    []RangeSpec{lo("6.2.1")},
		},
		{
			ID: "CVE-2022-21661", Severity: "high",
			Title:       "WordPress: SQL injection via WP_Query",
			Description: "A SQL injection reachable through WP_Query in affected core versions.",
			Reference:   nvd + "CVE-2022-21661",
			Affected:    []RangeSpec{lo("5.8.3")},
		},
		{
			ID: "CVE-2022-21662", Severity: "medium",
			Title:       "WordPress: stored XSS via post slugs (authenticated)",
			Description: "A low-privileged author could store cross-site scripting.",
			Reference:   nvd + "CVE-2022-21662",
			Affected:    []RangeSpec{lo("5.8.3")},
		},
		{
			ID: "CVE-2023-5561", Severity: "medium",
			Title:       "WordPress: user-email disclosure via the Application Passwords API",
			Description: "An insufficient access check in the Application Passwords endpoint could disclose user email addresses.",
			Reference:   nvd + "CVE-2023-5561",
			Affected:    []RangeSpec{lo("6.3.2")},
		},
		{
			ID: "CVE-2024-4439", Severity: "medium",
			Title:       "WordPress: stored XSS via the author-avatar block",
			Description: "A stored cross-site scripting issue in the core avatar block in affected versions.",
			Reference:   nvd + "CVE-2024-4439",
			Affected:    []RangeSpec{lo("6.5.2")},
		},
		{
			ID: "CVE-2022-21664", Severity: "high",
			Title:       "WordPress: SQL injection via WP_Meta_Query",
			Description: "A SQL injection reachable through WP_Meta_Query in affected core versions.",
			Reference:   nvd + "CVE-2022-21664",
			Affected:    []RangeSpec{lo("5.8.3")},
		},
		{
			ID: "CVE-2022-21663", Severity: "high",
			Title:       "WordPress: PHP object injection (authenticated, multisite)",
			Description: "An authenticated user on a multisite install could trigger PHP object injection in affected core versions.",
			Reference:   nvd + "CVE-2022-21663",
			Affected:    []RangeSpec{lo("5.8.3")},
		},
	},
	"drupal": {
		{
			ID: "CVE-2018-7600", Severity: "critical",
			Title:       "Drupal: remote code execution (Drupalgeddon2)",
			Description: "Insufficient input sanitisation in form rendering allows unauthenticated remote code execution.",
			Reference:   nvd + "CVE-2018-7600",
			Affected:    []RangeSpec{rng("7.0", "7.58"), rng("8.0", "8.5.1")},
		},
		{
			ID: "CVE-2018-7602", Severity: "critical",
			Title:       "Drupal: remote code execution (Drupalgeddon2 follow-up)",
			Description: "A further remote code execution in the same subsystem as CVE-2018-7600.",
			Reference:   nvd + "CVE-2018-7602",
			Affected:    []RangeSpec{rng("7.0", "7.59"), rng("8.0", "8.5.3")},
		},
		{
			ID: "CVE-2019-6340", Severity: "critical",
			Title:       "Drupal: REST module remote code execution",
			Description: "Missing input validation in some REST resources allows remote code execution.",
			Reference:   nvd + "CVE-2019-6340", Note: "sites with RESTful Web Services enabled",
			Affected: []RangeSpec{rng("8.0", "8.6.10")},
		},
	},
	"magento": {
		{
			ID: "CVE-2022-24086", Severity: "critical",
			Title:       "Magento / Adobe Commerce: pre-auth remote code execution",
			Description: "Improper input validation during the checkout flow allows unauthenticated remote code execution. Exploited in the wild.",
			Reference:   nvd + "CVE-2022-24086",
			Affected:    []RangeSpec{rng("2.3.0", "2.3.8"), rng("2.4.0", "2.4.4")},
		},
		{
			ID: "CVE-2024-34102", Severity: "critical",
			Title:       "Magento / Adobe Commerce: XXE nested deserialization (CosmicSting)",
			Description: "Improper restriction of XML external entity references enables information disclosure and, chained, remote code execution. Exploited in the wild.",
			Reference:   nvd + "CVE-2024-34102", Note: "fixed in 2.4.7-p1 / 2.4.6-p6 / 2.4.5-p8 / 2.4.4-p9",
			Affected: []RangeSpec{rng("2.3.0", "2.4.8")},
		},
	},
	"joomla": {
		{
			ID: "CVE-2023-23752", Severity: "medium",
			Title:       "Joomla: improper access control exposes webservice credentials",
			Description: "An unauthenticated request can reach privileged configuration endpoints.",
			Reference:   nvd + "CVE-2023-23752",
			Affected:    []RangeSpec{rng("4.0.0", "4.2.8")},
		},
		{
			ID: "CVE-2015-8562", Severity: "critical",
			Title:       "Joomla: PHP object injection remote code execution",
			Description: "A crafted User-Agent/X-Forwarded-For enables object injection and remote code execution.",
			Reference:   nvd + "CVE-2015-8562",
			Affected:    []RangeSpec{rng("1.5.0", "3.4.6")},
		},
		{
			ID: "CVE-2017-8917", Severity: "critical",
			Title:       "Joomla: SQL injection in core (3.7.0)",
			Description: "A SQL injection in the com_fields component, introduced in 3.7.0, allows unauthenticated database access.",
			Reference:   nvd + "CVE-2017-8917",
			Affected:    []RangeSpec{rng("3.7.0", "3.7.1")},
		},
		{
			ID: "CVE-2024-21726", Severity: "medium",
			Title:       "Joomla: core XSS via inadequate content filtering",
			Description: "Inadequate filtering in the core content layer allows stored cross-site scripting that can be chained to privilege escalation.",
			Reference:   nvd + "CVE-2024-21726",
			Affected:    []RangeSpec{rng("4.0.0", "4.4.3"), rng("5.0.0", "5.0.3")},
		},
	},
}

// builtinEOL maps a major.minor branch to its end of security support date.
var builtinEOL = map[string]string{
	"5.4": "2015-09-14",
	"5.5": "2016-07-21",
	"5.6": "2018-12-31",
	"7.0": "2019-01-10",
	"7.1": "2019-12-01",
	"7.2": "2020-11-30",
	"7.3": "2021-12-06",
	"7.4": "2022-11-28",
	"8.0": "2023-11-26",
	"8.1": "2025-12-31",
	"8.2": "2026-12-31",
	"8.3": "2027-12-31",
	"8.4": "2028-12-31",
	"8.5": "2029-12-31",
}
