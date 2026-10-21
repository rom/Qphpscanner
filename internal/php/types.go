// Package php contains the heuristics that decide whether a service is backed
// by PHP, and — in deep mode — fingerprints its version, variant, frameworks,
// extensions/modules and correlates known version-based vulnerabilities.
//
// Everything this package does is passive fingerprinting and evidence
// collection: it reads banners, headers, cookies and response bodies and
// reasons about them. It does not attempt to exploit anything.
package php

// Verdict is a coarse, human-facing classification derived from Confidence.
type Verdict string

const (
	VerdictConfirmed Verdict = "confirmed"
	VerdictLikely    Verdict = "likely"
	VerdictPossible  Verdict = "possible"
	VerdictNone      Verdict = "none"
)

// Evidence is a single observation that contributed to the verdict.
type Evidence struct {
	// Signal is a stable, machine-friendly identifier, e.g.
	// "header.x-powered-by" or "body.php-error".
	Signal string `json:"signal"`
	// Source names where the observation came from (a URL or header name).
	Source string `json:"source"`
	// Detail is a human readable explanation.
	Detail string `json:"detail"`
	// Data is the raw matched snippet (bounded), useful as proof in reports.
	Data string `json:"data,omitempty"`
	// Weight is this signal's contribution to the confidence score.
	Weight int `json:"weight"`
	// Confidence is a human tier (low/medium/high) derived from Weight.
	Confidence string `json:"confidence"`

	// --- Provenance metadata (where / how / what) ---
	// Where names the location of the match, e.g. "response header
	// 'X-Powered-By'", "response body", "cookie", "request URL".
	Where string `json:"where,omitempty"`
	// How names the matching technique, e.g. "header substring match",
	// "regular expression", "cookie-name match", "URL suffix".
	How string `json:"how,omitempty"`
	// Pattern is the literal matcher used (the substring or regex source).
	Pattern string `json:"pattern,omitempty"`
	// Snippet is the matched text with a little surrounding context.
	Snippet string `json:"snippet,omitempty"`
	// Line is the 1-based line number in the response body, when applicable.
	Line int `json:"line,omitempty"`
	// Probe is the request (method + URL) whose response produced the match.
	Probe string `json:"probe,omitempty"`
	// Status is the HTTP response code of the probe that produced the match
	// (0 when the evidence did not come from an HTTP response).
	Status int `json:"status,omitempty"`
}

// confidenceTier maps a signal weight to a low/medium/high label.
func confidenceTier(weight int) string {
	switch {
	case weight >= 60:
		return "high"
	case weight >= 30:
		return "medium"
	default:
		return "low"
	}
}

// Vulnerability is a known issue correlated purely from the detected version.
// It is an informational lead, not a confirmed, exploited finding.
type Vulnerability struct {
	ID               string `json:"id"`
	Severity         string `json:"severity"`
	Title            string `json:"title"`
	AffectedVersions string `json:"affected_versions"`
	Description      string `json:"description"`
	Reference        string `json:"reference,omitempty"`
	// MatchBasis explains how the correlation was made.
	MatchBasis string `json:"match_basis"`
}

// Detection is the full PHP assessment of one service.
type Detection struct {
	IsPHP      bool    `json:"is_php"`
	Verdict    Verdict `json:"verdict"`
	Confidence int     `json:"confidence"` // 0-100

	Variant       string `json:"variant,omitempty"`        // PHP, HHVM, ...
	Version       string `json:"version,omitempty"`        // e.g. 7.4.33
	VersionSource string `json:"version_source,omitempty"` // how the version was learned
	EndOfLife     bool   `json:"end_of_life,omitempty"`
	EOLDetail     string `json:"eol_detail,omitempty"`

	Frameworks        []string          `json:"frameworks,omitempty"`
	FrameworkVersions map[string]string `json:"framework_versions,omitempty" xml:"-"`
	Extensions        []string          `json:"extensions,omitempty"`
	Modules           []string          `json:"modules,omitempty"`
	// Addons are PHP tools, dev aids and runtime agents that give the stack
	// away (e.g. phpMyAdmin, Adminer, Laravel Debugbar, Whoops, New Relic).
	Addons []string `json:"addons,omitempty"`
	// SAPI is a best-effort guess of the server API (e.g. "apache (mod_php)",
	// "php-fpm", "php-cgi").
	SAPI string `json:"sapi,omitempty"`

	// FaviconHash is the Shodan-style mmh3 hash of the site favicon, when one
	// was fetched (deep mode). Useful for pivoting/fingerprinting.
	FaviconHash string `json:"favicon_hash,omitempty"`

	PHPInfoExposed bool   `json:"phpinfo_exposed,omitempty"`
	PHPInfoURL     string `json:"phpinfo_url,omitempty"`

	Evidence        []Evidence      `json:"evidence,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// scoreToVerdict maps a confidence score to a verdict band.
func scoreToVerdict(score int) Verdict {
	switch {
	case score >= 70:
		return VerdictConfirmed
	case score >= 50:
		return VerdictLikely
	case score >= 25:
		return VerdictPossible
	default:
		return VerdictNone
	}
}
