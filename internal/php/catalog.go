package php

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// FeedSchema is the schema identifier external feeds should declare.
const FeedSchema = "qphpscanner-vuln-feed/1"

// RangeSpec describes an affected version range. A version matches when every
// populated bound is satisfied:
//
//	Branch      restricts to a single major.minor (e.g. "8.1")
//	Introduced  version >= Introduced
//	Fixed       version <  Fixed
//	LessThan    version <  LessThan  (alias for an open-ended upper bound)
//
// At least one bound must be set for the range to match anything.
type RangeSpec struct {
	Branch     string `json:"branch,omitempty"`
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	LessThan   string `json:"lt,omitempty"`
	// Equals matches a single exact version (used by discrete CSAF products).
	Equals string `json:"eq,omitempty"`
}

func (r RangeSpec) empty() bool {
	return r.Branch == "" && r.Introduced == "" && r.Fixed == "" && r.LessThan == "" && r.Equals == ""
}

func (r RangeSpec) matches(v string) bool {
	if r.empty() {
		return false
	}
	if r.Equals != "" {
		return compareVersion(v, r.Equals) == 0
	}
	if r.Branch != "" {
		maj, min, ok := parseBranch(r.Branch)
		vmaj, vmin, _, vok := parseVersion(v)
		if !ok || !vok || maj != vmaj || min != vmin {
			return false
		}
	}
	if r.Introduced != "" && compareVersion(v, r.Introduced) < 0 {
		return false
	}
	if r.Fixed != "" && compareVersion(v, r.Fixed) >= 0 {
		return false
	}
	if r.LessThan != "" && compareVersion(v, r.LessThan) >= 0 {
		return false
	}
	return true
}

// FeedEntry is one catalogue entry (a CVE or advisory) plus its affected ranges.
type FeedEntry struct {
	ID          string      `json:"id"`
	Severity    string      `json:"severity"`
	Title       string      `json:"title"`
	Description string      `json:"description,omitempty"`
	Reference   string      `json:"reference,omitempty"`
	Note        string      `json:"note,omitempty"`
	Affected    []RangeSpec `json:"affected"`
}

func (e FeedEntry) matches(v string) bool {
	for _, r := range e.Affected {
		if r.matches(v) {
			return true
		}
	}
	return false
}

// VulnFeed is the on-disk / remote JSON format for external vulnerability data.
type VulnFeed struct {
	Schema    string                 `json:"schema"`
	Generated string                 `json:"generated,omitempty"`
	PHP       []FeedEntry            `json:"php,omitempty"`
	CMS       map[string][]FeedEntry `json:"cms,omitempty"`
	EOL       map[string]string      `json:"eol,omitempty"`
}

// Catalog holds the active vulnerability and end-of-life data: the built-in
// curated set, merged with any external feeds.
type Catalog struct {
	php []FeedEntry
	cms map[string][]FeedEntry
	eol map[string]string
}

// DefaultCatalog returns a fresh catalog built from the curated built-in data.
func DefaultCatalog() *Catalog {
	c := &Catalog{
		php: append([]FeedEntry(nil), builtinPHP...),
		cms: map[string][]FeedEntry{},
		eol: map[string]string{},
	}
	for k, v := range builtinCMS {
		c.cms[strings.ToLower(k)] = append([]FeedEntry(nil), v...)
	}
	for k, v := range builtinEOL {
		c.eol[k] = v
	}
	return c
}

// Merge folds an external feed into the catalog (appending entries and
// overriding EOL dates by branch).
func (c *Catalog) Merge(f *VulnFeed) {
	if f == nil {
		return
	}
	c.php = append(c.php, f.PHP...)
	if c.cms == nil {
		c.cms = map[string][]FeedEntry{}
	}
	for k, entries := range f.CMS {
		key := strings.ToLower(k)
		c.cms[key] = append(c.cms[key], entries...)
	}
	if c.eol == nil {
		c.eol = map[string]string{}
	}
	for branch, date := range f.EOL {
		c.eol[branch] = date
	}
}

// Counts reports how many PHP and CMS entries the catalog holds.
func (c *Catalog) Counts() (php, cms int) {
	php = len(c.php)
	for _, e := range c.cms {
		cms += len(e)
	}
	return
}

// CorrelatePHP returns leads for the detected PHP version. HHVM and other
// non-PHP runtimes use their own numbering and are skipped.
func (c *Catalog) CorrelatePHP(variant, version string) []Vulnerability {
	if version == "" {
		return nil
	}
	if variant != "" && variant != "PHP" && variant != "Zend Server" {
		return nil
	}
	if _, _, _, ok := parseVersion(version); !ok {
		return nil
	}
	return matchEntries(c.php, version, "version-correlation")
}

// CorrelateCMS returns leads for a detected CMS/framework core version.
func (c *Catalog) CorrelateCMS(framework, version string) []Vulnerability {
	if framework == "" || version == "" {
		return nil
	}
	entries, ok := c.cms[strings.ToLower(framework)]
	if !ok {
		return nil
	}
	if _, _, _, ok := parseVersion(version); !ok {
		return nil
	}
	return matchEntries(entries, version, framework+" version-correlation")
}

func matchEntries(entries []FeedEntry, version, basisKind string) []Vulnerability {
	var out []Vulnerability
	for _, e := range entries {
		if !e.matches(version) {
			continue
		}
		basis := basisKind
		if e.Note != "" {
			basis += "; applies to: " + e.Note
		}
		out = append(out, Vulnerability{
			ID:               e.ID,
			Severity:         e.Severity,
			Title:            e.Title,
			AffectedVersions: affectedSummary(e.Affected),
			Description:      e.Description,
			Reference:        e.Reference,
			MatchBasis:       basis,
		})
	}
	return out
}

// EOL reports whether the version's release branch has reached end of security
// support, relative to the current date.
func (c *Catalog) EOL(variant, version string) (bool, string) {
	if variant != "" && variant != "PHP" && variant != "Zend Server" {
		return false, ""
	}
	maj, min, _, ok := parseVersion(version)
	if !ok {
		return false, ""
	}
	branch := fmt.Sprintf("%d.%d", maj, min)
	if maj < 5 || (maj == 5 && min < 4) {
		return true, fmt.Sprintf("PHP %s is long past end of life", branch)
	}
	date, known := c.eol[branch]
	if !known {
		return false, ""
	}
	end, err := time.Parse("2006-01-02", date)
	if err != nil {
		return false, ""
	}
	if time.Now().After(end) {
		return true, fmt.Sprintf("PHP %s reached end of security support on %s", branch, date)
	}
	return false, fmt.Sprintf("PHP %s receives security support until %s", branch, date)
}

func affectedSummary(ranges []RangeSpec) string {
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		switch {
		case r.Equals != "":
			parts = append(parts, "= "+r.Equals)
		case r.Branch != "" && r.LessThan != "":
			parts = append(parts, r.Branch+".x < "+r.LessThan)
		case r.Branch != "" && r.Fixed != "":
			parts = append(parts, r.Branch+".x < "+r.Fixed)
		case r.Introduced != "" && r.Fixed != "":
			parts = append(parts, r.Introduced+" – "+r.Fixed)
		case r.LessThan != "":
			parts = append(parts, "< "+r.LessThan)
		case r.Fixed != "":
			parts = append(parts, "< "+r.Fixed)
		case r.Branch != "":
			parts = append(parts, r.Branch+".x")
		}
	}
	return strings.Join(parts, ", ")
}

// ParseFeed decodes feed JSON, auto-detecting the native qphpscanner schema,
// the OSV format (single record or array) and CSAF 2.0 advisories.
func ParseFeed(data []byte) (*VulnFeed, error) {
	switch detectFeedFormat(data) {
	case feedOSV:
		return convertOSV(data)
	case feedCSAF:
		return convertCSAF(data)
	default:
		var f VulnFeed
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("parse vuln feed: %w", err)
		}
		if f.Schema != "" && f.Schema != FeedSchema {
			return nil, fmt.Errorf("unsupported vuln feed schema %q (want %q, or an OSV/CSAF document)", f.Schema, FeedSchema)
		}
		return &f, nil
	}
}

// LoadFeed reads a feed from a local file path or an http(s) URL.
func LoadFeed(ctx context.Context, src string, client *http.Client) (*VulnFeed, error) {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		if client == nil {
			client = &http.Client{Timeout: 30 * time.Second}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch vuln feed: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch vuln feed: HTTP %d", resp.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		if err != nil {
			return nil, err
		}
		return ParseFeed(data)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return nil, fmt.Errorf("read vuln feed: %w", err)
	}
	return ParseFeed(data)
}

// SeverityRank maps a severity string to a comparable rank (higher = worse).
func SeverityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium", "moderate":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func parseBranch(b string) (maj, min int, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(b), ".", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	m, n, _, vok := parseVersion(b + ".0")
	return m, n, vok
}

// compareVersion returns -1, 0 or 1 comparing a and b as major.minor.patch.
func compareVersion(a, b string) int {
	am, an, ap, _ := parseVersion(a)
	bm, bn, bp, _ := parseVersion(b)
	switch {
	case am != bm:
		return sign(am - bm)
	case an != bn:
		return sign(an - bn)
	case ap != bp:
		return sign(ap - bp)
	default:
		return 0
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
