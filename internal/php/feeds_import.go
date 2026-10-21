package php

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// This file imports two standard vulnerability-data formats into the internal
// VulnFeed model: OSV (https://ossf.github.io/osv-schema/, one record or an
// array) and CSAF 2.0 (https://docs.oasis-open.org/csaf/). Both are mapped
// best-effort: PHP-core advisories feed the PHP list, everything else is keyed
// by a normalised framework/package name under CMS.

type feedFormat int

const (
	feedNative feedFormat = iota
	feedOSV
	feedCSAF
)

// detectFeedFormat sniffs the JSON to choose an importer.
func detectFeedFormat(data []byte) feedFormat {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return feedNative
	}
	if trimmed[0] == '[' {
		// A bare array is an OSV record list.
		return feedOSV
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return feedNative
	}
	if _, ok := probe["schema"]; ok {
		if _, native := probe["php"]; native {
			return feedNative
		}
		if _, native := probe["cms"]; native {
			return feedNative
		}
	}
	if _, ok := probe["document"]; ok {
		if _, v := probe["vulnerabilities"]; v {
			return feedCSAF
		}
		if _, v := probe["product_tree"]; v {
			return feedCSAF
		}
	}
	_, hasID := probe["id"]
	_, hasAffected := probe["affected"]
	if hasID && hasAffected {
		return feedOSV
	}
	return feedNative
}

// ---- OSV ------------------------------------------------------------------

type osvRecord struct {
	ID               string          `json:"id"`
	Summary          string          `json:"summary"`
	Details          string          `json:"details"`
	Aliases          []string        `json:"aliases"`
	Affected         []osvAffected   `json:"affected"`
	References       []osvReference  `json:"references"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

type osvAffected struct {
	Package  osvPackage `json:"package"`
	Ranges   []osvRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type osvRange struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func convertOSV(data []byte) (*VulnFeed, error) {
	trimmed := bytes.TrimSpace(data)
	var records []osvRecord
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &records); err != nil {
			return nil, fmt.Errorf("parse OSV array: %w", err)
		}
	} else {
		var one osvRecord
		if err := json.Unmarshal(trimmed, &one); err != nil {
			return nil, fmt.Errorf("parse OSV record: %w", err)
		}
		records = []osvRecord{one}
	}

	feed := &VulnFeed{Schema: FeedSchema, CMS: map[string][]FeedEntry{}}
	for _, rec := range records {
		title := firstText(rec.Summary, rec.Details, rec.ID)
		if len(title) > 160 {
			title = title[:160] + "…"
		}
		sev := osvSeverityLabel(rec.DatabaseSpecific)
		ref := osvPrimaryRef(rec.References)
		id := preferCVE(rec.ID, rec.Aliases)
		for _, aff := range rec.Affected {
			ranges := osvRanges(aff)
			if len(ranges) == 0 {
				continue
			}
			entry := FeedEntry{
				ID: id, Severity: sev, Title: title,
				Description: rec.Details, Reference: ref,
				Note: "OSV: " + aff.Package.Ecosystem + " " + aff.Package.Name, Affected: ranges,
			}
			key, isPHP := feedKeyForPackage(aff.Package.Ecosystem, aff.Package.Name)
			if isPHP {
				feed.PHP = append(feed.PHP, entry)
			} else if key != "" {
				feed.CMS[key] = append(feed.CMS[key], entry)
			}
		}
	}
	return feed, nil
}

// osvRanges turns OSV event lists into RangeSpecs. Discrete versions (no range)
// become exact-match specs.
func osvRanges(aff osvAffected) []RangeSpec {
	var out []RangeSpec
	for _, r := range aff.Ranges {
		if r.Type != "ECOSYSTEM" && r.Type != "SEMVER" && r.Type != "" {
			continue
		}
		var cur RangeSpec
		open := false
		for _, ev := range r.Events {
			if v, ok := ev["introduced"]; ok {
				cur = RangeSpec{}
				if v != "0" && v != "" {
					cur.Introduced = v
				}
				open = true
			}
			if v, ok := ev["fixed"]; ok && open {
				cur.Fixed = v
				out = append(out, cur)
				open = false
			}
			if v, ok := ev["last_affected"]; ok && open {
				// <= last_affected, expressed as < (last_affected patch + 1).
				cur.LessThan = bumpPatch(v)
				out = append(out, cur)
				open = false
			}
		}
		if open && !cur.empty() {
			out = append(out, cur)
		}
	}
	for _, v := range aff.Versions {
		if v != "" {
			out = append(out, RangeSpec{Equals: v})
		}
	}
	return out
}

func osvSeverityLabel(dbSpecific json.RawMessage) string {
	if len(dbSpecific) == 0 {
		return "unknown"
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(dbSpecific, &m); err != nil {
		return "unknown"
	}
	var sev string
	if raw, ok := m["severity"]; ok {
		_ = json.Unmarshal(raw, &sev)
	}
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MODERATE", "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "unknown"
	}
}

func osvPrimaryRef(refs []osvReference) string {
	for _, r := range refs {
		if strings.EqualFold(r.Type, "ADVISORY") {
			return r.URL
		}
	}
	if len(refs) > 0 {
		return refs[0].URL
	}
	return ""
}

// ---- CSAF 2.0 -------------------------------------------------------------

type csafDoc struct {
	Document struct {
		Title    string `json:"title"`
		Tracking struct {
			ID string `json:"id"`
		} `json:"tracking"`
	} `json:"document"`
	ProductTree     csafBranchNode `json:"product_tree"`
	Vulnerabilities []csafVuln     `json:"vulnerabilities"`
}

type csafBranchNode struct {
	Branches         []csafBranch      `json:"branches"`
	FullProductNames []csafFullProduct `json:"full_product_names"`
}

type csafBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Branches []csafBranch `json:"branches"`
	Product  *csafProduct `json:"product"`
}

type csafProduct struct {
	Name string `json:"name"`
	ID   string `json:"product_id"`
}

type csafFullProduct struct {
	Name string `json:"name"`
	ID   string `json:"product_id"`
}

type csafVuln struct {
	CVE   string `json:"cve"`
	Title string `json:"title"`
	Notes []struct {
		Category string `json:"category"`
		Text     string `json:"text"`
	} `json:"notes"`
	Scores []struct {
		CVSSV3 struct {
			BaseSeverity string  `json:"baseSeverity"`
			BaseScore    float64 `json:"baseScore"`
		} `json:"cvss_v3"`
	} `json:"scores"`
	ProductStatus struct {
		KnownAffected []string `json:"known_affected"`
	} `json:"product_status"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

func convertCSAF(data []byte) (*VulnFeed, error) {
	var doc csafDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse CSAF: %w", err)
	}

	// Resolve product_id -> (name, version) from the product tree.
	products := map[string]csafResolved{}
	collectCSAFProducts(doc.ProductTree.Branches, "", products)
	for _, fp := range doc.ProductTree.FullProductNames {
		products[fp.ID] = csafResolved{name: fp.Name, version: versionFromName(fp.Name)}
	}

	feed := &VulnFeed{Schema: FeedSchema, CMS: map[string][]FeedEntry{}}
	for _, v := range doc.Vulnerabilities {
		id := firstText(v.CVE, doc.Document.Tracking.ID)
		title := firstText(v.Title, doc.Document.Title, id)
		sev := csafSeverity(v)
		ref := ""
		if len(v.References) > 0 {
			ref = v.References[0].URL
		}
		// Group affected products by derived key.
		byKey := map[string][]RangeSpec{}
		keyIsPHP := map[string]bool{}
		for _, pid := range v.ProductStatus.KnownAffected {
			res, ok := products[pid]
			if !ok || res.version == "" {
				continue
			}
			key, isPHP := feedKeyForPackage("", res.name)
			spec := csafVersionSpec(res.version)
			if spec.empty() {
				continue
			}
			k := key
			if isPHP {
				k = "__php__"
			}
			byKey[k] = append(byKey[k], spec)
			keyIsPHP[k] = isPHP
		}
		for k, ranges := range byKey {
			entry := FeedEntry{ID: id, Severity: sev, Title: title, Reference: ref, Affected: ranges, Note: "CSAF import"}
			if keyIsPHP[k] {
				feed.PHP = append(feed.PHP, entry)
			} else if k != "" {
				feed.CMS[k] = append(feed.CMS[k], entry)
			}
		}
	}
	return feed, nil
}

type csafResolved struct {
	name    string
	version string
}

// collectCSAFProducts walks the branch tree, tracking the inherited product
// name and recording leaf products with their version.
func collectCSAFProducts(branches []csafBranch, inheritedName string, out map[string]csafResolved) {
	for _, b := range branches {
		name := inheritedName
		version := ""
		switch b.Category {
		case "product_name", "vendor":
			name = b.Name
		case "product_version", "product_version_range":
			version = b.Name
		}
		if b.Product != nil && b.Product.ID != "" {
			pname := b.Product.Name
			if pname == "" {
				pname = name
			}
			ver := version
			if ver == "" {
				ver = versionFromName(pname)
			}
			out[b.Product.ID] = csafResolved{name: pname, version: ver}
		}
		if len(b.Branches) > 0 {
			next := name
			collectCSAFProducts(b.Branches, next, out)
		}
	}
}

func csafSeverity(v csafVuln) string {
	for _, s := range v.Scores {
		switch strings.ToUpper(s.CVSSV3.BaseSeverity) {
		case "CRITICAL":
			return "critical"
		case "HIGH":
			return "high"
		case "MEDIUM", "MODERATE":
			return "medium"
		case "LOW":
			return "low"
		}
		if s.CVSSV3.BaseScore > 0 {
			return scoreToSeverity(s.CVSSV3.BaseScore)
		}
	}
	return "unknown"
}

func scoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
	}
}

// csafVersionSpec turns a CSAF version or version-range string into a RangeSpec.
func csafVersionSpec(s string) RangeSpec {
	s = strings.TrimSpace(s)
	if s == "" {
		return RangeSpec{}
	}
	// "vers:" range, or plain comparator soup like ">=1.0 <2.0".
	if strings.Contains(s, "<") || strings.Contains(s, ">") || strings.HasPrefix(s, "vers:") {
		return parseComparatorRange(s)
	}
	return RangeSpec{Equals: s}
}

func parseComparatorRange(s string) RangeSpec {
	s = strings.TrimPrefix(s, "vers:")
	if i := strings.Index(s, "/"); i >= 0 && strings.HasPrefix(s, "composer") {
		s = s[i+1:]
	}
	s = strings.ReplaceAll(s, "|", " ")
	var spec RangeSpec
	for _, tok := range strings.Fields(s) {
		switch {
		case strings.HasPrefix(tok, ">="):
			spec.Introduced = strings.TrimPrefix(tok, ">=")
		case strings.HasPrefix(tok, "<="):
			spec.LessThan = bumpPatch(strings.TrimPrefix(tok, "<="))
		case strings.HasPrefix(tok, "<"):
			spec.Fixed = strings.TrimPrefix(tok, "<")
		case strings.HasPrefix(tok, ">"):
			spec.Introduced = bumpPatch(strings.TrimPrefix(tok, ">"))
		case strings.HasPrefix(tok, "="):
			spec.Equals = strings.TrimPrefix(tok, "=")
		}
	}
	return spec
}

// bumpPatch increments the patch component so an inclusive bound (<=, >) can be
// expressed with the strict comparisons RangeSpec uses.
func bumpPatch(v string) string {
	maj, min, patch, ok := parseVersion(v)
	if !ok {
		return v
	}
	return fmt.Sprintf("%d.%d.%d", maj, min, patch+1)
}

// ---- shared helpers -------------------------------------------------------

// feedKeyForPackage maps an ecosystem/package name to a framework key, or flags
// it as PHP core.
func feedKeyForPackage(ecosystem, name string) (key string, isPHP bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "php" || n == "php-src" || strings.HasPrefix(n, "php/") || strings.HasPrefix(n, "php:") {
		return "", true
	}
	known := []struct{ sub, key string }{
		{"drupal", "drupal"}, {"wordpress", "wordpress"}, {"wpackagist", "wordpress"},
		{"joomla", "joomla"}, {"typo3", "typo3"}, {"laravel", "laravel"},
		{"symfony", "symfony"}, {"magento", "magento"}, {"prestashop", "prestashop"},
		{"mediawiki", "mediawiki"}, {"moodle", "moodle"}, {"phpbb", "phpbb"},
		{"opencart", "opencart"}, {"october", "october cms"}, {"silverstripe", "silverstripe"},
		{"contao", "contao"}, {"concrete", "concretecms"}, {"grav", "grav"},
		{"statamic", "statamic"}, {"nextcloud", "nextcloud/owncloud"}, {"owncloud", "nextcloud/owncloud"},
		{"roundcube", "roundcube"}, {"matomo", "matomo"}, {"piwik", "matomo"},
		{"dolibarr", "dolibarr"}, {"glpi", "glpi"}, {"zabbix", "zabbix"},
	}
	for _, k := range known {
		if strings.Contains(n, k.sub) {
			return k.key, false
		}
	}
	if i := strings.LastIndex(n, "/"); i >= 0 {
		n = n[i+1:]
	}
	return n, false
}

func versionFromName(name string) string {
	// A "name version" or "name X.Y.Z" string; take the last space-separated
	// token that parses as a version.
	fields := strings.Fields(name)
	for i := len(fields) - 1; i >= 0; i-- {
		if _, _, _, ok := parseVersion(strings.TrimLeft(fields[i], "vV")); ok {
			return strings.TrimLeft(fields[i], "vV")
		}
	}
	return ""
}

func firstText(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}

// preferCVE returns a CVE alias when the primary id is a database id (GHSA-…).
func preferCVE(id string, aliases []string) string {
	if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
		return id
	}
	for _, a := range aliases {
		if strings.HasPrefix(strings.ToUpper(a), "CVE-") {
			return a
		}
	}
	return id
}
