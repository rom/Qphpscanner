package php

import (
	"encoding/json"
	"sort"
	"strings"
)

// Composer dependency inventory (a partial, passive SBOM). When a project's
// Composer metadata is web-exposed or supplied by the operator, qphpscanner
// parses it into a structured list of packages — distinguishing declared
// requirements from resolved/installed versions — and correlates each resolved
// package against package-level advisory data. Everything here is read-only
// parsing of already-collected bytes; nothing is probed or executed.

// Package classification. Each inventory entry carries exactly one class
// describing the strongest evidence available for it.
const (
	// ComposerClassRequired is a declared constraint from composer.json
	// (e.g. "^2.0"), with no resolved version seen.
	ComposerClassRequired = "required"
	// ComposerClassLocked is a resolved version pinned in composer.lock.
	ComposerClassLocked = "locked"
	// ComposerClassInstalled is a concrete version reported by
	// vendor/composer/installed.json.
	ComposerClassInstalled = "installed"
)

// Bounds so a hostile or huge installed.json cannot blow up memory or output.
const (
	// maxComposerPackages caps how many distinct packages are retained.
	maxComposerPackages = 500
	// maxComposerBytes caps the size of any single Composer document parsed.
	maxComposerBytes = 3 << 20 // 3 MiB
)

// SuppliedComposerFile is operator-provided Composer file content, used to build
// an inventory for a target whose Composer files are not web-exposed.
type SuppliedComposerFile struct {
	// Name is the original filename or a label, used only for provenance and to
	// help classify the file (composer.json / composer.lock / installed.json).
	Name string
	// Data is the raw file content.
	Data []byte
}

// ComposerPackage is one dependency learned from Composer metadata.
type ComposerPackage struct {
	Name string `json:"name" xml:"name"`
	// Version is the resolved version (locked/installed) or, for a
	// required-only entry, the declared constraint.
	Version string `json:"version,omitempty" xml:"version,omitempty"`
	// Class is one of required / locked / installed.
	Class string `json:"class" xml:"class"`
	// Constraint is the composer.json require constraint, shown alongside a
	// resolved version when both are known.
	Constraint string `json:"constraint,omitempty" xml:"constraint,omitempty"`
	// Source is the VCS source reference (commit) where present.
	Source string `json:"source,omitempty" xml:"source,omitempty"`
	// Dev marks a dependency that appears only in the dev sections.
	Dev bool `json:"dev,omitempty" xml:"dev,omitempty"`
	// Advisories are informational, version-range-correlated package leads —
	// framed exactly like the version-correlated vulnerability leads, never
	// confirmed findings.
	Advisories []Vulnerability `json:"advisories,omitempty" xml:"advisories>advisory,omitempty"`
}

// ComposerInventory is the structured dependency inventory for one service.
type ComposerInventory struct {
	// PHPConstraint is the Composer `php` platform requirement (e.g. "^8.1").
	// It is a declared requirement, NOT the detected runtime version, and is
	// never fed into PHP-version correlation.
	PHPConstraint string `json:"php_constraint,omitempty" xml:"php_constraint,omitempty"`
	// Packages is the merged, sorted list of dependencies.
	Packages []ComposerPackage `json:"packages,omitempty" xml:"packages>package,omitempty"`
	// Sources records where the inventory data came from (probe URLs and/or
	// "supplied:<name>" labels).
	Sources []string `json:"sources,omitempty" xml:"sources>source,omitempty"`
	// Truncated is set when a package or size cap was hit.
	Truncated bool `json:"truncated,omitempty" xml:"truncated,omitempty"`
}

// AdvisoryCount returns the total number of package advisory leads across all
// packages in the inventory.
func (inv *ComposerInventory) AdvisoryCount() int {
	if inv == nil {
		return 0
	}
	n := 0
	for _, p := range inv.Packages {
		n += len(p.Advisories)
	}
	return n
}

// composerKind is the recognised Composer document type.
type composerKind int

const (
	kindUnknown composerKind = iota
	kindComposerJSON
	kindComposerLock
	kindInstalledJSON
)

// composerPkgEntry is the shared shape of a package record in composer.lock and
// installed.json.
type composerPkgEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  struct {
		Reference string `json:"reference"`
	} `json:"source"`
}

type composerJSONDoc struct {
	Name       string            `json:"name"`
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

type composerLockDoc struct {
	Packages    []composerPkgEntry `json:"packages"`
	PackagesDev []composerPkgEntry `json:"packages-dev"`
	Platform    map[string]string  `json:"platform"`
	PlatformDev map[string]string  `json:"platform-dev"`
}

type installedJSONDoc struct {
	Packages        []composerPkgEntry `json:"packages"`
	DevPackageNames []string           `json:"dev-package-names"`
}

// pkgAgg accumulates what is known about one package across the parsed files.
type pkgAgg struct {
	name         string
	constraint   string
	locked       string
	lockedSrc    string
	installed    string
	installedSrc string
	dev          bool // appeared in a dev section
	prod         bool // appeared in a non-dev section
}

// composerBuilder merges several Composer documents into one inventory.
type composerBuilder struct {
	byName        map[string]*pkgAgg
	phpConstraint string
	truncated     bool
	sources       []string
}

func newComposerBuilder() *composerBuilder {
	return &composerBuilder{byName: map[string]*pkgAgg{}}
}

func (b *composerBuilder) addSource(s string) {
	for _, existing := range b.sources {
		if existing == s {
			return
		}
	}
	b.sources = append(b.sources, s)
}

// agg returns the aggregate for a package name, creating it if room remains.
// It returns nil once the retained-package cap has been reached.
func (b *composerBuilder) agg(name string) *pkgAgg {
	if a, ok := b.byName[name]; ok {
		return a
	}
	if len(b.byName) >= maxComposerPackages {
		b.truncated = true
		return nil
	}
	a := &pkgAgg{name: name}
	b.byName[name] = a
	return a
}

// setPHPConstraint keeps the first non-empty php platform requirement seen.
func (b *composerBuilder) setPHPConstraint(v string) {
	v = strings.TrimSpace(v)
	if v != "" && b.phpConstraint == "" {
		b.phpConstraint = v
	}
}

// isPlatformPackage reports whether a Composer require key is a platform or
// virtual package (php, hhvm, ext-*, lib-*, composer-*) rather than a real
// vendor/package dependency. Real Composer packages always contain a "/".
func isPlatformPackage(name string) bool {
	return !strings.Contains(name, "/")
}

func (b *composerBuilder) addRequire(name, constraint string, dev bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return
	}
	if isPlatformPackage(name) {
		if name == "php" {
			b.setPHPConstraint(constraint)
		}
		return // other platform/virtual packages are not inventory dependencies
	}
	a := b.agg(name)
	if a == nil {
		return
	}
	if a.constraint == "" {
		a.constraint = strings.TrimSpace(constraint)
	}
	if dev {
		a.dev = true
	} else {
		a.prod = true
	}
}

func (b *composerBuilder) addResolved(name, version, source, class string, dev bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || isPlatformPackage(name) {
		return
	}
	a := b.agg(name)
	if a == nil {
		return
	}
	version = strings.TrimSpace(version)
	switch class {
	case ComposerClassInstalled:
		if a.installed == "" {
			a.installed = version
			a.installedSrc = strings.TrimSpace(source)
		}
	case ComposerClassLocked:
		if a.locked == "" {
			a.locked = version
			a.lockedSrc = strings.TrimSpace(source)
		}
	}
	if dev {
		a.dev = true
	} else {
		a.prod = true
	}
}

// parse decodes one document of the given kind into the builder. It returns
// true when the document parsed as valid JSON (even if it yielded no packages),
// and false on a malformed document — which is skipped gracefully.
func (b *composerBuilder) parse(kind composerKind, data []byte) bool {
	switch kind {
	case kindComposerJSON:
		return b.parseComposerJSON(data)
	case kindComposerLock:
		return b.parseComposerLock(data)
	case kindInstalledJSON:
		return b.parseInstalledJSON(data)
	default:
		return false
	}
}

func (b *composerBuilder) parseComposerJSON(data []byte) bool {
	var doc composerJSONDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return false
	}
	for _, name := range sortedMapKeys(doc.Require) {
		b.addRequire(name, doc.Require[name], false)
	}
	for _, name := range sortedMapKeys(doc.RequireDev) {
		b.addRequire(name, doc.RequireDev[name], true)
	}
	return true
}

func (b *composerBuilder) parseComposerLock(data []byte) bool {
	var doc composerLockDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return false
	}
	for _, e := range doc.Packages {
		b.addResolved(e.Name, e.Version, e.Source.Reference, ComposerClassLocked, false)
	}
	for _, e := range doc.PackagesDev {
		b.addResolved(e.Name, e.Version, e.Source.Reference, ComposerClassLocked, true)
	}
	b.setPHPConstraint(doc.Platform["php"])
	return true
}

func (b *composerBuilder) parseInstalledJSON(data []byte) bool {
	// Composer 2 wraps the list in an object; Composer 1 is a bare array.
	var doc installedJSONDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		var arr []composerPkgEntry
		if err2 := json.Unmarshal(data, &arr); err2 != nil {
			return false
		}
		doc.Packages = arr
	} else if len(doc.Packages) == 0 {
		var arr []composerPkgEntry
		if json.Unmarshal(data, &arr) == nil {
			doc.Packages = arr
		}
	}
	devSet := map[string]bool{}
	for _, n := range doc.DevPackageNames {
		devSet[strings.ToLower(strings.TrimSpace(n))] = true
	}
	for _, e := range doc.Packages {
		dev := devSet[strings.ToLower(strings.TrimSpace(e.Name))]
		b.addResolved(e.Name, e.Version, e.Source.Reference, ComposerClassInstalled, dev)
	}
	return true
}

// inventory finalises the merged data into a sorted ComposerInventory, or nil
// when nothing was learned. When cat is non-nil, resolved packages are
// correlated against package-advisory data.
func (b *composerBuilder) inventory(cat *Catalog) *ComposerInventory {
	if len(b.byName) == 0 && b.phpConstraint == "" {
		return nil
	}
	inv := &ComposerInventory{
		PHPConstraint: b.phpConstraint,
		Truncated:     b.truncated,
		Sources:       b.sources,
	}
	names := make([]string, 0, len(b.byName))
	for n := range b.byName {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		a := b.byName[n]
		p := ComposerPackage{Name: a.name}
		switch {
		case a.installed != "":
			p.Class, p.Version, p.Source = ComposerClassInstalled, a.installed, a.installedSrc
		case a.locked != "":
			p.Class, p.Version, p.Source = ComposerClassLocked, a.locked, a.lockedSrc
		default:
			p.Class, p.Version = ComposerClassRequired, a.constraint
		}
		// Show the declared constraint alongside a resolved version.
		if a.constraint != "" && p.Class != ComposerClassRequired {
			p.Constraint = a.constraint
		}
		p.Dev = a.dev && !a.prod
		// Correlate only concrete resolved versions; a bare constraint cannot be
		// matched against a version range.
		if cat != nil && (p.Class == ComposerClassInstalled || p.Class == ComposerClassLocked) {
			p.Advisories = cat.CorrelatePackage(a.name, p.Version)
			sortVulns(p.Advisories)
		}
		inv.Packages = append(inv.Packages, p)
	}
	return inv
}

// buildComposerInventory assembles a ComposerInventory from web-exposed Composer
// probe responses and any operator-supplied files. It returns the inventory (or
// nil when no Composer data was found) and whether supplied files contributed.
func buildComposerInventory(in Input, cat *Catalog) (*ComposerInventory, bool) {
	b := newComposerBuilder()

	// Web-exposed Composer files (deep-probe responses), in sorted URL order so
	// the result and any cap truncation are deterministic.
	urls := make([]string, 0, len(in.Extra))
	for u := range in.Extra {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	for _, url := range urls {
		resp := in.Extra[url]
		if resp == nil || resp.Err != "" || resp.Status != 200 || !looksComposerURL(url) {
			continue
		}
		body := resp.BodyString()
		if body == "" {
			continue
		}
		if len(body) > maxComposerBytes {
			b.truncated = true
			continue
		}
		kind := classifyComposer(url, body)
		if kind != kindUnknown && b.parse(kind, []byte(body)) {
			b.addSource(url)
		}
	}

	// Operator-supplied files.
	suppliedFound := false
	for _, f := range in.SuppliedComposer {
		if len(f.Data) == 0 {
			continue
		}
		if len(f.Data) > maxComposerBytes {
			b.truncated = true
			continue
		}
		kind := classifyComposer(f.Name, string(f.Data))
		if kind == kindUnknown || !b.parse(kind, f.Data) {
			continue
		}
		suppliedFound = true
		label := strings.TrimSpace(f.Name)
		if label == "" {
			label = "file"
		}
		b.addSource("supplied:" + label)
	}

	return b.inventory(cat), suppliedFound
}

// looksComposerURL reports whether a probe URL points at a Composer artefact.
func looksComposerURL(u string) bool {
	lu := strings.ToLower(u)
	return strings.Contains(lu, "composer.json") ||
		strings.Contains(lu, "composer.lock") ||
		strings.Contains(lu, "installed.json")
}

// classifyComposer decides which kind of Composer document a file is, preferring
// the filename and falling back to a content sniff.
func classifyComposer(name, body string) composerKind {
	ln := strings.ToLower(name)
	switch {
	case strings.Contains(ln, "installed.json"):
		return kindInstalledJSON
	case strings.Contains(ln, "composer.lock"):
		return kindComposerLock
	case strings.Contains(ln, "composer.json"):
		return kindComposerJSON
	}
	// Content sniff for unlabelled supplied files.
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "[") {
		return kindInstalledJSON // a bare array is a Composer 1 installed.json
	}
	hasPackages := strings.Contains(body, "\"packages\"")
	switch {
	case hasPackages && strings.Contains(body, "\"dev-package-names\""):
		return kindInstalledJSON
	case hasPackages && (strings.Contains(body, "\"packages-dev\"") ||
		strings.Contains(body, "\"content-hash\"") ||
		strings.Contains(body, "\"_readme\"")):
		return kindComposerLock
	case strings.Contains(body, "\"require\""):
		return kindComposerJSON
	case hasPackages:
		return kindInstalledJSON
	}
	return kindUnknown
}

// sortedMapKeys returns a map's keys in sorted order for deterministic output.
func sortedMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
