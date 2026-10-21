package php

import (
	"encoding/json"
	"sort"
	"strings"
)

// maxComposerPackages bounds how many packages the inventory retains, so a huge
// installed.json cannot blow up memory or output.
const maxComposerPackages = 500

// ComposerInventory is the dependency inventory parsed from a project's Composer
// metadata (a partial SBOM). The PHP platform requirement is kept separate from
// any detected runtime version — a Composer "php" constraint is a requirement,
// not the version actually running.
type ComposerInventory struct {
	PHPRequire string            `json:"php_require,omitempty" xml:"php_require,omitempty"`
	Packages   []ComposerPackage `json:"packages,omitempty" xml:"packages>package,omitempty"`
}

// ComposerPackage is one dependency and how it was learned.
type ComposerPackage struct {
	Name    string `json:"name" xml:"name,attr"`
	Version string `json:"version" xml:"version,attr"`
	// Class is the most authoritative source seen: required / required-dev
	// (a constraint from composer.json), locked (composer.lock) or installed
	// (vendor/composer/installed.json — a concrete, running version).
	Class           string          `json:"class" xml:"class,attr"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty" xml:"vulnerabilities>vulnerability,omitempty"`
}

type composerDoc struct {
	Require     map[string]string `json:"require"`
	RequireDev  map[string]string `json:"require-dev"`
	Packages    []composerPkg     `json:"packages"`
	PackagesDev []composerPkg     `json:"packages-dev"`
}

type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

var composerClassRank = map[string]int{"required": 1, "required-dev": 2, "locked": 3, "installed": 4}

// classifyComposer sniffs a raw body into "json", "lock", "installed" or "".
// Used for operator-supplied files, where there is no URL to go by.
func classifyComposer(body string) string {
	t := strings.TrimSpace(body)
	if t == "" {
		return ""
	}
	if strings.HasPrefix(t, "[") {
		return "installed" // Composer 1 installed.json is a bare array
	}
	switch {
	case strings.Contains(t, `"content-hash"`) || strings.Contains(t, `"_readme"`):
		return "lock"
	case strings.Contains(t, `"dev-package-names"`) || strings.Contains(t, `"version_normalized"`):
		return "installed"
	case strings.Contains(t, `"packages"`):
		return "lock"
	case strings.Contains(t, `"require"`) || strings.Contains(t, `"require-dev"`):
		return "json"
	}
	return ""
}

func composerCleanVersion(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}

// composerPlatform reports whether a require key is a platform/virtual package
// (php, ext-*, lib-*, composer-runtime-api, …) rather than a real dependency.
// Real packages are always "vendor/name".
func composerPlatform(name string) bool {
	return !strings.Contains(name, "/")
}

// parseComposerPackages decodes the packages array of a composer.lock or
// installed.json body (object form or Composer-1 bare array).
func parseComposerPackages(body string) []composerPkg {
	t := strings.TrimSpace(body)
	if t == "" {
		return nil
	}
	if strings.HasPrefix(t, "[") {
		var arr []composerPkg
		_ = json.Unmarshal([]byte(t), &arr)
		return arr
	}
	var d composerDoc
	if json.Unmarshal([]byte(t), &d) != nil {
		return nil
	}
	return append(d.Packages, d.PackagesDev...)
}

// buildComposerInventory assembles a deduplicated inventory from the three
// Composer file bodies (any may be empty). Each package is kept once, labelled
// with the most authoritative class seen. Returns nil when nothing was found.
func buildComposerInventory(jsonBody, lockBody, installedBody string) *ComposerInventory {
	inv := &ComposerInventory{}
	idx := map[string]int{}
	add := func(name, version, class string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		if i, ok := idx[name]; ok {
			if composerClassRank[class] > composerClassRank[inv.Packages[i].Class] {
				inv.Packages[i].Class = class
				inv.Packages[i].Version = composerCleanVersion(version)
			}
			return
		}
		if len(inv.Packages) >= maxComposerPackages {
			return
		}
		idx[name] = len(inv.Packages)
		inv.Packages = append(inv.Packages, ComposerPackage{Name: name, Version: composerCleanVersion(version), Class: class})
	}

	if jsonBody != "" {
		var d composerDoc
		if json.Unmarshal([]byte(jsonBody), &d) == nil {
			for name, c := range d.Require {
				if strings.EqualFold(name, "php") {
					inv.PHPRequire = c
					continue
				}
				if composerPlatform(name) {
					continue
				}
				add(name, c, "required")
			}
			for name, c := range d.RequireDev {
				if composerPlatform(name) {
					continue
				}
				add(name, c, "required-dev")
			}
		}
	}
	for _, p := range parseComposerPackages(lockBody) {
		add(p.Name, p.Version, "locked")
	}
	for _, p := range parseComposerPackages(installedBody) {
		add(p.Name, p.Version, "installed")
	}

	sort.Slice(inv.Packages, func(i, j int) bool { return inv.Packages[i].Name < inv.Packages[j].Name })
	if len(inv.Packages) == 0 && inv.PHPRequire == "" {
		return nil
	}
	return inv
}

// correlateComposer attaches package-advisory leads to each concrete-version
// package (locked/installed). Declared constraints are not concrete versions
// and are left uncorrelated.
func correlateComposer(cat *Catalog, inv *ComposerInventory, facts ObservedFacts) {
	if inv == nil || cat == nil {
		return
	}
	for i := range inv.Packages {
		p := &inv.Packages[i]
		if p.Class != "locked" && p.Class != "installed" {
			continue
		}
		if leads := cat.CorrelatePackage(p.Name, p.Version, facts); len(leads) > 0 {
			sortVulns(leads)
			p.Vulnerabilities = leads
		}
	}
}
