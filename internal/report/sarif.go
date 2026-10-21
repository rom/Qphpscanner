package report

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/rom/qphpscanner/internal/php"
	"github.com/rom/qphpscanner/internal/scanner"
	"github.com/rom/qphpscanner/internal/version"
)

// Minimal SARIF 2.1.0 model (static analysis results interchange format), so
// results can be ingested by CI and security tooling.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifText           `json:"shortDescription"`
	HelpURI          string              `json:"helpUri,omitempty"`
	Properties       sarifRuleProperties `json:"properties"`
}

type sarifRuleProperties struct {
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    sarifText              `json:"message"`
	Locations  []sarifLocation        `json:"locations"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

func writeSARIF(w io.Writer, res *scanner.ScanResult) error {
	rules := map[string]sarifRule{}
	var results []sarifResult

	addRule := func(id, name, desc, helpURI, severity string, tags []string) {
		if _, ok := rules[id]; ok {
			return
		}
		rules[id] = sarifRule{
			ID: id, Name: name,
			ShortDescription: sarifText{Text: desc},
			HelpURI:          helpURI,
			Properties:       sarifRuleProperties{SecuritySeverity: securityScore(severity), Tags: tags},
		}
	}

	for _, t := range res.Targets {
		for _, s := range t.Services {
			if s.PHP == nil {
				continue
			}
			loc := []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifact{URI: s.URL}}}}

			for _, v := range s.PHP.Vulnerabilities {
				addRule(v.ID, v.Title, v.Title, v.Reference, v.Severity, []string{"security", "vulnerability"})
				results = append(results, sarifResult{
					RuleID:    v.ID,
					Level:     sarifLevel(v.Severity),
					Message:   sarifText{Text: v.ID + ": " + v.Title + " (" + v.AffectedVersions + ")"},
					Locations: loc,
					Properties: map[string]interface{}{
						"severity": v.Severity, "host": s.Host, "port": s.Port,
						"php_version": s.PHP.Version, "match_basis": v.MatchBasis,
					},
				})
			}

			if s.PHP.EndOfLife {
				addRule("php-end-of-life", "PHP branch end of life", "The detected PHP release branch no longer receives security support", "https://www.php.net/supported-versions.php", "high", []string{"security", "maintenance"})
				results = append(results, sarifResult{
					RuleID: "php-end-of-life", Level: "warning",
					Message:    sarifText{Text: s.PHP.EOLDetail},
					Locations:  loc,
					Properties: map[string]interface{}{"host": s.Host, "port": s.Port, "php_version": s.PHP.Version},
				})
			}
			if s.PHP.PHPInfoExposed {
				addRule("phpinfo-exposed", "phpinfo() exposed", "phpinfo() output is publicly accessible", "", "medium", []string{"security", "information-disclosure"})
				results = append(results, sarifResult{
					RuleID: "phpinfo-exposed", Level: "warning",
					Message:    sarifText{Text: "phpinfo() is exposed at " + s.PHP.PHPInfoURL},
					Locations:  loc,
					Properties: map[string]interface{}{"host": s.Host, "port": s.Port},
				})
			}

			// Composer package advisory leads (version-range correlations).
			if s.PHP.Composer != nil {
				for _, p := range s.PHP.Composer.Packages {
					for _, a := range p.Advisories {
						addRule(a.ID, a.Title, a.Title, a.Reference, a.Severity, []string{"security", "vulnerability", "dependency"})
						results = append(results, sarifResult{
							RuleID:    a.ID,
							Level:     sarifLevel(a.Severity),
							Message:   sarifText{Text: a.ID + ": " + strings.TrimSpace(p.Name+" "+p.Version) + " — " + a.Title + " (" + a.AffectedVersions + ")"},
							Locations: loc,
							Properties: map[string]interface{}{
								"severity": a.Severity, "host": s.Host, "port": s.Port,
								"composer_package": p.Name, "package_version": p.Version,
								"match_basis": a.MatchBasis,
							},
						})
					}
				}
			}
		}
	}

	ruleList := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	if results == nil {
		results = []sarifResult{}
	}

	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: version.Name, Version: res.Meta.Version,
				InformationURI: "https://github.com/rom/qphpscanner",
				Rules:          ruleList,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

func sarifLevel(severity string) string {
	switch php.SeverityRank(severity) {
	case 4, 3:
		return "error"
	case 2:
		return "warning"
	default:
		return "note"
	}
}

func securityScore(severity string) string {
	switch php.SeverityRank(severity) {
	case 4:
		return "9.0"
	case 3:
		return "7.5"
	case 2:
		return "5.0"
	case 1:
		return "3.0"
	default:
		return ""
	}
}
