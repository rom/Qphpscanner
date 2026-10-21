package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/rom/qphpscanner/internal/scanner"
)

func writeCSV(w io.Writer, res *scanner.ScanResult) error {
	cw := csv.NewWriter(w)
	header := []string{
		"host", "port", "scheme", "url", "port_open", "banner",
		"http_status", "server", "powered_by",
		"php_verdict", "php_confidence", "php_variant", "php_version",
		"end_of_life", "frameworks", "vuln_count", "vuln_ids", "max_severity",
		"composer_packages", "composer_advisory_leads",
		"security_txt", "server_product", "server_version", "behind_proxy", "cdn", "waf",
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, t := range res.Targets {
		for _, s := range t.Services {
			row := []string{
				s.Host, fmt.Sprintf("%d", s.Port), s.Scheme, s.URL,
				fmt.Sprintf("%t", s.PortOpen), s.Banner,
			}
			if s.HTTP != nil {
				row = append(row, fmt.Sprintf("%d", s.HTTP.Status), s.HTTP.Server, s.HTTP.PoweredBy)
			} else {
				row = append(row, "", "", "")
			}
			if s.PHP != nil {
				maxSev := ""
				for _, v := range s.PHP.Vulnerabilities {
					maxSev = worseSeverity(maxSev, v.Severity)
				}
				ids := make([]string, 0, len(s.PHP.Vulnerabilities))
				for _, v := range s.PHP.Vulnerabilities {
					ids = append(ids, v.ID)
				}
				composerPkgs, composerAdv := 0, 0
				if s.PHP.Composer != nil {
					composerPkgs = len(s.PHP.Composer.Packages)
					composerAdv = s.PHP.Composer.AdvisoryCount()
				}
				row = append(row,
					string(s.PHP.Verdict), fmt.Sprintf("%d", s.PHP.Confidence),
					s.PHP.Variant, s.PHP.Version, fmt.Sprintf("%t", s.PHP.EndOfLife),
					strings.Join(s.PHP.Frameworks, "|"),
					fmt.Sprintf("%d", len(s.PHP.Vulnerabilities)),
					strings.Join(ids, "|"), maxSev,
					fmt.Sprintf("%d", composerPkgs), fmt.Sprintf("%d", composerAdv),
				)
			} else {
				row = append(row, "", "", "", "", "", "", "0", "", "", "0", "0")
			}
			row = append(row, fmt.Sprintf("%t", s.SecurityTxt != nil && s.SecurityTxt.Present))

			serverProduct, serverVersion := "", ""
			if s.Server != nil {
				serverProduct, serverVersion = s.Server.Product, s.Server.Version
			}
			behindProxy, cdn, waf := "false", "", ""
			if s.Proxy != nil && s.Proxy.Present {
				behindProxy = "true"
				cdn = strings.Join(s.Proxy.CDN, "|")
				waf = strings.Join(s.Proxy.WAF, "|")
			}
			row = append(row, serverProduct, serverVersion, behindProxy, cdn, waf)

			if err := cw.Write(row); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}
