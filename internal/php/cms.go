package php

import (
	"regexp"
	"strings"
)

var (
	reWPGenerator     = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']WordPress ([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reWPReadme        = regexp.MustCompile(`(?i)<br\s*/?>\s*Version ([0-9]+\.[0-9]+(?:\.[0-9]+)?)|Version ([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reDrupalChangelog = regexp.MustCompile(`(?i)Drupal ([0-9]+\.[0-9]+(?:\.[0-9]+)?),`)
	reDrupalGen       = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']Drupal ([0-9]+(?:\.[0-9]+)*)`)
	reJoomlaManifest  = regexp.MustCompile(`(?i)<version>\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*</version>`)
	reJoomlaGen       = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']Joomla!? ([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reMediaWikiGen    = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']MediaWiki ([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reTYPO3Gen        = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']TYPO3 CMS ([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	// Nextcloud/ownCloud expose product and version in status.php's JSON.
	reCloudProduct    = regexp.MustCompile(`(?i)"productname"\s*:\s*"([^"]+)"`)
	reCloudVersionStr = regexp.MustCompile(`(?i)"versionstring"\s*:\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	// Magento exposes "Magento/2.4.6 (Community)" at /magento_version.
	reMagentoVersion = regexp.MustCompile(`(?i)Magento/([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	// Drupal also advertises its version in the X-Generator header.
	reDrupalVer = regexp.MustCompile(`(?i)Drupal ([0-9]+(?:\.[0-9]+)*)`)
)

// canonCloud maps a status.php productname to the canonical PHP groupware name,
// or "" for products that are not the PHP Nextcloud/ownCloud codebase.
func canonCloud(product string) string {
	p := strings.ToLower(strings.TrimSpace(product))
	switch {
	case strings.Contains(p, "nextcloud"):
		return "Nextcloud"
	case strings.Contains(p, "owncloud") && !strings.Contains(p, "infinite scale"):
		return "ownCloud"
	default:
		return ""
	}
}

// detectCMSVersions extracts CMS/framework core versions from the collected
// bodies, preferring the most specific (most dotted) version seen for each.
func detectCMSVersions(in Input, fwSet map[string]bool, addEv func(Evidence), addFw func(string)) map[string]string {
	type cand struct{ ver, src string }
	best := map[string]cand{}
	consider := func(fw, ver, src string) {
		if ver == "" {
			return
		}
		if cur, ok := best[fw]; ok && dotCount(cur.ver) >= dotCount(ver) {
			return
		}
		best[fw] = cand{ver, src}
	}

	type body struct {
		url  string
		text string
	}
	var bodies []body
	if in.Root != nil && in.Root.Err == "" {
		bodies = append(bodies, body{in.TargetURL, in.Root.BodyString()})
	}
	for url, resp := range in.Extra {
		if resp != nil && resp.Err == "" && resp.Status == 200 {
			bodies = append(bodies, body{url, resp.BodyString()})
		}
	}

	for _, b := range bodies {
		lu := strings.ToLower(b.url)
		if m := reWPGenerator.FindStringSubmatch(b.text); m != nil {
			consider("WordPress", m[1], b.url)
		}
		if strings.Contains(lu, "readme.html") {
			if m := reWPReadme.FindStringSubmatch(b.text); m != nil {
				consider("WordPress", firstNonEmpty(m[1:]), b.url)
			}
		}
		if strings.Contains(lu, "changelog") {
			if m := reDrupalChangelog.FindStringSubmatch(b.text); m != nil {
				consider("Drupal", m[1], b.url)
			}
		}
		if m := reDrupalGen.FindStringSubmatch(b.text); m != nil {
			consider("Drupal", m[1], b.url)
		}
		if strings.Contains(lu, "joomla.xml") {
			if m := reJoomlaManifest.FindStringSubmatch(b.text); m != nil {
				consider("Joomla", m[1], b.url)
			}
		}
		if m := reJoomlaGen.FindStringSubmatch(b.text); m != nil {
			consider("Joomla", m[1], b.url)
		}
		if m := reMediaWikiGen.FindStringSubmatch(b.text); m != nil {
			consider("MediaWiki", m[1], b.url)
		}
		if m := reTYPO3Gen.FindStringSubmatch(b.text); m != nil {
			consider("TYPO3", m[1], b.url)
		}
		if strings.Contains(lu, "magento_version") {
			if m := reMagentoVersion.FindStringSubmatch(b.text); m != nil {
				consider("Magento", m[1], b.url)
			}
		}
		// Nextcloud/ownCloud status.php: productname + versionstring together.
		if mp := reCloudProduct.FindStringSubmatch(b.text); mp != nil {
			if prod := canonCloud(mp[1]); prod != "" {
				if mv := reCloudVersionStr.FindStringSubmatch(b.text); mv != nil {
					consider(prod, mv[1], b.url)
				}
			}
		}
	}

	// Drupal's version also appears in the X-Generator response header.
	consumeGen := func(vals []string) {
		for _, g := range vals {
			if m := reDrupalVer.FindStringSubmatch(g); m != nil {
				consider("Drupal", m[1], "X-Generator header")
			}
		}
	}
	if in.Root != nil {
		consumeGen(in.Root.HeaderValues("X-Generator"))
	}
	for _, resp := range in.Extra {
		if resp != nil {
			consumeGen(resp.HeaderValues("X-Generator"))
		}
	}

	if len(best) == 0 {
		return nil
	}
	out := make(map[string]string, len(best))
	for fw, c := range best {
		out[fw] = c.ver
		addFw(fw)
		addEv(Evidence{
			Signal: "cms.version." + strings.ToLower(fw), Source: c.src, Weight: 15,
			Detail: fw + " core version " + c.ver, Data: c.ver,
		})
	}
	return out
}

func dotCount(s string) int { return strings.Count(s, ".") }

func firstNonEmpty(ss []string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// FaviconPath is fetched in deep mode for the favicon fingerprint.
const FaviconPath = "/favicon.ico"
