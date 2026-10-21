package scanner

import (
	"net/url"
	"strconv"
	"time"

	"github.com/rom/qphpscanner/internal/corpus"
	"github.com/rom/qphpscanner/internal/php"
	"github.com/rom/qphpscanner/internal/probe"
	"github.com/rom/qphpscanner/internal/version"
)

// Replay reconstructs a ScanResult by running each service's captured responses
// back through the PHP detection pipeline, offline — no network, no targets.
// It reproduces the per-service PHP detection and HTTP summary (the detection
// regression surface); network-only facets of a live scan (port state, service
// banners, security.txt, web-server/proxy identification) are not part of the
// corpus and are left unset. opts.Catalog overrides the built-in vuln catalogue
// and opts.ComposerFiles augment any captured Composer inputs; detection
// otherwise runs with the current build's catalogues and signature packs, which
// is what a regression run wants.
func Replay(c *corpus.Corpus, opts Options) *ScanResult {
	opts = opts.withDefaults()
	start := time.Now()

	var results []ServiceResult
	byHost := map[string][]ServiceResult{}
	hostOrder := []string{}
	hostSeen := map[string]bool{}
	anyDeep := false

	for _, svc := range c.Services {
		r := replayService(svc, opts)
		if svc.Deep {
			anyDeep = true
		}
		results = append(results, r)
		if !hostSeen[r.Host] {
			hostSeen[r.Host] = true
			hostOrder = append(hostOrder, r.Host)
		}
		byHost[r.Host] = append(byHost[r.Host], r)
	}

	mode := ModeDetect
	if anyDeep {
		mode = ModeDeep
	}
	cat := opts.Catalog
	if cat == nil {
		cat = php.DefaultCatalog()
	}
	catPHP, catCMS := cat.Counts()

	out := &ScanResult{
		Meta: Meta{
			Tool:           version.Name,
			Version:        version.Version,
			Mode:           mode,
			StartedAt:      start,
			FinishedAt:     time.Now(),
			DurationMS:     time.Since(start).Milliseconds(),
			CatalogPHP:     catPHP,
			CatalogCMS:     catCMS,
			SignaturePacks: php.SignaturePacks(),
		},
	}
	for _, h := range hostOrder {
		svcs := byHost[h]
		if len(svcs) == 0 {
			continue
		}
		out.Targets = append(out.Targets, TargetResult{Host: h, Services: svcs})
	}
	out.Summary = summarise(results, hostOrder, opts)
	return out
}

// replayService turns one captured service into a ServiceResult by rebuilding
// the detection Input and running php.Analyze.
func replayService(svc corpus.Service, opts Options) ServiceResult {
	res := ServiceResult{URL: svc.Target, PortOpen: true}
	if u, err := url.Parse(svc.Target); err == nil {
		res.Host = u.Hostname()
		res.Scheme = u.Scheme
		res.TLS = u.Scheme == "https"
		res.Port = replayPort(u)
	}

	root := svc.Root.ToResponse()
	if root == nil || (root.Err != "" && root.Status == 0) {
		if root != nil {
			res.Error = root.Err
		}
		return res
	}
	res.HTTP = buildHTTPInfo(res.URL, root)

	in := php.Input{
		TargetURL:     res.URL,
		Deep:          svc.Deep,
		Root:          root,
		Catalog:       opts.Catalog,
		ComposerFiles: opts.ComposerFiles,
	}
	if svc.Deep {
		in.EasterCredits = svc.EasterCredits.ToResponse()
		in.EasterLogo = svc.EasterLogo.ToResponse()
		in.Favicon = svc.Favicon.ToResponse()
		in.PathInfo = svc.PathInfo.ToResponse()
		in.Control = svc.Control.ToResponse()
		if len(svc.Extra) > 0 {
			in.Extra = make(map[string]*probe.Response, len(svc.Extra))
			for k, v := range svc.Extra {
				in.Extra[k] = v.ToResponse()
			}
		}
	}
	res.PHP = php.Analyze(in)
	return res
}

// replayPort recovers the port from a captured target URL, defaulting by scheme
// when it is implicit.
func replayPort(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}
