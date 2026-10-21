package scanner

import (
	"net/url"
	"strconv"
	"time"

	"github.com/rom/qphpscanner/internal/php"
	"github.com/rom/qphpscanner/internal/probe"
	"github.com/rom/qphpscanner/internal/replay"
	"github.com/rom/qphpscanner/internal/version"
)

// multiRecorder fans one exchange out to several recorders.
type multiRecorder []probe.Recorder

func (m multiRecorder) Record(ex probe.Exchange) {
	for _, r := range m {
		r.Record(ex)
	}
}

// combineRecorders returns a single recorder for a set: nil for none, the lone
// recorder for one, or a fan-out for several.
func combineRecorders(recs []probe.Recorder) probe.Recorder {
	switch len(recs) {
	case 0:
		return nil
	case 1:
		return recs[0]
	default:
		return multiRecorder(recs)
	}
}

// ReplayCorpus runs a recorded corpus through the detection pipeline with no
// network, producing a ScanResult just like a live deep scan would — so output,
// reports and diffing all work on replayed results, and loaded signature packs
// / vuln feeds (via opts) are applied for validation.
func ReplayCorpus(corpus *replay.Corpus, opts Options) (*ScanResult, error) {
	start := time.Now()
	results := replay.Replay(corpus, replay.Options{
		Signatures: opts.Signatures,
		Catalog:    opts.Catalog,
	})

	cat := opts.Catalog
	if cat == nil {
		cat = php.DefaultCatalog()
	}
	catPHP, catCMS := cat.Counts()

	out := &ScanResult{
		Meta: Meta{
			Tool:       version.Name,
			Version:    version.Version,
			Mode:       ModeDeep,
			StartedAt:  start,
			TLSMode:    TLSAuto,
			CatalogPHP: catPHP,
			CatalogCMS: catCMS,
		},
	}
	if opts.Signatures != nil {
		out.Meta.SignaturePacks = opts.Signatures.Refs()
	}

	var allResults []ServiceResult
	byHost := map[string][]ServiceResult{}
	var hostOrder []string
	for _, r := range results {
		svc := replayService(r)
		allResults = append(allResults, svc)
		if _, ok := byHost[svc.Host]; !ok {
			hostOrder = append(hostOrder, svc.Host)
		}
		byHost[svc.Host] = append(byHost[svc.Host], svc)
	}
	for _, h := range hostOrder {
		out.Targets = append(out.Targets, TargetResult{Host: h, Services: byHost[h]})
	}

	out.Meta.FinishedAt = time.Now()
	out.Meta.DurationMS = time.Since(start).Milliseconds()
	out.Summary = summarise(allResults, hostOrder, opts)
	return out, nil
}

// replayService turns one replay result into a ServiceResult.
func replayService(r replay.Result) ServiceResult {
	scheme, host, port := splitOrigin(r.Origin)
	svc := ServiceResult{
		Host:     host,
		Port:     port,
		Scheme:   scheme,
		TLS:      scheme == "https",
		URL:      r.TargetURL,
		PortOpen: true,
		PHP:      r.Detection,
	}
	svc.HTTP = &HTTPInfo{URL: r.TargetURL, Status: r.Status}
	return svc
}

// splitOrigin breaks "scheme://host[:port]" into its parts, defaulting the port
// to the scheme's well-known value.
func splitOrigin(origin string) (scheme, host string, port int) {
	u, err := url.Parse(origin)
	if err != nil {
		return "http", origin, 80
	}
	scheme = u.Scheme
	host = u.Hostname()
	if p := u.Port(); p != "" {
		if n, perr := strconv.Atoi(p); perr == nil {
			port = n
		}
	}
	if port == 0 {
		if scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	return scheme, host, port
}
