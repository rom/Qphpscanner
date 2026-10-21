package php

import (
	"strings"
	"testing"

	"github.com/rom/qphpscanner/internal/probe"
)

// A catch-all server returns the same generic 200 page for every path,
// including a guaranteed-missing one. URL-only (phpMyAdmin path) and
// behavioural (PATH_INFO) signals must not, on their own, reach a PHP verdict.
func TestSoftNotFoundSuppressesUrlOnlySignals(t *testing.T) {
	page := "<html><body>" + strings.Repeat("generic landing page. ", 20) + "</body></html>"
	ct := map[string]string{"Content-Type": "text/html"}
	in := Input{
		TargetURL: "http://host/",
		Deep:      true,
		Root:      resp(200, ct, nil, page),
		Control:   resp(200, ct, nil, page),
		PathInfo:  resp(200, ct, nil, page),
		Extra: map[string]*probe.Response{
			"http://host/phpmyadmin/":           resp(200, ct, nil, page),
			"http://host/qphpscanner_probe_404": resp(200, ct, nil, page),
		},
	}
	d := Analyze(in)
	if d == nil {
		t.Fatal("nil detection")
	}
	if hasEvidence(d, "diag.phpmyadmin") {
		t.Errorf("phpMyAdmin URL-only signal should be suppressed on a catch-all: %+v", d.Evidence)
	}
	if hasEvidence(d, "behavior.path-info") {
		t.Errorf("PATH_INFO signal should be suppressed on a catch-all: %+v", d.Evidence)
	}
	if d.Verdict == VerdictConfirmed {
		t.Errorf("a catch-all with no PHP evidence must not be confirmed (conf %d, verdict %s)", d.Confidence, d.Verdict)
	}
}

// Against a real 404 baseline the same signals are distinguishable and count.
func TestRealBaselineStillAwardsUrlSignals(t *testing.T) {
	ct := map[string]string{"Content-Type": "text/html"}
	in := Input{
		TargetURL: "http://host/",
		Deep:      true,
		Root:      resp(200, ct, nil, "<html>home</html>"),
		Control:   resp(404, ct, nil, "<html>404 - not found</html>"),
		PathInfo:  resp(200, ct, nil, "<html>path info served</html>"),
		Extra: map[string]*probe.Response{
			// Body has no phpMyAdmin markers, so only the URL arm can fire.
			"http://host/phpmyadmin/": resp(200, ct, nil, "<html>database manager</html>"),
		},
	}
	d := Analyze(in)
	if !hasEvidence(d, "diag.phpmyadmin") {
		t.Errorf("phpMyAdmin URL signal should fire against a real 404 baseline: %+v", d.Evidence)
	}
	if !hasEvidence(d, "behavior.path-info") {
		t.Errorf("PATH_INFO signal should fire against a real 404 baseline: %+v", d.Evidence)
	}
}
