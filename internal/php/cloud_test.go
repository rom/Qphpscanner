package php

import (
	"testing"

	"github.com/rom/qphpscanner/internal/probe"
)

func TestNextcloudStatusDetection(t *testing.T) {
	status := `{"installed":true,"maintenance":false,"version":"28.0.1.1","versionstring":"28.0.1","edition":"","productname":"Nextcloud"}`
	in := Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      resp(200, nil, nil, "<html></html>"),
		Extra:     map[string]*probe.Response{"http://h/status.php": resp(200, nil, nil, status)},
	}
	d := Analyze(in)
	if !hasStr(d.Frameworks, "Nextcloud") {
		t.Fatalf("Nextcloud not detected: %v", d.Frameworks)
	}
	if d.FrameworkVersions["Nextcloud"] != "28.0.1" {
		t.Errorf("Nextcloud version = %q, want 28.0.1", d.FrameworkVersions["Nextcloud"])
	}
	if !d.IsPHP {
		t.Errorf("Nextcloud status.php should classify as PHP (conf %d)", d.Confidence)
	}
}

func TestOwnCloudCookieDetection(t *testing.T) {
	d := Analyze(Input{
		TargetURL: "http://h/",
		Root:      resp(200, nil, []string{"oc_token"}, "<html></html>"),
	})
	if !hasStr(d.Frameworks, "ownCloud/Nextcloud") {
		t.Errorf("ownCloud cookie not detected: %v", d.Frameworks)
	}
	if !d.IsPHP {
		t.Errorf("ownCloud session cookie should classify as PHP (conf %d)", d.Confidence)
	}
}

func TestOpenCloudDetectedButNotPHP(t *testing.T) {
	// oCIS / Infinite Scale is a Go rewrite: detect the product, do not call it PHP.
	status := `{"installed":true,"version":"5.0.0.0","versionstring":"5.0.0","productname":"ownCloud Infinite Scale"}`
	in := Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      resp(200, map[string]string{"X-Ocis-Version": "5.0.0"}, nil, "<html>OpenCloud Infinite Scale</html>"),
		Extra:     map[string]*probe.Response{"http://h/status.php": resp(200, nil, nil, status)},
	}
	d := Analyze(in)
	if !hasStr(d.Frameworks, "ownCloud Infinite Scale") && !hasStr(d.Frameworks, "OpenCloud/oCIS") {
		t.Fatalf("OpenCloud/oCIS not detected: %v", d.Frameworks)
	}
	if d.IsPHP {
		t.Errorf("OpenCloud (Go) must not be classified as PHP (conf %d, evidence %+v)", d.Confidence, d.Evidence)
	}
}

func TestPHPImpliedGatingNonPHPServer(t *testing.T) {
	// A cPanel (cpsrvd) server marker is phpImplied=false: it should be noted
	// but contribute nothing to the PHP confidence score.
	d := Analyze(Input{
		TargetURL: "http://h/",
		Root:      resp(200, map[string]string{"Server": "cpsrvd"}, nil, "<html></html>"),
	})
	if d.Confidence != 0 {
		t.Errorf("non-PHP server marker boosted PHP confidence to %d", d.Confidence)
	}
	if d.IsPHP {
		t.Error("cPanel-only response should not be classified as PHP")
	}
}
