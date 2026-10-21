package report

import (
	"bytes"
	"testing"
)

func TestLoadScanAnyJSONAndXML(t *testing.T) {
	res := richResult()

	for _, format := range []string{"json", "xml"} {
		var b bytes.Buffer
		if err := WriteOutput(&b, res, format); err != nil {
			t.Fatalf("WriteOutput %s: %v", format, err)
		}
		loaded, err := LoadScanAny(b.Bytes())
		if err != nil {
			t.Fatalf("LoadScanAny %s: %v", format, err)
		}
		// Diffing a scan against its own reloaded copy yields no changes.
		if d := Diff(res, loaded); !d.Empty() {
			t.Errorf("%s: self-diff not empty: %+v", format, d)
		}
		// The fields the diff relies on must survive the round-trip.
		svc := loaded.Targets[0].Services[0]
		if svc.URL != "https://h/" || svc.PHP == nil || string(svc.PHP.Verdict) != "confirmed" {
			t.Errorf("%s: service not reloaded: %+v", format, svc)
		}
		if svc.PHP.Version != "7.4.3" || len(svc.PHP.Vulnerabilities) != 2 {
			t.Errorf("%s: PHP detail lost: %+v", format, svc.PHP)
		}
	}

	if _, err := LoadScanAny([]byte("   ")); err == nil {
		t.Error("empty input should error")
	}
	if _, err := LoadScanAny([]byte("<not valid xml")); err == nil {
		t.Error("broken XML should error")
	}
}
