package php

import "testing"

func TestCoreAndConditionalProbesPartition(t *testing.T) {
	core := CoreProbePaths()
	if len(core) == 0 {
		t.Fatal("core probe set is empty")
	}
	coreSet := map[string]bool{}
	for _, p := range core {
		if coreSet[p] {
			t.Errorf("duplicate core probe %q", p)
		}
		coreSet[p] = true
	}
	// Core probes are generic; no app-specific path should appear in the core
	// set, and every conditional path must be distinct from the core set.
	cond := ConditionalProbes()
	if len(cond) == 0 {
		t.Fatal("conditional probe set is empty")
	}
	seenTrigger := map[string]bool{}
	for _, ap := range cond {
		if ap.Trigger == "" {
			t.Error("conditional probe set has an empty trigger")
		}
		if seenTrigger[ap.Trigger] {
			t.Errorf("duplicate trigger %q", ap.Trigger)
		}
		seenTrigger[ap.Trigger] = true
		if len(ap.Paths) == 0 {
			t.Errorf("trigger %q has no paths", ap.Trigger)
		}
		for _, p := range ap.Paths {
			if coreSet[p] {
				t.Errorf("conditional path %q (trigger %q) also in core set", p, ap.Trigger)
			}
		}
	}

	// The WordPress trigger must gate the classic WordPress endpoints.
	var wp []string
	for _, ap := range cond {
		if ap.Trigger == "WordPress" {
			wp = ap.Paths
		}
	}
	if !hasStr(wp, "/wp-login.php") || !hasStr(wp, "/xmlrpc.php") {
		t.Fatalf("WordPress trigger missing expected paths: %v", wp)
	}
}

func TestDeepProbePathsIsUnion(t *testing.T) {
	deep := DeepProbePaths()
	if deep[0] != "/" {
		t.Fatalf("DeepProbePaths should start with root, got %q", deep[0])
	}
	seen := map[string]bool{}
	for _, p := range deep {
		if seen[p] {
			t.Errorf("DeepProbePaths has duplicate %q", p)
		}
		seen[p] = true
	}
	// Every core and conditional path must be reachable through DeepProbePaths.
	for _, p := range CoreProbePaths() {
		if !seen[p] {
			t.Errorf("core path %q missing from DeepProbePaths union", p)
		}
	}
	for _, ap := range ConditionalProbes() {
		for _, p := range ap.Paths {
			if !seen[p] {
				t.Errorf("conditional path %q missing from DeepProbePaths union", p)
			}
		}
	}
	if ControlProbePath == "" {
		t.Fatal("ControlProbePath must not be empty")
	}
	if seen[ControlProbePath] {
		t.Fatalf("control path %q must not collide with a real probe", ControlProbePath)
	}
}
