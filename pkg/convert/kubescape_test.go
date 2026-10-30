package convert

import (
	"bytes"
	"testing"

	"github.com/redseacomputing/pce/pkg/parser"
)

// Kubescape-Rohausgabe, minimal aber realistisch:
// C-0035 (HostPath mount) = failed, betroffene Ressource default/pod-with-hostpath.
const kubescapeSample = `{
  "results": [
    {
      "test": {
        "status": "failed",
        "controlID": "C-0035"
      },
      "resources": [
        {"namespace": "default", "name": "pod-with-hostpath", "kind": "Pod"}
      ]
    }
  ]
}`

func TestKubescapeOutputToOSCAL(t *testing.T) {
	oscalJSON, err := ConvertKubescapeToOSCAL([]byte(kubescapeSample))
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}

	// Ebene 1: Ergebnis ist valides OSCAL 1.1.2, geparst mit dem
	// SELBSTEN Hub-Parser (Vertragsnaht Spoke<->Hub).
	results, err := parser.ParseAssessmentResults(bytes.NewReader(oscalJSON))
	if err != nil {
		t.Fatalf("converted OSCAL rejected by hub parser: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	// Ebene 2: Mapping-Vertrag - Kubescape C-0035 muss als SC-8-Finding
	// mit Status "not-satisfied" landen.
	findings := *results[0].Findings
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Target.TargetId != "SC-8" {
		t.Errorf("expected target-id 'SC-8', got %q", f.Target.TargetId)
	}
	if f.Target.Status.State != "not-satisfied" {
		t.Errorf("expected state 'not-satisfied', got %q", f.Target.Status.State)
	}
}

func TestKubescapeUnknownControlSkipped(t *testing.T) {
	// Nicht gemappte Kubescape-IDs werden uebersprungen (nicht im Crosswalk).
	raw := `{"results":[{"test":{"status":"failed","controlID":"C-9999"},"resources":[{"namespace":"x","name":"y","kind":"Pod"}]}]}`
	oscalJSON, err := ConvertKubescapeToOSCAL([]byte(raw))
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}
	results, err := parser.ParseAssessmentResults(bytes.NewReader(oscalJSON))
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(*results[0].Findings) != 0 {
		t.Errorf("expected 0 findings for unmapped control, got %d", len(*results[0].Findings))
	}
}

func TestKubescapeSatisfiedControl(t *testing.T) {
	// Bestandene Pruefungen muessen als "satisfied" durchschlagen.
	raw := `{"results":[{"test":{"status":"passed","controlID":"C-0035"},"resources":[{"namespace":"default","name":"ok-pod","kind":"Pod"}]}]}`
	oscalJSON, err := ConvertKubescapeToOSCAL([]byte(raw))
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}
	results, err := parser.ParseAssessmentResults(bytes.NewReader(oscalJSON))
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	findings := *results[0].Findings
	if len(findings) != 1 || findings[0].Target.Status.State != "satisfied" {
		t.Fatalf("expected 1 satisfied finding, got %+v", findings)
	}
}
