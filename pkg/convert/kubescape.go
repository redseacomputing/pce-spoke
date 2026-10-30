package convert

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	oscalTypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-2"

	"github.com/redseacomputing/pce/pkg/parser"
)

// kubescapeIDToControlID mappt Kubescape-IDs auf die Control-IDs des PCE-Katalogs.
// M1: nur die fuer Art.21(2)h relevanten; waechst mit der Mapping-Matrix.
var kubescapeIDToControlID = map[string]string{
	"C-0035": "SC-8", // HostPath mount -> Verschluesselungsthema (lit. h)
}

type kubescapeReport struct {
	Results []struct {
		Test struct {
			Status    string `json:"status"`
			ControlID string `json:"controlID"`
		} `json:"test"`
		Resources []struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
			Kind      string `json:"kind"`
		} `json:"resources"`
	} `json:"results"`
}

// ConvertKubescapeToOSCAL wandelt eine Kubescape-JSON-Ausgabe in ein
// OSCAL 1.1.2 Assessment Results Dokument um, das der Hub-Parser
// (pkg/parser.ParseAssessmentResults) konsumieren kann.
//
// WICHTIG: OSCAL spricht "satisfied"/"not-satisfied" - NICHT die
// Engine-internen "satisfied"/"unsatisfied".
func ConvertKubescapeToOSCAL(raw []byte) ([]byte, error) {
	var report kubescapeReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("parse kubescape report: %w", err)
	}

	findings := []oscalTypes.Finding{}
	for _, res := range report.Results {
		controlID, ok := kubescapeIDToControlID[res.Test.ControlID]
		if !ok {
			continue // nicht im Crosswalk -> fuer Hub irrelevant, ueberspringen
		}
		state := "satisfied"
		if res.Test.Status == "failed" {
			state = "not-satisfied"
		}
		for _, r := range res.Resources {
			findings = append(findings, oscalTypes.Finding{
				UUID: uuid.NewString(),
				Target: oscalTypes.FindingTarget{
					TargetId: controlID,
					Status:   oscalTypes.ObjectiveStatus{State: state},
				},
				Description: fmt.Sprintf("kubescape %s: %s %s/%s",
					res.Test.ControlID, r.Kind, r.Namespace, r.Name),
			})
		}
	}

	result := oscalTypes.Result{
		UUID:        uuid.NewString(),
		Title:       "Kubescape Spoke Scan",
		Description: "Converted from kubescape report by pce-spoke agent",
		Findings:    &findings,
	}
	wrapper := parser.OSCALAssessmentResultsWrapper{
		AssessmentResults: oscalTypes.AssessmentResults{
			UUID: uuid.NewString(),
			Metadata: oscalTypes.Metadata{
				Title:        "Kubescape Spoke Scan Result",
				Version:      "1.0",
				OscalVersion: "1.1.2",
			},
			Results: []oscalTypes.Result{result},
		},
	}
	out, err := json.Marshal(wrapper)
	if err != nil {
		return nil, fmt.Errorf("marshal oscal: %w", err)
	}
	return out, nil
}
