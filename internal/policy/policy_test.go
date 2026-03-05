package policy

import (
	"os"
	"testing"

	"github.com/trustin-tech/vulnex/internal/model"
)

func boolPtr(b bool) *bool       { return &b }
func float64Ptr(f float64) *float64 { return &f }

func TestLoad(t *testing.T) {
	p, err := Load("../../testdata/policy-sample.yaml")
	if err != nil {
		t.Fatal(err)
	}

	if p.Version != 1 {
		t.Errorf("expected version 1, got %d", p.Version)
	}
	if len(p.Rules) != 5 {
		t.Errorf("expected 5 rules, got %d", len(p.Rules))
	}
	if p.Rules[0].Name != "block-kev" {
		t.Errorf("expected first rule name block-kev, got %s", p.Rules[0].Name)
	}
	if p.Rules[0].Action != "fail" {
		t.Errorf("expected first rule action fail, got %s", p.Rules[0].Action)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("nonexistent.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoad_MissingVersion(t *testing.T) {
	// Create a temp file without version
	tmpFile := t.TempDir() + "/bad-policy.yaml"
	if err := writeTestFile(tmpFile, "rules: []\n"); err != nil {
		t.Fatal(err)
	}
	_, err := Load(tmpFile)
	if err == nil {
		t.Error("expected error for missing version")
	}
}

func TestEvaluate_KEV(t *testing.T) {
	p := &Policy{
		Version: 1,
		Rules: []Rule{
			{Name: "block-kev", Match: Condition{KEV: boolPtr(true)}, Action: "fail"},
		},
	}

	// Finding with KEV
	f := model.SBOMFinding{
		KEV: &model.KEVEntry{CVEID: "CVE-2021-44228"},
	}
	action, name := p.Evaluate(f)
	if action != "fail" || name != "block-kev" {
		t.Errorf("expected fail/block-kev, got %s/%s", action, name)
	}

	// Finding without KEV
	f2 := model.SBOMFinding{}
	action, name = p.Evaluate(f2)
	if action != "" || name != "" {
		t.Errorf("expected no match, got %s/%s", action, name)
	}
}

func TestEvaluate_Severity(t *testing.T) {
	p := &Policy{
		Version: 1,
		Rules: []Rule{
			{Name: "block-critical", Match: Condition{Severity: []string{"CRITICAL"}}, Action: "fail"},
		},
	}

	f := model.SBOMFinding{Advisory: model.Advisory{Severity: "critical"}}
	action, _ := p.Evaluate(f)
	if action != "fail" {
		t.Errorf("expected fail, got %s", action)
	}

	f2 := model.SBOMFinding{Advisory: model.Advisory{Severity: "HIGH"}}
	action, _ = p.Evaluate(f2)
	if action != "" {
		t.Errorf("expected no match for HIGH, got %s", action)
	}
}

func TestEvaluate_EPSSGte(t *testing.T) {
	p := &Policy{
		Version: 1,
		Rules: []Rule{
			{Name: "high-epss", Match: Condition{EPSSGte: float64Ptr(0.7)}, Action: "fail"},
		},
	}

	f := model.SBOMFinding{EPSS: &model.EPSSScore{Score: 0.85}}
	action, _ := p.Evaluate(f)
	if action != "fail" {
		t.Errorf("expected fail for EPSS 0.85, got %s", action)
	}

	f2 := model.SBOMFinding{EPSS: &model.EPSSScore{Score: 0.5}}
	action, _ = p.Evaluate(f2)
	if action != "" {
		t.Errorf("expected no match for EPSS 0.5, got %s", action)
	}

	// nil EPSS should not match
	f3 := model.SBOMFinding{}
	action, _ = p.Evaluate(f3)
	if action != "" {
		t.Errorf("expected no match for nil EPSS, got %s", action)
	}
}

func TestEvaluate_CVSSGte(t *testing.T) {
	p := &Policy{
		Version: 1,
		Rules: []Rule{
			{Name: "high-cvss", Match: Condition{CVSSGte: float64Ptr(9.0)}, Action: "fail"},
		},
	}

	f := model.SBOMFinding{CVSSScore: 9.8}
	action, _ := p.Evaluate(f)
	if action != "fail" {
		t.Errorf("expected fail for CVSS 9.8, got %s", action)
	}

	f2 := model.SBOMFinding{CVSSScore: 7.5}
	action, _ = p.Evaluate(f2)
	if action != "" {
		t.Errorf("expected no match for CVSS 7.5, got %s", action)
	}
}

func TestEvaluate_HasExploit(t *testing.T) {
	p := &Policy{
		Version: 1,
		Rules: []Rule{
			{Name: "exploitable", Match: Condition{HasExploit: boolPtr(true)}, Action: "warn"},
		},
	}

	f := model.SBOMFinding{HasExploit: true}
	action, _ := p.Evaluate(f)
	if action != "warn" {
		t.Errorf("expected warn, got %s", action)
	}

	f2 := model.SBOMFinding{HasExploit: false}
	action, _ = p.Evaluate(f2)
	if action != "" {
		t.Errorf("expected no match, got %s", action)
	}
}

func TestEvaluate_Priority(t *testing.T) {
	p := &Policy{
		Version: 1,
		Rules: []Rule{
			{Name: "block-p0", Match: Condition{Priority: []string{"P0-CRITICAL"}}, Action: "fail"},
		},
	}

	f := model.SBOMFinding{Risk: &model.RiskScore{Priority: model.PriorityCritical}}
	action, _ := p.Evaluate(f)
	if action != "fail" {
		t.Errorf("expected fail, got %s", action)
	}

	f2 := model.SBOMFinding{Risk: &model.RiskScore{Priority: model.PriorityHigh}}
	action, _ = p.Evaluate(f2)
	if action != "" {
		t.Errorf("expected no match, got %s", action)
	}
}

func TestEvaluate_Ecosystem(t *testing.T) {
	p := &Policy{
		Version: 1,
		Rules: []Rule{
			{Name: "block-npm", Match: Condition{Ecosystem: []string{"npm"}}, Action: "fail"},
		},
	}

	f := model.SBOMFinding{Ecosystem: "npm"}
	action, _ := p.Evaluate(f)
	if action != "fail" {
		t.Errorf("expected fail, got %s", action)
	}

	f2 := model.SBOMFinding{Ecosystem: "Go"}
	action, _ = p.Evaluate(f2)
	if action != "" {
		t.Errorf("expected no match, got %s", action)
	}
}

func TestEvaluate_AND(t *testing.T) {
	// All conditions must match
	p := &Policy{
		Version: 1,
		Rules: []Rule{
			{
				Name: "critical-and-kev",
				Match: Condition{
					KEV:      boolPtr(true),
					Severity: []string{"CRITICAL"},
				},
				Action: "fail",
			},
		},
	}

	// Both match
	f := model.SBOMFinding{
		Advisory: model.Advisory{Severity: "CRITICAL"},
		KEV:      &model.KEVEntry{CVEID: "CVE-2021-44228"},
	}
	action, _ := p.Evaluate(f)
	if action != "fail" {
		t.Errorf("expected fail when both match, got %s", action)
	}

	// Only severity matches
	f2 := model.SBOMFinding{
		Advisory: model.Advisory{Severity: "CRITICAL"},
	}
	action, _ = p.Evaluate(f2)
	if action != "" {
		t.Errorf("expected no match when only severity matches, got %s", action)
	}

	// Only KEV matches
	f3 := model.SBOMFinding{
		Advisory: model.Advisory{Severity: "LOW"},
		KEV:      &model.KEVEntry{CVEID: "CVE-2021-44228"},
	}
	action, _ = p.Evaluate(f3)
	if action != "" {
		t.Errorf("expected no match when only KEV matches, got %s", action)
	}
}

func TestEvaluateAll(t *testing.T) {
	p := &Policy{
		Version: 1,
		Rules: []Rule{
			{Name: "block-kev", Match: Condition{KEV: boolPtr(true)}, Action: "fail"},
			{Name: "warn-high", Match: Condition{Severity: []string{"HIGH"}}, Action: "warn"},
		},
	}

	findings := []model.SBOMFinding{
		{KEV: &model.KEVEntry{CVEID: "CVE-2021-44228"}, Advisory: model.Advisory{Severity: "CRITICAL"}},
		{Advisory: model.Advisory{Severity: "HIGH"}},
		{Advisory: model.Advisory{Severity: "LOW"}},
	}

	result := p.EvaluateAll(findings)
	if result.Passed {
		t.Error("expected result to not pass")
	}
	if len(result.Failures) != 1 {
		t.Errorf("expected 1 failure, got %d", len(result.Failures))
	}
	if len(result.Warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(result.Warnings))
	}
}

func TestEvaluateAll_AllPass(t *testing.T) {
	p := &Policy{
		Version: 1,
		Rules: []Rule{
			{Name: "block-kev", Match: Condition{KEV: boolPtr(true)}, Action: "fail"},
		},
	}

	findings := []model.SBOMFinding{
		{Advisory: model.Advisory{Severity: "LOW"}},
	}

	result := p.EvaluateAll(findings)
	if !result.Passed {
		t.Error("expected result to pass")
	}
	if len(result.Failures) != 0 {
		t.Errorf("expected 0 failures, got %d", len(result.Failures))
	}
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
