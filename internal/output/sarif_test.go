package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/trustin-tech/vulnex/internal/model"
)

func parseSARIF(t *testing.T, data []byte) sarifLog {
	t.Helper()
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\n%s", err, data)
	}
	return log
}

func TestSARIFStructure(t *testing.T) {
	sf := newSARIFFormatter("1.0.0")
	var buf bytes.Buffer
	result := &model.SBOMResult{File: "bom.json", Findings: nil}

	if err := sf.FormatSBOMResult(&buf, result); err != nil {
		t.Fatal(err)
	}

	log := parseSARIF(t, buf.Bytes())

	if log.Schema != sarifSchema {
		t.Errorf("$schema = %q, want %q", log.Schema, sarifSchema)
	}
	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", log.Version, "2.1.0")
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs count = %d, want 1", len(log.Runs))
	}
	if log.Runs[0].Tool.Driver.Name != "vulnex" {
		t.Errorf("tool.driver.name = %q, want %q", log.Runs[0].Tool.Driver.Name, "vulnex")
	}
	if log.Runs[0].Tool.Driver.Version != "1.0.0" {
		t.Errorf("tool.driver.version = %q, want %q", log.Runs[0].Tool.Driver.Version, "1.0.0")
	}
}

func TestSARIFEmptyFindings(t *testing.T) {
	sf := newSARIFFormatter("dev")
	var buf bytes.Buffer
	result := &model.SBOMResult{File: "bom.json", Findings: nil}

	if err := sf.FormatSBOMResult(&buf, result); err != nil {
		t.Fatal(err)
	}

	log := parseSARIF(t, buf.Bytes())
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("results count = %d, want 0", len(log.Runs[0].Results))
	}
}

func TestSARIFRuleDeduplication(t *testing.T) {
	sf := newSARIFFormatter("1.0.0")
	var buf bytes.Buffer

	result := &model.SBOMResult{
		File: "bom.json",
		Findings: []model.SBOMFinding{
			{
				Ecosystem: "PyPI",
				Name:      "django",
				Version:   "3.2.0",
				Advisory:  model.Advisory{ID: "GHSA-aaaa", Severity: "CRITICAL", Summary: "SQL injection"},
			},
			{
				Ecosystem: "PyPI",
				Name:      "django",
				Version:   "3.1.0",
				Advisory:  model.Advisory{ID: "GHSA-aaaa", Severity: "CRITICAL", Summary: "SQL injection"},
			},
		},
	}

	if err := sf.FormatSBOMResult(&buf, result); err != nil {
		t.Fatal(err)
	}

	log := parseSARIF(t, buf.Bytes())

	if len(log.Runs[0].Tool.Driver.Rules) != 1 {
		t.Errorf("rules count = %d, want 1 (deduplication)", len(log.Runs[0].Tool.Driver.Rules))
	}
	if len(log.Runs[0].Results) != 2 {
		t.Errorf("results count = %d, want 2", len(log.Runs[0].Results))
	}
}

func TestSARIFSeverityMapping(t *testing.T) {
	tests := []struct {
		severity string
		level    string
		score    string
	}{
		{"CRITICAL", "error", "9.0"},
		{"HIGH", "error", "7.0"},
		{"MEDIUM", "warning", "4.0"},
		{"LOW", "note", "1.0"},
		{"UNKNOWN", "note", "1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			if got := severityToSARIFLevel(tt.severity); got != tt.level {
				t.Errorf("severityToSARIFLevel(%q) = %q, want %q", tt.severity, got, tt.level)
			}
			if got := severityToSecuritySeverity(tt.severity); got != tt.score {
				t.Errorf("severityToSecuritySeverity(%q) = %q, want %q", tt.severity, got, tt.score)
			}
		})
	}
}

func TestSARIFMessageWithFixVersion(t *testing.T) {
	sf := newSARIFFormatter("1.0.0")
	var buf bytes.Buffer

	result := &model.SBOMResult{
		File: "bom.json",
		Findings: []model.SBOMFinding{
			{
				Ecosystem: "PyPI",
				Name:      "django",
				Version:   "3.2.0",
				Fixed:     "3.2.5",
				Advisory:  model.Advisory{ID: "GHSA-aaaa", Severity: "HIGH", Summary: "XSS"},
			},
		},
	}

	if err := sf.FormatSBOMResult(&buf, result); err != nil {
		t.Fatal(err)
	}

	log := parseSARIF(t, buf.Bytes())
	msg := log.Runs[0].Results[0].Message.Text

	if expected := "[fixed in 3.2.5]"; !contains(msg, expected) {
		t.Errorf("message %q does not contain %q", msg, expected)
	}
}

func TestSARIFMessageWithoutFixVersion(t *testing.T) {
	sf := newSARIFFormatter("1.0.0")
	var buf bytes.Buffer

	result := &model.SBOMResult{
		File: "bom.json",
		Findings: []model.SBOMFinding{
			{
				Ecosystem: "npm",
				Name:      "lodash",
				Version:   "4.17.20",
				Advisory:  model.Advisory{ID: "GHSA-bbbb", Severity: "HIGH", Summary: "Prototype pollution"},
			},
		},
	}

	if err := sf.FormatSBOMResult(&buf, result); err != nil {
		t.Fatal(err)
	}

	log := parseSARIF(t, buf.Bytes())
	msg := log.Runs[0].Results[0].Message.Text

	if contains(msg, "[fixed in") {
		t.Errorf("message %q should not contain fix version", msg)
	}
	if !contains(msg, "lodash@4.17.20") {
		t.Errorf("message %q should contain component info", msg)
	}
}

func TestSARIFLocationFields(t *testing.T) {
	sf := newSARIFFormatter("1.0.0")
	var buf bytes.Buffer

	result := &model.SBOMResult{
		File: "path/to/bom.json",
		Findings: []model.SBOMFinding{
			{
				Ecosystem: "PyPI",
				Name:      "django",
				Version:   "3.2.0",
				Advisory:  model.Advisory{ID: "GHSA-cccc", Severity: "CRITICAL", Summary: "Test"},
			},
		},
	}

	if err := sf.FormatSBOMResult(&buf, result); err != nil {
		t.Fatal(err)
	}

	log := parseSARIF(t, buf.Bytes())
	loc := log.Runs[0].Results[0].Locations[0]

	if loc.PhysicalLocation.ArtifactLocation.URI != "path/to/bom.json" {
		t.Errorf("physical location URI = %q, want %q", loc.PhysicalLocation.ArtifactLocation.URI, "path/to/bom.json")
	}
	if loc.LogicalLocations[0].Name != "django" {
		t.Errorf("logical location name = %q, want %q", loc.LogicalLocations[0].Name, "django")
	}
	if loc.LogicalLocations[0].FullyQualifiedName != "PyPI/django@3.2.0" {
		t.Errorf("logical location fqn = %q, want %q", loc.LogicalLocations[0].FullyQualifiedName, "PyPI/django@3.2.0")
	}
	if loc.LogicalLocations[0].Kind != "module" {
		t.Errorf("logical location kind = %q, want %q", loc.LogicalLocations[0].Kind, "module")
	}
}

func TestSARIFSBOMDiffOnlyAdded(t *testing.T) {
	sf := newSARIFFormatter("1.0.0")
	var buf bytes.Buffer

	diff := &model.SBOMDiffResult{
		NewFile: "new-bom.json",
		Added: []model.SBOMFinding{
			{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Advisory: model.Advisory{ID: "GHSA-added", Severity: "HIGH", Summary: "Added"}},
		},
		Removed: []model.SBOMFinding{
			{Ecosystem: "npm", Name: "underscore", Version: "1.0.0", Advisory: model.Advisory{ID: "GHSA-removed", Severity: "LOW", Summary: "Removed"}},
		},
		Unchanged: []model.SBOMFinding{
			{Ecosystem: "npm", Name: "express", Version: "4.0.0", Advisory: model.Advisory{ID: "GHSA-unchanged", Severity: "MEDIUM", Summary: "Unchanged"}},
		},
	}

	if err := sf.FormatSBOMDiffResult(&buf, diff); err != nil {
		t.Fatal(err)
	}

	log := parseSARIF(t, buf.Bytes())

	if len(log.Runs[0].Results) != 1 {
		t.Fatalf("results count = %d, want 1 (only added)", len(log.Runs[0].Results))
	}
	if log.Runs[0].Results[0].RuleID != "GHSA-added" {
		t.Errorf("result ruleId = %q, want %q", log.Runs[0].Results[0].RuleID, "GHSA-added")
	}
}

func TestSARIFCVESecuritySeverityFromCVSS(t *testing.T) {
	sf := newSARIFFormatter("1.0.0")
	var buf bytes.Buffer

	cve := &model.EnrichedCVE{
		ID:           "CVE-2021-44228",
		Descriptions: []model.LangString{{Lang: "en", Value: "Log4Shell"}},
		CVSS:         []model.CVSSScore{{Version: "3.1", BaseScore: 10.0, Severity: "CRITICAL"}},
	}

	if err := sf.FormatCVE(&buf, cve); err != nil {
		t.Fatal(err)
	}

	log := parseSARIF(t, buf.Bytes())
	secSev := log.Runs[0].Tool.Driver.Rules[0].Properties.SecuritySeverity

	if secSev != "10.0" {
		t.Errorf("security-severity = %q, want %q (from CVSS base score)", secSev, "10.0")
	}
}

func TestSARIFExploitAlwaysError(t *testing.T) {
	sf := newSARIFFormatter("1.0.0")
	var buf bytes.Buffer

	result := &model.ExploitResult{
		CVEID:      "CVE-2021-44228",
		HasExploit: true,
		Exploits: []model.ExploitRef{
			{Source: "github", Name: "log4j-shell-poc", URL: "https://github.com/example/poc"},
		},
	}

	if err := sf.FormatExploitResult(&buf, result); err != nil {
		t.Fatal(err)
	}

	log := parseSARIF(t, buf.Bytes())
	if log.Runs[0].Results[0].Level != "error" {
		t.Errorf("exploit level = %q, want %q", log.Runs[0].Results[0].Level, "error")
	}
}

func TestSARIFFallbackMethodsProduceJSON(t *testing.T) {
	sf := newSARIFFormatter("1.0.0")

	t.Run("KEVList", func(t *testing.T) {
		var buf bytes.Buffer
		if err := sf.FormatKEVList(&buf, []model.KEVEntry{}); err != nil {
			t.Fatal(err)
		}
		// Should be a JSON array, not SARIF
		var arr []interface{}
		if err := json.Unmarshal(buf.Bytes(), &arr); err != nil {
			t.Errorf("KEVList fallback is not valid JSON array: %v", err)
		}
	})

	t.Run("EPSSScores", func(t *testing.T) {
		var buf bytes.Buffer
		if err := sf.FormatEPSSScores(&buf, map[string]*model.EPSSScore{}); err != nil {
			t.Fatal(err)
		}
		var obj map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &obj); err != nil {
			t.Errorf("EPSSScores fallback is not valid JSON object: %v", err)
		}
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && bytes.Contains([]byte(s), []byte(substr))
}
