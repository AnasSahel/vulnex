package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/trustin-tech/vulnex/internal/cache"
	"github.com/trustin-tech/vulnex/internal/model"
)

// SARIF v2.1.0 structs

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool      `json:"tool"`
	Results []sarifResult  `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	HelpURI          string              `json:"helpUri,omitempty"`
	Properties       sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID   string          `json:"ruleId"`
	Level    string          `json:"level"`
	Message  sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
const sarifVersion = "2.1.0"

// sarifFormatter implements the Formatter interface for SARIF v2.1.0 output.
type sarifFormatter struct {
	version      string
	jsonFallback *jsonFormatter
}

func newSARIFFormatter(version string) *sarifFormatter {
	return &sarifFormatter{
		version:      version,
		jsonFallback: newJSONFormatter(&formatterOpts{}),
	}
}

func (sf *sarifFormatter) newLog(rules []sarifRule, results []sarifResult) sarifLog {
	return sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "vulnex",
					Version:        sf.version,
					InformationURI: "https://github.com/AnasSahel/vulnex",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}
}

func (sf *sarifFormatter) writeSARIF(w io.Writer, log sarifLog) error {
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling SARIF: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// severityToSARIFLevel maps vulnerability severity to SARIF level.
func severityToSARIFLevel(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW", "UNKNOWN", "NONE":
		return "note"
	default:
		return "note"
	}
}

// severityToSecuritySeverity maps severity to GitHub Code Scanning security-severity score.
func severityToSecuritySeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "9.0"
	case "HIGH":
		return "7.0"
	case "MEDIUM":
		return "4.0"
	case "LOW":
		return "1.0"
	default:
		return "1.0"
	}
}

// FormatSBOMResult converts SBOM findings to SARIF format.
func (sf *sarifFormatter) FormatSBOMResult(w io.Writer, result *model.SBOMResult) error {
	ruleMap := map[string]sarifRule{}
	var results []sarifResult

	for _, f := range result.Findings {
		ruleID := f.Advisory.ID

		if _, exists := ruleMap[ruleID]; !exists {
			ruleMap[ruleID] = sarifRule{
				ID:               ruleID,
				ShortDescription: sarifMessage{Text: f.Advisory.Summary},
				HelpURI:          f.Advisory.URL,
				Properties: sarifRuleProperties{
					SecuritySeverity: severityToSecuritySeverity(f.Advisory.Severity),
					Tags:             []string{"security", "vulnerability"},
				},
			}
		}

		msg := fmt.Sprintf("Vulnerable dependency: %s@%s (%s) — %s", f.Name, f.Version, f.Ecosystem, f.Advisory.Summary)
		if f.Fixed != "" {
			msg = fmt.Sprintf("Vulnerable dependency: %s@%s (%s) — %s [fixed in %s]", f.Name, f.Version, f.Ecosystem, f.Advisory.Summary, f.Fixed)
		}

		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   severityToSARIFLevel(f.Advisory.Severity),
			Message: sarifMessage{Text: msg},
			Locations: []sarifLocation{{
				PhysicalLocation: &sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: result.File},
				},
				LogicalLocations: []sarifLogicalLocation{{
					Name:               f.Name,
					FullyQualifiedName: fmt.Sprintf("%s/%s@%s", f.Ecosystem, f.Name, f.Version),
					Kind:               "module",
				}},
			}},
		})
	}

	rules := make([]sarifRule, 0, len(ruleMap))
	for _, r := range ruleMap {
		rules = append(rules, r)
	}

	return sf.writeSARIF(w, sf.newLog(rules, results))
}

// FormatSBOMDiffResult converts SBOM diff results to SARIF — only added findings.
func (sf *sarifFormatter) FormatSBOMDiffResult(w io.Writer, result *model.SBOMDiffResult) error {
	sbomResult := &model.SBOMResult{
		File:     result.NewFile,
		Findings: result.Added,
	}
	return sf.FormatSBOMResult(w, sbomResult)
}

// FormatCVE converts a single CVE to SARIF format.
func (sf *sarifFormatter) FormatCVE(w io.Writer, cve *model.EnrichedCVE) error {
	secSeverity := severityToSecuritySeverity(cve.Severity())
	if s := cve.HighestScore(); s != nil {
		secSeverity = fmt.Sprintf("%.1f", s.BaseScore)
	}

	rule := sarifRule{
		ID:               cve.ID,
		ShortDescription: sarifMessage{Text: cve.Description()},
		Properties: sarifRuleProperties{
			SecuritySeverity: secSeverity,
			Tags:             []string{"security", "vulnerability"},
		},
	}

	result := sarifResult{
		RuleID:  cve.ID,
		Level:   severityToSARIFLevel(cve.Severity()),
		Message: sarifMessage{Text: cve.Description()},
	}

	return sf.writeSARIF(w, sf.newLog([]sarifRule{rule}, []sarifResult{result}))
}

// FormatCVEList converts a list of CVEs to SARIF format.
func (sf *sarifFormatter) FormatCVEList(w io.Writer, cves []*model.EnrichedCVE) error {
	var rules []sarifRule
	var results []sarifResult

	for _, cve := range cves {
		secSeverity := severityToSecuritySeverity(cve.Severity())
		if s := cve.HighestScore(); s != nil {
			secSeverity = fmt.Sprintf("%.1f", s.BaseScore)
		}

		rules = append(rules, sarifRule{
			ID:               cve.ID,
			ShortDescription: sarifMessage{Text: cve.Description()},
			Properties: sarifRuleProperties{
				SecuritySeverity: secSeverity,
				Tags:             []string{"security", "vulnerability"},
			},
		})

		results = append(results, sarifResult{
			RuleID:  cve.ID,
			Level:   severityToSARIFLevel(cve.Severity()),
			Message: sarifMessage{Text: cve.Description()},
		})
	}

	return sf.writeSARIF(w, sf.newLog(rules, results))
}

// FormatAdvisory converts a single advisory to SARIF format.
func (sf *sarifFormatter) FormatAdvisory(w io.Writer, advisory *model.EnrichedAdvisory) error {
	secSeverity := severityToSecuritySeverity(advisory.Severity)
	if advisory.CVSSScore > 0 {
		secSeverity = fmt.Sprintf("%.1f", advisory.CVSSScore)
	}

	rule := sarifRule{
		ID:               advisory.ID,
		ShortDescription: sarifMessage{Text: advisory.Summary},
		HelpURI:          advisory.URL,
		Properties: sarifRuleProperties{
			SecuritySeverity: secSeverity,
			Tags:             []string{"security", "vulnerability"},
		},
	}

	result := sarifResult{
		RuleID:  advisory.ID,
		Level:   severityToSARIFLevel(advisory.Severity),
		Message: sarifMessage{Text: advisory.Summary},
	}

	return sf.writeSARIF(w, sf.newLog([]sarifRule{rule}, []sarifResult{result}))
}

// FormatAdvisories converts a list of advisories to SARIF format.
func (sf *sarifFormatter) FormatAdvisories(w io.Writer, advisories []model.Advisory) error {
	var rules []sarifRule
	var results []sarifResult

	for _, a := range advisories {
		rules = append(rules, sarifRule{
			ID:               a.ID,
			ShortDescription: sarifMessage{Text: a.Summary},
			HelpURI:          a.URL,
			Properties: sarifRuleProperties{
				SecuritySeverity: severityToSecuritySeverity(a.Severity),
				Tags:             []string{"security", "vulnerability"},
			},
		})

		results = append(results, sarifResult{
			RuleID:  a.ID,
			Level:   severityToSARIFLevel(a.Severity),
			Message: sarifMessage{Text: a.Summary},
		})
	}

	return sf.writeSARIF(w, sf.newLog(rules, results))
}

// FormatExploitResult converts a single exploit result to SARIF format.
func (sf *sarifFormatter) FormatExploitResult(w io.Writer, result *model.ExploitResult) error {
	var rules []sarifRule
	var results []sarifResult

	ruleMap := map[string]bool{}

	for _, ex := range result.Exploits {
		ruleID := result.CVEID
		if !ruleMap[ruleID] {
			rules = append(rules, sarifRule{
				ID:               ruleID,
				ShortDescription: sarifMessage{Text: fmt.Sprintf("Known exploit for %s", ruleID)},
				Properties: sarifRuleProperties{
					SecuritySeverity: "9.0",
					Tags:             []string{"security", "exploit"},
				},
			})
			ruleMap[ruleID] = true
		}

		msg := fmt.Sprintf("Exploit: %s (%s)", ex.Name, ex.Source)
		if ex.URL != "" {
			msg = fmt.Sprintf("Exploit: %s (%s) — %s", ex.Name, ex.Source, ex.URL)
		}

		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   "error",
			Message: sarifMessage{Text: msg},
		})
	}

	return sf.writeSARIF(w, sf.newLog(rules, results))
}

// FormatExploitResults converts multiple exploit results to SARIF format.
func (sf *sarifFormatter) FormatExploitResults(w io.Writer, exploitResults []*model.ExploitResult) error {
	var rules []sarifRule
	var results []sarifResult

	ruleMap := map[string]bool{}

	for _, er := range exploitResults {
		for _, ex := range er.Exploits {
			ruleID := er.CVEID
			if !ruleMap[ruleID] {
				rules = append(rules, sarifRule{
					ID:               ruleID,
					ShortDescription: sarifMessage{Text: fmt.Sprintf("Known exploit for %s", ruleID)},
					Properties: sarifRuleProperties{
						SecuritySeverity: "9.0",
						Tags:             []string{"security", "exploit"},
					},
				})
				ruleMap[ruleID] = true
			}

			msg := fmt.Sprintf("Exploit: %s (%s)", ex.Name, ex.Source)
			if ex.URL != "" {
				msg = fmt.Sprintf("Exploit: %s (%s) — %s", ex.Name, ex.Source, ex.URL)
			}

			results = append(results, sarifResult{
				RuleID:  ruleID,
				Level:   "error",
				Message: sarifMessage{Text: msg},
			})
		}
	}

	return sf.writeSARIF(w, sf.newLog(rules, results))
}

// JSON fallback methods — these data types are not security findings.

func (sf *sarifFormatter) FormatKEVList(w io.Writer, entries []model.KEVEntry) error {
	return sf.jsonFallback.FormatKEVList(w, entries)
}

func (sf *sarifFormatter) FormatEPSSScores(w io.Writer, scores map[string]*model.EPSSScore) error {
	return sf.jsonFallback.FormatEPSSScores(w, scores)
}

func (sf *sarifFormatter) FormatCVEHistory(w io.Writer, cve *model.EnrichedCVE) error {
	return sf.jsonFallback.FormatCVEHistory(w, cve)
}

func (sf *sarifFormatter) FormatCacheStats(w io.Writer, stats *cache.Stats) error {
	return sf.jsonFallback.FormatCacheStats(w, stats)
}
