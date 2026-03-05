package scanner

import (
	"encoding/json"
	"io"
	"strings"
)

// SARIFParser parses SARIF input files.
type SARIFParser struct{}

type sarifDocument struct {
	Schema string     `json:"$schema"`
	Runs   []sarifRun `json:"runs"`
}

type sarifRun struct {
	Results []sarifResult `json:"results"`
	Tool    sarifTool     `json:"tool"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	ShortDescription sarifMultiformatMsg `json:"shortDescription"`
}

type sarifMultiformatMsg struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string       `json:"ruleId"`
	Level     string       `json:"level"`
	Message   sarifMessage `json:"message"`
	Locations []sarifLoc   `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLoc struct {
	PhysicalLocation sarifPhysLoc `json:"physicalLocation"`
	LogicalLocations []sarifLL    `json:"logicalLocations"`
}

type sarifPhysLoc struct {
	ArtifactLocation sarifArtifactLoc `json:"artifactLocation"`
}

type sarifArtifactLoc struct {
	URI string `json:"uri"`
}

type sarifLL struct {
	Name string `json:"name"`
}

func (p *SARIFParser) Parse(r io.Reader) ([]Finding, error) {
	var doc sarifDocument
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, err
	}

	if len(doc.Runs) == 0 {
		return nil, nil
	}

	run := doc.Runs[0]

	// Build rule lookup for titles
	ruleTitles := make(map[string]string)
	for _, rule := range run.Tool.Driver.Rules {
		ruleTitles[rule.ID] = rule.ShortDescription.Text
	}

	var findings []Finding
	for _, result := range run.Results {
		severity := mapSARIFLevel(result.Level)

		// Extract package from logical locations
		pkg := ""
		target := ""
		for _, loc := range result.Locations {
			if target == "" && loc.PhysicalLocation.ArtifactLocation.URI != "" {
				target = loc.PhysicalLocation.ArtifactLocation.URI
			}
			for _, ll := range loc.LogicalLocations {
				if ll.Name != "" && pkg == "" {
					pkg = ll.Name
				}
			}
		}

		title := ruleTitles[result.RuleID]
		if title == "" {
			title = result.Message.Text
		}

		findings = append(findings, Finding{
			CVE:      result.RuleID,
			Package:  pkg,
			Severity: severity,
			Source:   "sarif",
			Target:  target,
			Title:   title,
		})
	}
	return findings, nil
}

func mapSARIFLevel(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return "HIGH"
	case "warning":
		return "MEDIUM"
	case "note":
		return "LOW"
	default:
		return "MEDIUM"
	}
}
