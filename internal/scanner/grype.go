package scanner

import (
	"encoding/json"
	"io"
	"strings"
)

// GrypeParser parses Grype JSON output.
type GrypeParser struct{}

type grypeOutput struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability grypeVuln     `json:"vulnerability"`
	Artifact      grypeArtifact `json:"artifact"`
}

type grypeVuln struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Fix      grypeFix `json:"fix"`
}

type grypeFix struct {
	State    string   `json:"state"`
	Versions []string `json:"versions"`
}

type grypeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

func (p *GrypeParser) Parse(r io.Reader) ([]Finding, error) {
	var out grypeOutput
	if err := json.NewDecoder(r).Decode(&out); err != nil {
		return nil, err
	}

	var findings []Finding
	for _, m := range out.Matches {
		fixed := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixed = m.Vulnerability.Fix.Versions[0]
		}

		findings = append(findings, Finding{
			CVE:       m.Vulnerability.ID,
			Package:   m.Artifact.Name,
			Version:   m.Artifact.Version,
			Fixed:     fixed,
			Severity:  strings.ToUpper(m.Vulnerability.Severity),
			Ecosystem: mapGrypeEcosystem(m.Artifact.Type),
			Source:    "grype",
			Title:    "",
		})
	}
	return findings, nil
}

func mapGrypeEcosystem(typ string) string {
	switch strings.ToLower(typ) {
	case "go-module":
		return "Go"
	case "npm":
		return "npm"
	case "python":
		return "PyPI"
	case "rust-crate":
		return "crates.io"
	case "gem":
		return "RubyGems"
	case "java-archive":
		return "Maven"
	case "dotnet":
		return "NuGet"
	default:
		return typ
	}
}
