package scanner

import (
	"encoding/json"
	"io"
	"strings"
)

// TrivyParser parses Trivy JSON output.
type TrivyParser struct{}

type trivyOutput struct {
	SchemaVersion int           `json:"SchemaVersion"`
	Results       []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string      `json:"Target"`
	Type            string      `json:"Type"`
	Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
}

func (p *TrivyParser) Parse(r io.Reader) ([]Finding, error) {
	var out trivyOutput
	if err := json.NewDecoder(r).Decode(&out); err != nil {
		return nil, err
	}

	var findings []Finding
	for _, result := range out.Results {
		eco := mapTrivyEcosystem(result.Type)
		for _, v := range result.Vulnerabilities {
			findings = append(findings, Finding{
				CVE:       v.VulnerabilityID,
				Package:   v.PkgName,
				Version:   v.InstalledVersion,
				Fixed:     v.FixedVersion,
				Severity:  strings.ToUpper(v.Severity),
				Ecosystem: eco,
				Source:    "trivy",
				Target:   result.Target,
				Title:    v.Title,
			})
		}
	}
	return findings, nil
}

func mapTrivyEcosystem(typ string) string {
	switch strings.ToLower(typ) {
	case "gomod", "gobinary":
		return "Go"
	case "npm", "node-pkg", "yarn", "pnpm":
		return "npm"
	case "pip", "pipenv", "poetry", "conda":
		return "PyPI"
	case "cargo":
		return "crates.io"
	case "bundler", "gemspec":
		return "RubyGems"
	case "composer":
		return "Packagist"
	case "nuget", "dotnet-core":
		return "NuGet"
	case "jar", "pom":
		return "Maven"
	default:
		return typ
	}
}
