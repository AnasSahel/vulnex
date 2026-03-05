package scanner

import (
	"encoding/json"
	"fmt"
	"io"
)

// Finding represents a normalized vulnerability finding from any scanner.
type Finding struct {
	CVE       string // CVE-YYYY-NNNNN
	Package   string // package name
	Version   string // installed version
	Fixed     string // fixed version
	Severity  string // CRITICAL, HIGH, MEDIUM, LOW
	Ecosystem string // Go, npm, PyPI, etc.
	Source    string // "trivy", "grype", "sarif"
	Target   string // scanned file/image
	Title    string // vulnerability title/summary
}

// Parser parses scanner output into normalized findings.
type Parser interface {
	Parse(r io.Reader) ([]Finding, error)
}

// Detect reads JSON and returns the appropriate parser + format name.
// Heuristic: Trivy has "Results", Grype has "matches", SARIF has "$schema" with "sarif".
func Detect(data []byte) (Parser, string, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, "", fmt.Errorf("invalid JSON input: %w", err)
	}

	// Check for SARIF: has "$schema" containing "sarif"
	if schema, ok := probe["$schema"]; ok {
		var s string
		if json.Unmarshal(schema, &s) == nil {
			if containsSARIF(s) {
				return &SARIFParser{}, "sarif", nil
			}
		}
	}

	// Check for Trivy: has "Results" key
	if _, ok := probe["Results"]; ok {
		return &TrivyParser{}, "trivy", nil
	}

	// Check for Grype: has "matches" key
	if _, ok := probe["matches"]; ok {
		return &GrypeParser{}, "grype", nil
	}

	return nil, "", fmt.Errorf("unable to detect scanner format (expected Trivy, Grype, or SARIF)")
}

func containsSARIF(s string) bool {
	for i := 0; i+4 < len(s); i++ {
		if s[i] == 's' && s[i+1] == 'a' && s[i+2] == 'r' && s[i+3] == 'i' && s[i+4] == 'f' {
			return true
		}
	}
	return false
}
