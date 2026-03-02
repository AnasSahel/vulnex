package sbom

import (
	"fmt"
	"time"

	"github.com/trustin-tech/vulnex/internal/model"
)

// VEXStatement represents a vulnerability exploitability assessment.
type VEXStatement struct {
	VulnID        string `json:"vulnerability"`
	Status        string `json:"status"` // "affected", "not_affected", "fixed", "under_investigation"
	Justification string `json:"justification,omitempty"`
	Product       string `json:"product"`
	Timestamp     string `json:"timestamp"`
}

// VEXDocument represents an OpenVEX-style document.
type VEXDocument struct {
	Context    string         `json:"@context"`
	ID         string         `json:"@id"`
	Author     string         `json:"author"`
	Timestamp  string         `json:"timestamp"`
	Statements []VEXStatement `json:"statements"`
}

// GenerateVEX creates a VEX document from vulnerability scan results.
//
// The components slice contains the parsed SBOM components.
// The vulnResults map is keyed by component PURL and contains the enriched
// CVE data for vulnerabilities affecting that component.
func GenerateVEX(components []Component, vulnResults map[string]*model.EnrichedCVE) (*VEXDocument, error) {
	now := time.Now().UTC()
	timestamp := now.Format(time.RFC3339)

	doc := &VEXDocument{
		Context:   "https://openvex.dev/ns/v0.2.0",
		ID:        fmt.Sprintf("vulnex/vex/%d", now.UnixNano()),
		Author:    "vulnex",
		Timestamp: timestamp,
	}

	for _, comp := range components {
		// Build a product identifier from the component. Prefer the PURL;
		// fall back to name@version.
		product := comp.PURL
		if product == "" {
			product = comp.Name
			if comp.Version != "" {
				product = comp.Name + "@" + comp.Version
			}
		}

		// Look up CVE data for this component. The caller keys the map by
		// CVE ID, so we iterate over all results and match against the
		// component's affected packages.
		for cveID, cve := range vulnResults {
			if !componentAffected(comp, cve) {
				continue
			}

			status := determineStatus(comp, cve)
			stmt := VEXStatement{
				VulnID:    cveID,
				Status:    status,
				Product:   product,
				Timestamp: timestamp,
			}

			if status == "not_affected" {
				stmt.Justification = "component_not_present"
			}

			doc.Statements = append(doc.Statements, stmt)
		}
	}

	return doc, nil
}

// componentAffected returns true if the given CVE lists the component's
// ecosystem and package name among its affected packages.
func componentAffected(comp Component, cve *model.EnrichedCVE) bool {
	if cve == nil {
		return false
	}

	for _, pkg := range cve.AffectedPkgs {
		if matchesComponent(comp, pkg) {
			return true
		}
	}

	// Also match by CPE if the component has one
	if comp.CPE != "" {
		for _, cpe := range cve.CPEs {
			if cpe.CPE23URI == comp.CPE && cpe.Vulnerable {
				return true
			}
		}
	}

	return false
}

// matchesComponent checks whether an AffectedPkg matches a Component by
// comparing ecosystem and name (case-insensitive).
func matchesComponent(comp Component, pkg model.AffectedPkg) bool {
	if comp.Ecosystem == "" || pkg.Ecosystem == "" {
		// If either ecosystem is unknown, fall back to name-only matching
		return comp.Name != "" && comp.Name == pkg.Name
	}
	return normalizeEcosystem(comp.Ecosystem) == normalizeEcosystem(pkg.Ecosystem) &&
		comp.Name == pkg.Name
}

// determineStatus decides the VEX status for a component + CVE pair.
// If a fixed version exists in the affected package data, the status is
// "fixed"; otherwise it is "affected".
func determineStatus(comp Component, cve *model.EnrichedCVE) string {
	if cve == nil {
		return "under_investigation"
	}

	for _, pkg := range cve.AffectedPkgs {
		if !matchesComponent(comp, pkg) {
			continue
		}
		if pkg.Fixed != "" {
			return "fixed"
		}
		for _, r := range pkg.Ranges {
			if r.Fixed != "" {
				return "fixed"
			}
		}
	}

	return "affected"
}

// normalizeEcosystem maps common ecosystem identifiers to a canonical form
// so that comparisons between PURL types and OSV ecosystems work correctly.
func normalizeEcosystem(eco string) string {
	switch eco {
	case "npm", "npm:":
		return "npm"
	case "pip", "pypi", "PyPI":
		return "pypi"
	case "maven", "Maven":
		return "maven"
	case "go", "Go", "golang":
		return "go"
	case "rubygems", "gem", "RubyGems":
		return "rubygems"
	case "cargo", "crates.io":
		return "cargo"
	case "nuget", "NuGet":
		return "nuget"
	default:
		return eco
	}
}
