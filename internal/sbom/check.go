package sbom

import (
	"context"
	"log/slog"
	"strings"

	"github.com/trustin-tech/vulnex/internal/api/osv"
	"github.com/trustin-tech/vulnex/internal/model"
)

// CheckOptions configures the vulnerability check behavior.
type CheckOptions struct {
	EcosystemFilter string
	SeverityFilter  string
}

// CheckResult holds the outcome of a vulnerability check.
type CheckResult struct {
	TotalComponents int
	Findings        []model.SBOMFinding
	VulnDetails     map[string]*model.EnrichedCVE
}

// CheckComponents queries OSV for vulnerabilities affecting the given components
// and returns the findings. It applies ecosystem and severity filters from opts.
func CheckComponents(ctx context.Context, osvClient *osv.Client, components []Component, opts CheckOptions) (*CheckResult, error) {
	// Apply ecosystem filter
	if opts.EcosystemFilter != "" {
		filtered := make([]Component, 0)
		for _, c := range components {
			if strings.EqualFold(c.Ecosystem, opts.EcosystemFilter) {
				filtered = append(filtered, c)
			}
		}
		components = filtered
	}

	result := &CheckResult{
		TotalComponents: len(components),
		VulnDetails:     make(map[string]*model.EnrichedCVE),
	}

	for _, comp := range components {
		if comp.PURL == "" && (comp.Ecosystem == "" || comp.Name == "") {
			slog.Debug("skipping component without PURL or ecosystem/name", "name", comp.Name)
			continue
		}

		ecosystem := MapEcosystemToOSV(comp.Ecosystem)
		name := comp.Name
		version := comp.Version

		vulns, err := osvClient.QueryByPackage(ctx, ecosystem, name, version)
		if err != nil {
			slog.Warn("querying OSV for component",
				"ecosystem", ecosystem,
				"name", name,
				"version", version,
				"error", err,
			)
			continue
		}

		if len(vulns) == 0 {
			continue
		}

		slog.Debug("found vulnerabilities",
			"component", name,
			"version", version,
			"count", len(vulns),
		)

		for _, v := range vulns {
			severity := osv.ExtractSeverity(v)

			// Extract first fixed version for this component
			fixed := ""
			for _, a := range v.Affected {
				if strings.EqualFold(a.Package.Ecosystem, ecosystem) && a.Package.Name == name {
					for _, r := range a.Ranges {
						for _, evt := range r.Events {
							if evt.Fixed != "" && fixed == "" {
								fixed = evt.Fixed
							}
						}
					}
				}
			}

			finding := model.SBOMFinding{
				Ecosystem: ecosystem,
				Name:      name,
				Version:   version,
				Fixed:     fixed,
				Advisory: model.Advisory{
					ID:       v.ID,
					Source:   "osv",
					URL:      "https://osv.dev/vulnerability/" + v.ID,
					Severity: severity,
					Summary:  v.Summary,
				},
			}
			result.Findings = append(result.Findings, finding)

			// Build a minimal EnrichedCVE for VEX generation
			if _, exists := result.VulnDetails[v.ID]; !exists {
				enriched := &model.EnrichedCVE{
					ID:          v.ID,
					DataSources: []string{"osv"},
				}

				for _, a := range v.Affected {
					pkg := model.AffectedPkg{
						Ecosystem: a.Package.Ecosystem,
						Name:      a.Package.Name,
						Versions:  a.Versions,
					}
					for _, r := range a.Ranges {
						var introduced, fixedVer, lastAffected string
						for _, evt := range r.Events {
							if evt.Introduced != "" {
								introduced = evt.Introduced
							}
							if evt.Fixed != "" {
								fixedVer = evt.Fixed
								if pkg.Fixed == "" {
									pkg.Fixed = fixedVer
								}
							}
							if evt.LastAffected != "" {
								lastAffected = evt.LastAffected
							}
						}
						pkg.Ranges = append(pkg.Ranges, model.Range{
							Type:         r.Type,
							Introduced:   introduced,
							Fixed:        fixedVer,
							LastAffected: lastAffected,
						})
					}
					enriched.AffectedPkgs = append(enriched.AffectedPkgs, pkg)
				}

				result.VulnDetails[v.ID] = enriched
			}
		}
	}

	// Apply severity filter
	if opts.SeverityFilter != "" {
		filtered := make([]model.SBOMFinding, 0)
		for _, f := range result.Findings {
			if strings.EqualFold(f.Advisory.Severity, opts.SeverityFilter) {
				filtered = append(filtered, f)
			}
		}
		result.Findings = filtered
	}

	return result, nil
}
