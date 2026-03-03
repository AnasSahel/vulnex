package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/api/osv"
	"github.com/trustin-tech/vulnex/internal/model"
	"github.com/trustin-tech/vulnex/internal/sbom"
)

var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "SBOM analysis operations",
	Long:  "Parse Software Bill of Materials (SBOM) files and check components for known vulnerabilities.",
}

var sbomCheckCmd = &cobra.Command{
	Use:   "check <file>",
	Short: "Check SBOM components for vulnerabilities",
	Long: `Parse a CycloneDX or SPDX JSON SBOM file and query each component
against the OSV vulnerability database. Results are displayed as a table
by default, or as a VEX document with the --vex flag.`,
	Example: `  vulnex sbom check bom.json
  vulnex sbom check bom.json --vex
  vulnex sbom check sbom-spdx.json --ecosystem npm --severity HIGH
  vulnex sbom check bom.json --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		ecosystemFilter, _ := cmd.Flags().GetString("ecosystem")
		severityFilter, _ := cmd.Flags().GetString("severity")
		vexOutput, _ := cmd.Flags().GetBool("vex")
		quiet, _ := cmd.Flags().GetBool("quiet")

		components, findings, vulnResults, err := scanSBOM(cmd.Context(), filePath, ecosystemFilter, quiet)
		if err != nil {
			return err
		}

		// Apply severity filter
		if severityFilter != "" {
			filtered := make([]model.SBOMFinding, 0)
			for _, f := range findings {
				if strings.EqualFold(f.Advisory.Severity, severityFilter) {
					filtered = append(filtered, f)
				}
			}
			findings = filtered
		}

		if !quiet {
			fmt.Fprintf(os.Stderr, "Found %d vulnerabilities\n", len(findings))
		}

		// Output results
		if vexOutput {
			vexDoc, err := sbom.GenerateVEX(components, vulnResults)
			if err != nil {
				return fmt.Errorf("generating VEX document: %w", err)
			}

			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			return encoder.Encode(vexDoc)
		}

		result := &model.SBOMResult{
			File:            filePath,
			TotalComponents: len(components),
			Findings:        findings,
		}

		if len(findings) == 0 {
			if !quiet {
				fmt.Fprintln(os.Stderr, "No vulnerabilities found for SBOM components")
			}
			return nil
		}

		if err := app.Formatter.FormatSBOMResult(os.Stdout, result); err != nil {
			return err
		}

		os.Exit(1)
		return nil
	},
}

var sbomDiffCmd = &cobra.Command{
	Use:   "diff <old-sbom> <new-sbom>",
	Short: "Compare two SBOMs for vulnerability changes",
	Long: `Compare two CycloneDX or SPDX JSON SBOM files and report which
vulnerabilities were added, removed, or unchanged between them.

Exit code 0 means no new vulnerabilities were introduced.
Exit code 1 means at least one new vulnerability was added (CI gate failure).`,
	Example: `  vulnex sbom diff old-bom.json new-bom.json
  vulnex sbom diff old.json new.json --severity critical
  vulnex sbom diff old.json new.json --ecosystem npm
  vulnex sbom diff old.json new.json -o json`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		oldFile := args[0]
		newFile := args[1]
		ecosystemFilter, _ := cmd.Flags().GetString("ecosystem")
		severityFilter, _ := cmd.Flags().GetString("severity")
		quiet, _ := cmd.Flags().GetBool("quiet")

		oldComponents, oldFindings, _, err := scanSBOM(cmd.Context(), oldFile, ecosystemFilter, quiet)
		if err != nil {
			return fmt.Errorf("scanning old SBOM: %w", err)
		}

		newComponents, newFindings, _, err := scanSBOM(cmd.Context(), newFile, ecosystemFilter, quiet)
		if err != nil {
			return fmt.Errorf("scanning new SBOM: %w", err)
		}

		// Build finding key sets: ecosystem/name@version:advisoryID
		findingKey := func(f model.SBOMFinding) string {
			return fmt.Sprintf("%s/%s@%s:%s", f.Ecosystem, f.Name, f.Version, f.Advisory.ID)
		}

		oldSet := make(map[string]model.SBOMFinding, len(oldFindings))
		for _, f := range oldFindings {
			oldSet[findingKey(f)] = f
		}

		newSet := make(map[string]model.SBOMFinding, len(newFindings))
		for _, f := range newFindings {
			newSet[findingKey(f)] = f
		}

		var added, removed, unchanged []model.SBOMFinding

		for key, f := range newSet {
			if _, exists := oldSet[key]; exists {
				unchanged = append(unchanged, f)
			} else {
				added = append(added, f)
			}
		}

		for key, f := range oldSet {
			if _, exists := newSet[key]; !exists {
				removed = append(removed, f)
			}
		}

		// Apply severity filter
		if severityFilter != "" {
			added = filterBySeverity(added, severityFilter)
			removed = filterBySeverity(removed, severityFilter)
			unchanged = filterBySeverity(unchanged, severityFilter)
		}

		result := &model.SBOMDiffResult{
			OldFile:       oldFile,
			NewFile:       newFile,
			OldComponents: len(oldComponents),
			NewComponents: len(newComponents),
			Added:         added,
			Removed:       removed,
			Unchanged:     unchanged,
		}

		if !quiet {
			fmt.Fprintf(os.Stderr, "Diff: +%d added, -%d removed, =%d unchanged\n",
				len(added), len(removed), len(unchanged))
		}

		if err := app.Formatter.FormatSBOMDiffResult(os.Stdout, result); err != nil {
			return err
		}

		if len(added) > 0 {
			os.Exit(1)
		}
		return nil
	},
}

// scanSBOM parses an SBOM file, applies ecosystem filtering, and queries OSV for vulnerabilities.
// It returns the components, findings, and a map of enriched CVEs for VEX generation.
func scanSBOM(ctx context.Context, filePath, ecosystemFilter string, quiet bool) ([]sbom.Component, []model.SBOMFinding, map[string]*model.EnrichedCVE, error) {
	components, err := sbom.ParseFile(filePath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing SBOM: %w", err)
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "Parsed %d components from %s\n", len(components), filePath)
	}

	// Apply ecosystem filter
	if ecosystemFilter != "" {
		filtered := make([]sbom.Component, 0)
		for _, c := range components {
			if strings.EqualFold(c.Ecosystem, ecosystemFilter) {
				filtered = append(filtered, c)
			}
		}
		components = filtered
		if !quiet {
			fmt.Fprintf(os.Stderr, "Filtered to %d %s components\n", len(components), ecosystemFilter)
		}
	}

	if len(components) == 0 {
		if !quiet {
			fmt.Fprintln(os.Stderr, "No components to check")
		}
		return components, nil, nil, nil
	}

	// Query OSV for each component and collect results
	var findings []model.SBOMFinding
	vulnResults := make(map[string]*model.EnrichedCVE)

	for _, comp := range components {
		if comp.PURL == "" && (comp.Ecosystem == "" || comp.Name == "") {
			slog.Debug("skipping component without PURL or ecosystem/name", "name", comp.Name)
			continue
		}

		ecosystem := comp.Ecosystem
		name := comp.Name
		version := comp.Version

		// Map PURL ecosystem types to OSV ecosystem names
		ecosystem = mapEcosystemToOSV(ecosystem)

		vulns, err := app.OSV.QueryByPackage(ctx, ecosystem, name, version)
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
			findings = append(findings, finding)

			// Build a minimal EnrichedCVE for VEX generation
			if _, exists := vulnResults[v.ID]; !exists {
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

				vulnResults[v.ID] = enriched
			}
		}
	}

	return components, findings, vulnResults, nil
}

// filterBySeverity filters findings to only those matching the given severity.
func filterBySeverity(findings []model.SBOMFinding, severity string) []model.SBOMFinding {
	filtered := make([]model.SBOMFinding, 0)
	for _, f := range findings {
		if strings.EqualFold(f.Advisory.Severity, severity) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// mapEcosystemToOSV converts PURL ecosystem type strings to OSV ecosystem names.
func mapEcosystemToOSV(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "npm"
	case "pypi", "pip":
		return "PyPI"
	case "maven":
		return "Maven"
	case "go", "golang":
		return "Go"
	case "cargo":
		return "crates.io"
	case "nuget":
		return "NuGet"
	case "gem", "rubygems":
		return "RubyGems"
	case "composer":
		return "Packagist"
	case "hex":
		return "Hex"
	case "pub":
		return "Pub"
	case "swift":
		return "SwiftURL"
	default:
		return ecosystem
	}
}

func init() {
	sbomCheckCmd.Flags().Bool("vex", false, "Output an OpenVEX document instead of a table")
	sbomCheckCmd.Flags().String("ecosystem", "", "Filter components by ecosystem (npm, pip, maven, go, etc.)")
	sbomCheckCmd.Flags().String("severity", "", "Filter results by severity (critical, high, medium, low)")

	sbomDiffCmd.Flags().String("ecosystem", "", "Filter components by ecosystem (npm, pip, maven, go, etc.)")
	sbomDiffCmd.Flags().String("severity", "", "Filter results by severity (critical, high, medium, low)")

	sbomCmd.AddCommand(sbomCheckCmd)
	sbomCmd.AddCommand(sbomDiffCmd)
	rootCmd.AddCommand(sbomCmd)
}
