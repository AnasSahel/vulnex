package cmd

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
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

		// Parse the SBOM file
		components, err := sbom.ParseFile(filePath)
		if err != nil {
			return fmt.Errorf("parsing SBOM: %w", err)
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
			return nil
		}

		// Query OSV for each component and collect results
		var allAdvisories []model.Advisory
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

			vulns, err := app.OSV.QueryByPackage(cmd.Context(), ecosystem, name, version)
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
				// Build advisory from OSV result
				severity := ""
				for _, s := range v.Severity {
					severity = s.Score
					break
				}

				advisory := model.Advisory{
					ID:       v.ID,
					Source:   "osv",
					URL:      "https://osv.dev/vulnerability/" + v.ID,
					Severity: severity,
					Summary:  v.Summary,
				}
				allAdvisories = append(allAdvisories, advisory)

				// Build a minimal EnrichedCVE for VEX generation
				if _, exists := vulnResults[v.ID]; !exists {
					enriched := &model.EnrichedCVE{
						ID:          v.ID,
						DataSources: []string{"osv"},
					}

					// Extract affected packages
					for _, a := range v.Affected {
						pkg := model.AffectedPkg{
							Ecosystem: a.Package.Ecosystem,
							Name:      a.Package.Name,
							Versions:  a.Versions,
						}
						for _, r := range a.Ranges {
							var introduced, fixed, lastAffected string
							for _, evt := range r.Events {
								if evt.Introduced != "" {
									introduced = evt.Introduced
								}
								if evt.Fixed != "" {
									fixed = evt.Fixed
									if pkg.Fixed == "" {
										pkg.Fixed = fixed
									}
								}
								if evt.LastAffected != "" {
									lastAffected = evt.LastAffected
								}
							}
							pkg.Ranges = append(pkg.Ranges, model.Range{
								Type:         r.Type,
								Introduced:   introduced,
								Fixed:        fixed,
								LastAffected: lastAffected,
							})
						}
						enriched.AffectedPkgs = append(enriched.AffectedPkgs, pkg)
					}

					vulnResults[v.ID] = enriched
				}
			}
		}

		// Apply severity filter to advisories
		if severityFilter != "" {
			filtered := make([]model.Advisory, 0)
			for _, a := range allAdvisories {
				if strings.EqualFold(a.Severity, severityFilter) {
					filtered = append(filtered, a)
				}
			}
			allAdvisories = filtered
		}

		if !quiet {
			fmt.Fprintf(os.Stderr, "Found %d vulnerabilities\n", len(allAdvisories))
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

		if len(allAdvisories) == 0 {
			if !quiet {
				fmt.Fprintln(os.Stderr, "No vulnerabilities found for SBOM components")
			}
			return nil
		}

		return app.Formatter.FormatAdvisories(os.Stdout, allAdvisories)
	},
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

	sbomCmd.AddCommand(sbomCheckCmd)
	rootCmd.AddCommand(sbomCmd)
}
