package cmd

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/ignore"
	"github.com/trustin-tech/vulnex/internal/model"
	"github.com/trustin-tech/vulnex/internal/sbom"
)

var scanCmd = &cobra.Command{
	Use:   "scan <file>",
	Short: "Scan a lockfile or SBOM for vulnerabilities",
	Long: `Scan a package lockfile or SBOM file for known vulnerabilities.

Supported lockfiles: go.sum, package-lock.json, yarn.lock, pnpm-lock.yaml,
Cargo.lock, Gemfile.lock, requirements.txt, poetry.lock, composer.lock.

Supported SBOMs: CycloneDX (JSON), SPDX (JSON).

Results are displayed as a table by default. Use --output to change the format.
Use --enrich to add EPSS, KEV, CVSS, and exploit data to findings.`,
	Example: `  vulnex scan go.sum
  vulnex scan package-lock.json --severity HIGH
  vulnex scan Cargo.lock -o json
  vulnex scan bom.json --ecosystem npm
  vulnex scan go.sum --enrich`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScanPipeline(cmd, args[0])
	},
}

// runScanPipeline is the shared scan+filter+ignore+output pipeline used by
// both "sbom check" and "scan" commands.
func runScanPipeline(cmd *cobra.Command, filePath string) error {
	start := time.Now()
	ecosystemFilter, _ := cmd.Flags().GetString("ecosystem")
	severityFilter, _ := cmd.Flags().GetString("severity")
	vexOutput, _ := cmd.Flags().GetBool("vex")
	quiet, _ := cmd.Flags().GetBool("quiet")
	enrich, _ := cmd.Flags().GetBool("enrich")

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

	// Apply suppressions from .vulnexignore
	strict, _ := cmd.Flags().GetBool("strict")
	var suppressedFindings []model.SBOMFinding
	if !strict {
		ignoreFile, _ := cmd.Flags().GetString("ignore-file")
		igf, err := ignore.Load(resolveIgnoreFile(ignoreFile))
		if err != nil {
			return fmt.Errorf("loading ignore file: %w", err)
		}
		findings, suppressedFindings = igf.Apply(findings, time.Now())
		if !quiet && len(suppressedFindings) > 0 {
			fmt.Fprintf(os.Stderr, "Suppressed %d findings via .vulnexignore\n", len(suppressedFindings))
		}
	}

	// Enrich findings with EPSS/KEV/exploit data
	if enrich && len(findings) > 0 {
		findings = enrichFindings(cmd, findings, quiet)
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
		Suppressed:      suppressedFindings,
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "Completed in %s\n", time.Since(start).Round(time.Millisecond))
	}

	if len(findings) == 0 {
		if !quiet {
			fmt.Fprintln(os.Stderr, "No vulnerabilities found")
		}
		return nil
	}

	if err := app.Formatter.FormatSBOMResult(os.Stdout, result); err != nil {
		return err
	}

	os.Exit(1)
	return nil
}

// enrichFindings adds EPSS, KEV, CVSS, and exploit data to SBOM findings.
func enrichFindings(cmd *cobra.Command, findings []model.SBOMFinding, quiet bool) []model.SBOMFinding {
	ctx := cmd.Context()

	// Collect unique CVE IDs across all findings
	cveSet := make(map[string]struct{})
	for _, f := range findings {
		for _, id := range f.CVEIDs {
			cveSet[id] = struct{}{}
		}
	}

	if len(cveSet) == 0 {
		if !quiet {
			fmt.Fprintln(os.Stderr, "No CVE IDs found in findings, skipping enrichment")
		}
		return findings
	}

	uniqueCVEIDs := make([]string, 0, len(cveSet))
	for id := range cveSet {
		uniqueCVEIDs = append(uniqueCVEIDs, id)
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "Enriching %d unique CVE IDs...\n", len(uniqueCVEIDs))
	}

	// Enrich CVEs in batch
	enrichedCVEs, err := app.Enricher.EnrichBatch(ctx, uniqueCVEIDs)
	if err != nil {
		slog.Warn("enrichment batch failed", "error", err)
	}

	// Build lookup map
	enrichedMap := make(map[string]*model.EnrichedCVE, len(enrichedCVEs))
	for i, cve := range enrichedCVEs {
		if cve != nil {
			enrichedMap[uniqueCVEIDs[i]] = cve
		}
	}

	// Check for exploits in batch
	exploitMap := make(map[string]bool)
	if app.Exploit != nil {
		for _, id := range uniqueCVEIDs {
			result, err := app.Exploit.Check(ctx, id)
			if err != nil {
				slog.Debug("exploit check failed", "cve", id, "error", err)
				continue
			}
			if result != nil && len(result.Exploits) > 0 {
				exploitMap[id] = true
			}
		}
	}

	// Apply enrichment to findings
	enrichedCount := 0
	for i := range findings {
		for _, cveID := range findings[i].CVEIDs {
			if cve, ok := enrichedMap[cveID]; ok {
				findings[i].EPSS = cve.EPSS
				findings[i].KEV = cve.KEV
				if score := cve.HighestScore(); score != nil {
					findings[i].CVSSScore = score.BaseScore
				}
				risk := model.ComputeRisk(cve)
				findings[i].Risk = &risk
				enrichedCount++
				break // Use first matching CVE
			}
		}
		for _, cveID := range findings[i].CVEIDs {
			if exploitMap[cveID] {
				findings[i].HasExploit = true
				break
			}
		}
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "Enriched %d findings with EPSS/KEV/exploit data\n", enrichedCount)
	}

	return findings
}

func init() {
	scanCmd.Flags().Bool("vex", false, "Output an OpenVEX document instead of a table")
	scanCmd.Flags().Bool("enrich", false, "Enrich findings with EPSS, KEV, CVSS, and exploit data")
	scanCmd.Flags().String("ecosystem", "", "Filter components by ecosystem (npm, pip, maven, go, etc.)")
	scanCmd.Flags().String("severity", "", "Filter results by severity (critical, high, medium, low)")
	scanCmd.Flags().String("ignore-file", "", "Path to suppression file (default: .vulnexignore)")
	scanCmd.Flags().Bool("strict", false, "Ignore suppression file and report all findings")

	rootCmd.AddCommand(scanCmd)
}
