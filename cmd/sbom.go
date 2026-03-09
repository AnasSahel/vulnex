package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/api/osv"
	"github.com/trustin-tech/vulnex/internal/enricher"
	"github.com/trustin-tech/vulnex/internal/ignore"
	"github.com/trustin-tech/vulnex/internal/model"
	"github.com/trustin-tech/vulnex/internal/policy"
	"github.com/trustin-tech/vulnex/internal/sbom"
)

var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "SBOM analysis operations",
	Long:  "Parse Software Bill of Materials (SBOM) files and check components for known vulnerabilities.",
}

var sbomCheckCmd = &cobra.Command{
	Use:   "check <file>",
	Short: "Check SBOM or lockfile components for vulnerabilities",
	Long: `Parse a CycloneDX/SPDX JSON SBOM or a package lockfile and query each
component against the OSV vulnerability database. Results are displayed as
a table by default, or as a VEX document with the --vex flag.

Supported lockfiles: go.sum, package-lock.json, yarn.lock, pnpm-lock.yaml,
Cargo.lock, Gemfile.lock, requirements.txt, poetry.lock, composer.lock.`,
	Example: `  vulnex sbom check bom.json
  vulnex sbom check bom.json --vex
  vulnex sbom check sbom-spdx.json --ecosystem npm --severity HIGH
  vulnex sbom check bom.json --output json
  vulnex sbom check go.sum
  vulnex sbom check package-lock.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScanPipeline(cmd, args[0])
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

		// Apply suppressions to added findings only
		strict, _ := cmd.Flags().GetBool("strict")
		var suppressedFindings []model.SBOMFinding
		if !strict {
			ignoreFile, _ := cmd.Flags().GetString("ignore-file")
			igf, err := ignore.Load(resolveIgnoreFile(ignoreFile))
			if err != nil {
				return fmt.Errorf("loading ignore file: %w", err)
			}
			added, suppressedFindings = igf.Apply(added, time.Now())
			if !quiet && len(suppressedFindings) > 0 {
				fmt.Fprintf(os.Stderr, "Suppressed %d added findings via .vulnexignore\n", len(suppressedFindings))
			}
		}

		result := &model.SBOMDiffResult{
			OldFile:       oldFile,
			NewFile:       newFile,
			OldComponents: len(oldComponents),
			NewComponents: len(newComponents),
			Added:         added,
			Removed:       removed,
			Unchanged:     unchanged,
			Suppressed:    suppressedFindings,
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

	// Build queryable components with mapped ecosystems
	type queryComp struct {
		ecosystem string
		name      string
		version   string
	}
	var queryComps []queryComp
	for _, comp := range components {
		if comp.PURL == "" && (comp.Ecosystem == "" || comp.Name == "") {
			slog.Debug("skipping component without PURL or ecosystem/name", "name", comp.Name)
			continue
		}
		queryComps = append(queryComps, queryComp{
			ecosystem: mapEcosystemToOSV(comp.Ecosystem),
			name:      comp.Name,
			version:   comp.Version,
		})
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "Querying OSV for %d components...\n", len(queryComps))
	}

	// Build batch queries (OSV batch endpoint supports up to 1000 per request)
	const batchSize = 1000
	queries := make([]osv.QueryRequest, len(queryComps))
	for i, qc := range queryComps {
		queries[i] = osv.QueryRequest{
			Version: qc.version,
			Package: &osv.QueryPackage{
				Name:      qc.name,
				Ecosystem: qc.ecosystem,
			},
		}
	}

	// Collect all batch results, aligned by index with queryComps.
	// The batch endpoint only returns vuln IDs, so we collect IDs per component.
	type batchHit struct {
		vulnIDs []string
	}
	allHits := make([]batchHit, len(queryComps))
	for start := 0; start < len(queries); start += batchSize {
		end := start + batchSize
		if end > len(queries) {
			end = len(queries)
		}
		batch := queries[start:end]

		batchResp, err := app.OSV.BatchQuery(ctx, batch)
		if err != nil {
			slog.Warn("OSV batch query failed", "error", err)
			continue
		}

		for i, result := range batchResp.Results {
			ids := make([]string, len(result.Vulns))
			for j, v := range result.Vulns {
				ids[j] = v.ID
			}
			allHits[start+i] = batchHit{vulnIDs: ids}
		}
	}

	// Collect unique vuln IDs and fetch full details
	uniqueVulnIDs := make(map[string]struct{})
	for _, hit := range allHits {
		for _, id := range hit.vulnIDs {
			uniqueVulnIDs[id] = struct{}{}
		}
	}

	if !quiet && len(uniqueVulnIDs) > 0 {
		fmt.Fprintf(os.Stderr, "Fetching details for %d vulnerabilities...\n", len(uniqueVulnIDs))
	}

	// Fetch full vulnerability details concurrently
	fullVulns := make(map[string]*osv.OSVVulnerability, len(uniqueVulnIDs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // limit concurrency to 10
	for id := range uniqueVulnIDs {
		wg.Add(1)
		go func(vulnID string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			vuln, err := app.OSV.GetVulnerability(ctx, vulnID)
			if err != nil {
				slog.Debug("failed to fetch vulnerability details", "id", vulnID, "error", err)
				return
			}
			if vuln != nil {
				mu.Lock()
				fullVulns[vulnID] = vuln
				mu.Unlock()
			}
		}(id)
	}
	wg.Wait()

	// Process results using full vulnerability data
	var findings []model.SBOMFinding
	vulnResults := make(map[string]*model.EnrichedCVE)

	for i, qc := range queryComps {
		if len(allHits[i].vulnIDs) == 0 {
			continue
		}

		slog.Debug("found vulnerabilities",
			"component", qc.name,
			"version", qc.version,
			"count", len(allHits[i].vulnIDs),
		)

		for _, vulnID := range allHits[i].vulnIDs {
			v, ok := fullVulns[vulnID]
			if !ok {
				continue
			}

			severity := osv.ExtractSeverity(*v)

			// Extract first fixed version for this component
			fixed := ""
			for _, a := range v.Affected {
				if strings.EqualFold(a.Package.Ecosystem, qc.ecosystem) && a.Package.Name == qc.name {
					for _, r := range a.Ranges {
						for _, evt := range r.Events {
							if evt.Fixed != "" && fixed == "" {
								fixed = evt.Fixed
							}
						}
					}
				}
			}

			// Extract CVE IDs from the vulnerability ID and aliases
			var cveIDs []string
			if strings.HasPrefix(v.ID, "CVE-") {
				cveIDs = append(cveIDs, v.ID)
			}
			for _, alias := range v.Aliases {
				if strings.HasPrefix(alias, "CVE-") {
					cveIDs = append(cveIDs, alias)
				}
			}

			finding := model.SBOMFinding{
				Ecosystem: qc.ecosystem,
				Name:      qc.name,
				Version:   qc.version,
				Fixed:     fixed,
				CVEIDs:    cveIDs,
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

// resolveIgnoreFile returns the flag value if non-empty, else the default ".vulnexignore".
func resolveIgnoreFile(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return ".vulnexignore"
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

// runScanPipeline is the shared scan+filter+ignore+output pipeline used by
// the "sbom check" command.
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

	// Policy evaluation
	policyPath, _ := cmd.Flags().GetString("policy")
	if policyPath != "" {
		pol, err := policy.Load(policyPath)
		if err != nil {
			return fmt.Errorf("loading policy: %w", err)
		}
		policyResult := pol.EvaluateAll(findings)
		if !quiet {
			for _, v := range policyResult.Warnings {
				fmt.Fprintf(os.Stderr, "[WARN] %s: %s (%s)\n", v.RuleName, v.Finding.Advisory.ID, v.Finding.Name)
			}
			for _, v := range policyResult.Failures {
				fmt.Fprintf(os.Stderr, "[FAIL] %s: %s (%s)\n", v.RuleName, v.Finding.Advisory.ID, v.Finding.Name)
			}
		}
		if !policyResult.Passed {
			os.Exit(1)
		}
		return nil
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

	// Save snapshots for enriched CVEs
	enricher.SaveSnapshots(ctx, app.Cache, enrichedCVEs)

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
		results, err := app.Exploit.CheckBatch(ctx, uniqueCVEIDs)
		if err != nil {
			slog.Debug("exploit batch check failed", "error", err)
		}
		for i, r := range results {
			if r != nil && r.HasExploit {
				exploitMap[uniqueCVEIDs[i]] = true
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

	// Compute EPSS trends
	for i := range findings {
		for _, cveID := range findings[i].CVEIDs {
			if findings[i].EPSS != nil {
				entries, err := app.EPSS.GetTimeSeries(ctx, cveID, 30)
				if err != nil {
					slog.Debug("EPSS time series failed", "cve", cveID, "error", err)
					break
				}
				if len(entries) >= 2 {
					current := entries[len(entries)-1].Score
					previous := entries[0].Score
					delta := current - previous
					direction := "stable"
					if delta >= 0.05 {
						direction = "rising"
					} else if delta <= -0.05 {
						direction = "falling"
					}
					findings[i].EPSSTrend = &model.EPSSTrend{
						Current:    current,
						Previous30: previous,
						Delta:      delta,
						Direction:  direction,
					}
				}
				break
			}
		}
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "Enriched %d findings with EPSS/KEV/exploit data\n", enrichedCount)
	}

	return findings
}

func addScanFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("vex", false, "Output a VEX (Vulnerability Exploitability eXchange) document for sharing triage decisions")
	cmd.Flags().Bool("enrich", false, "Add exploit likelihood, known-exploitation status, and severity scores from multiple sources")
	cmd.Flags().String("ecosystem", "", "Filter components by ecosystem (npm, pip, maven, go, etc.)")
	cmd.Flags().String("severity", "", "Filter results by severity (critical, high, medium, low)")
	cmd.Flags().String("ignore-file", "", "Path to suppression file (default: .vulnexignore)")
	cmd.Flags().Bool("strict", false, "Show all findings, including those suppressed by .vulnexignore")
	cmd.Flags().String("policy", "", "Path to policy file for pass/fail evaluation")
}

func init() {
	addScanFlags(sbomCheckCmd)

	sbomDiffCmd.Flags().Bool("enrich", false, "Add exploit likelihood, known-exploitation status, and severity scores from multiple sources")
	sbomDiffCmd.Flags().String("ecosystem", "", "Filter components by ecosystem (npm, pip, maven, go, etc.)")
	sbomDiffCmd.Flags().String("severity", "", "Filter results by severity (critical, high, medium, low)")
	sbomDiffCmd.Flags().String("ignore-file", "", "Path to suppression file (default: .vulnexignore)")
	sbomDiffCmd.Flags().Bool("strict", false, "Show all findings, including those suppressed by .vulnexignore")

	sbomCmd.AddCommand(sbomCheckCmd)
	sbomCmd.AddCommand(sbomDiffCmd)
	rootCmd.AddCommand(sbomCmd)

	// Hidden alias: "vulnex scan" → "vulnex sbom check" for backwards compatibility
	scanCmd := &cobra.Command{
		Use:   "scan <file>",
		Short: "Alias for 'sbom check' (hidden)",
		Long: `Scan a package lockfile or SBOM file for known vulnerabilities.

This command is a hidden alias for 'vulnex sbom check'.
Use 'vulnex sbom check' instead.`,
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScanPipeline(cmd, args[0])
		},
	}
	addScanFlags(scanCmd)
	rootCmd.AddCommand(scanCmd)
}
