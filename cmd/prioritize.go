package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/ignore"
	"github.com/trustin-tech/vulnex/internal/model"
	"github.com/trustin-tech/vulnex/internal/policy"
	"github.com/trustin-tech/vulnex/internal/scanner"
)

var prioritizeCmd = &cobra.Command{
	Use:   "prioritize [file]",
	Short: "Enrich and prioritize scanner findings",
	Long: `Ingest vulnerability findings from Trivy, Grype, or SARIF and enrich
each finding with EPSS scores, KEV status, exploit availability, and
composite risk priority (P0-P4).

Reads from stdin when no file argument is given.`,
	Example: `  vulnex prioritize trivy-results.json
  cat grype-output.json | vulnex prioritize
  vulnex prioritize scan.sarif --from sarif
  vulnex prioritize trivy.json --policy .vulnex-policy.yaml

  # Custom scoring weights
  vulnex prioritize trivy.json --scoring-profile exploit-focused
  vulnex prioritize trivy.json --cvss-weight 0.5 --epss-weight 0.3 --kev-weight 0.2`,
	Args: cobra.MaximumNArgs(1),
	RunE: runPrioritize,
}

func runPrioritize(cmd *cobra.Command, args []string) error {
	start := time.Now()
	quiet, _ := cmd.Flags().GetBool("quiet")
	fromFlag, _ := cmd.Flags().GetString("from")

	// Read input
	var data []byte
	var err error
	if len(args) > 0 {
		data, err = os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("reading input file: %w", err)
		}
	} else {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
	}

	if len(data) == 0 {
		return fmt.Errorf("empty input")
	}

	// Select parser
	var parser scanner.Parser
	var format string
	if fromFlag != "" {
		switch strings.ToLower(fromFlag) {
		case "trivy":
			parser = &scanner.TrivyParser{}
			format = "trivy"
		case "grype":
			parser = &scanner.GrypeParser{}
			format = "grype"
		case "sarif":
			parser = &scanner.SARIFParser{}
			format = "sarif"
		default:
			return fmt.Errorf("unknown format %q (supported: trivy, grype, sarif)", fromFlag)
		}
	} else {
		parser, format, err = scanner.Detect(data)
		if err != nil {
			return fmt.Errorf("detecting format: %w", err)
		}
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "Detected format: %s\n", format)
	}

	// Parse findings
	scannerFindings, err := parser.Parse(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("parsing %s output: %w", format, err)
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "Parsed %d findings\n", len(scannerFindings))
	}

	if len(scannerFindings) == 0 {
		if !quiet {
			fmt.Fprintln(os.Stderr, "No findings to prioritize")
		}
		return nil
	}

	// Convert to SBOMFindings
	findings := make([]model.SBOMFinding, 0, len(scannerFindings))
	for _, f := range scannerFindings {
		sf := model.SBOMFinding{
			Ecosystem: f.Ecosystem,
			Name:      f.Package,
			Version:   f.Version,
			Fixed:     f.Fixed,
			Advisory: model.Advisory{
				ID:       f.CVE,
				Source:   f.Source,
				Severity: f.Severity,
				Summary:  f.Title,
			},
		}
		if strings.HasPrefix(f.CVE, "CVE-") {
			sf.CVEIDs = []string{f.CVE}
		}
		findings = append(findings, sf)
	}

	// Apply suppressions
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

	// Enrich findings
	if len(findings) > 0 {
		findings = enrichFindings(cmd, findings, quiet)
	}

	// Sort by priority: P0 first, then by score descending
	sort.Slice(findings, func(i, j int) bool {
		ri, rj := findings[i].Risk, findings[j].Risk
		if ri == nil && rj == nil {
			return false
		}
		if ri == nil {
			return false
		}
		if rj == nil {
			return true
		}
		if ri.Score != rj.Score {
			return ri.Score > rj.Score
		}
		return ri.Priority < rj.Priority
	})

	// Policy evaluation
	policyPath, _ := cmd.Flags().GetString("policy")
	if policyPath == "" {
		// Check for default policy file
		if _, err := os.Stat(".vulnex-policy.yaml"); err == nil {
			policyPath = ".vulnex-policy.yaml"
		}
	}

	var policyResult *policy.Result
	if policyPath != "" {
		pol, err := policy.Load(policyPath)
		if err != nil {
			return fmt.Errorf("loading policy: %w", err)
		}
		policyResult = pol.EvaluateAll(findings)

		if !quiet {
			if len(policyResult.Warnings) > 0 {
				fmt.Fprintf(os.Stderr, "Policy warnings: %d\n", len(policyResult.Warnings))
				for _, v := range policyResult.Warnings {
					fmt.Fprintf(os.Stderr, "  [WARN] %s: %s (%s)\n", v.RuleName, v.Finding.Advisory.ID, v.Finding.Name)
				}
			}
			if len(policyResult.Failures) > 0 {
				fmt.Fprintf(os.Stderr, "Policy failures: %d\n", len(policyResult.Failures))
				for _, v := range policyResult.Failures {
					fmt.Fprintf(os.Stderr, "  [FAIL] %s: %s (%s)\n", v.RuleName, v.Finding.Advisory.ID, v.Finding.Name)
				}
			}
		}
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "Completed in %s\n", time.Since(start).Round(time.Millisecond))
	}

	if len(findings) == 0 {
		if !quiet {
			fmt.Fprintln(os.Stderr, "No findings after filtering")
		}
		return nil
	}

	// Output results
	inputName := "stdin"
	if len(args) > 0 {
		inputName = args[0]
	}
	result := &model.SBOMResult{
		File:            inputName,
		TotalComponents: len(findings),
		Findings:        findings,
		Suppressed:      suppressedFindings,
	}

	// Populate policy failures for inline display
	if policyResult != nil && len(policyResult.Failures) > 0 {
		result.PolicyFailures = make(map[string]string, len(policyResult.Failures))
		for _, v := range policyResult.Failures {
			result.PolicyFailures[v.Finding.Advisory.ID] = v.RuleName
		}
	}

	if err := app.Formatter.FormatSBOMResult(os.Stdout, result); err != nil {
		return err
	}

	// Exit code
	if policyResult != nil {
		if !policyResult.Passed {
			os.Exit(1)
		}
		return nil
	}

	// Default: exit 1 when findings exist
	os.Exit(1)
	return nil
}

func init() {
	prioritizeCmd.Flags().String("from", "", "Input format: trivy, grype, or sarif (auto-detected from file content if omitted)")
	prioritizeCmd.Flags().String("ignore-file", "", "Path to suppression file (default: .vulnexignore)")
	prioritizeCmd.Flags().Bool("strict", false, "Show all findings, including those suppressed by .vulnexignore")
	prioritizeCmd.Flags().String("scoring-profile", "", "Preset weight balance for scoring: default (balanced), exploit-focused, or severity-focused")
	prioritizeCmd.Flags().Float64("cvss-weight", 0, "How much severity (CVSS) influences the final score, from 0.0 (ignore) to 1.0 (full weight)")
	prioritizeCmd.Flags().Float64("epss-weight", 0, "How much exploit probability (EPSS) influences the final score, from 0.0 (ignore) to 1.0 (full weight)")
	prioritizeCmd.Flags().Float64("kev-weight", 0, "How much known-exploited status (KEV) influences the final score, from 0.0 (ignore) to 1.0 (full weight)")
	prioritizeCmd.Flags().String("policy", "", "Path to policy file (default: .vulnex-policy.yaml if present)")

	rootCmd.AddCommand(prioritizeCmd)
}
