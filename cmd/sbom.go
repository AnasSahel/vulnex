package cmd

import (
	"encoding/json"
	"fmt"
	"os"

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

		if len(components) == 0 {
			if !quiet {
				fmt.Fprintln(os.Stderr, "No components to check")
			}
			return nil
		}

		// Run the vulnerability check
		checkResult, err := sbom.CheckComponents(cmd.Context(), app.OSV, components, sbom.CheckOptions{
			EcosystemFilter: ecosystemFilter,
			SeverityFilter:  severityFilter,
		})
		if err != nil {
			return fmt.Errorf("checking components: %w", err)
		}

		if !quiet {
			fmt.Fprintf(os.Stderr, "Found %d vulnerabilities\n", len(checkResult.Findings))
		}

		// Output results
		if vexOutput {
			vexDoc, err := sbom.GenerateVEX(components, checkResult.VulnDetails)
			if err != nil {
				return fmt.Errorf("generating VEX document: %w", err)
			}

			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			return encoder.Encode(vexDoc)
		}

		result := &model.SBOMResult{
			File:            filePath,
			TotalComponents: checkResult.TotalComponents,
			Findings:        checkResult.Findings,
		}

		if len(checkResult.Findings) == 0 {
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

func init() {
	sbomCheckCmd.Flags().Bool("vex", false, "Output an OpenVEX document instead of a table")
	sbomCheckCmd.Flags().String("ecosystem", "", "Filter components by ecosystem (npm, pip, maven, go, etc.)")
	sbomCheckCmd.Flags().String("severity", "", "Filter results by severity (critical, high, medium, low)")

	sbomCmd.AddCommand(sbomCheckCmd)
	rootCmd.AddCommand(sbomCmd)
}
