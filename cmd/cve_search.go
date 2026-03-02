package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/api/nvd"
)

var cveSearchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search CVEs by keyword",
	Long:  "Search NVD for CVEs matching keywords with optional filters.",
	Example: `  vulnex cve search "apache log4j"
  vulnex cve search "remote code execution" --severity critical --has-kev
  vulnex cve search "fortinet" --year 2024 --output json`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		severity, _ := cmd.Flags().GetString("severity")
		hasKEV, _ := cmd.Flags().GetBool("has-kev")
		year, _ := cmd.Flags().GetString("year")
		cwe, _ := cmd.Flags().GetString("cwe")
		noRejected, _ := cmd.Flags().GetBool("no-rejected")
		limit, _ := cmd.Flags().GetInt("limit")

		params := nvd.SearchParams{
			KeywordSearch: args[0],
			CvssV3Severity: severity,
			HasKev:         hasKEV,
			CweID:          cwe,
			NoRejected:     noRejected,
			ResultsPerPage: limit,
		}

		if year != "" {
			params.PubStartDate = year + "-01-01T00:00:00.000"
			params.PubEndDate = year + "-12-31T23:59:59.999"
		}

		result, err := app.NVD.SearchCVEs(cmd.Context(), params)
		if err != nil {
			return err
		}

		quiet, _ := cmd.Flags().GetBool("quiet")
		if !quiet {
			fmt.Fprintf(os.Stderr, "Found %d results\n", result.TotalResults)
		}

		return app.Formatter.FormatCVEList(os.Stdout, result.CVEs)
	},
}

func init() {
	cveSearchCmd.Flags().String("severity", "", "Filter by CVSS v3 severity (LOW, MEDIUM, HIGH, CRITICAL)")
	cveSearchCmd.Flags().Bool("has-kev", false, "Only show CVEs in CISA KEV")
	cveSearchCmd.Flags().String("year", "", "Filter by publication year (e.g., 2024)")
	cveSearchCmd.Flags().String("cwe", "", "Filter by CWE ID (e.g., CWE-79)")
	cveSearchCmd.Flags().Bool("no-rejected", true, "Exclude rejected CVEs")
	cveSearchCmd.Flags().Int("limit", 20, "Maximum results to return")
	cveCmd.AddCommand(cveSearchCmd)
}
