package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/api/nvd"
)

var cveListCmd = &cobra.Command{
	Use:   "list",
	Short: "List CVEs with filters",
	Long:  "List CVEs from NVD with pagination and optional severity/date filters.",
	Example: `  vulnex cve list --severity critical --limit 50
  vulnex cve list --start-date 2024-01-01 --end-date 2024-12-31`,
	RunE: func(cmd *cobra.Command, args []string) error {
		severity, _ := cmd.Flags().GetString("severity")
		startDate, _ := cmd.Flags().GetString("start-date")
		endDate, _ := cmd.Flags().GetString("end-date")
		noRejected, _ := cmd.Flags().GetBool("no-rejected")
		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")

		params := nvd.SearchParams{
			CvssV3Severity: severity,
			NoRejected:     noRejected,
			StartIndex:     offset,
			ResultsPerPage: limit,
		}

		if startDate != "" {
			params.PubStartDate = startDate + "T00:00:00.000"
		}
		if endDate != "" {
			params.PubEndDate = endDate + "T23:59:59.999"
		}

		result, err := app.NVD.SearchCVEs(cmd.Context(), params)
		if err != nil {
			return err
		}

		quiet, _ := cmd.Flags().GetBool("quiet")
		if !quiet {
			fmt.Fprintf(os.Stderr, "Showing %d of %d results (offset %d)\n", len(result.CVEs), result.TotalResults, offset)
		}

		return app.Formatter.FormatCVEList(os.Stdout, result.CVEs)
	},
}

func init() {
	cveListCmd.Flags().String("severity", "", "Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)")
	cveListCmd.Flags().String("start-date", "", "Publication start date (YYYY-MM-DD)")
	cveListCmd.Flags().String("end-date", "", "Publication end date (YYYY-MM-DD)")
	cveListCmd.Flags().Bool("no-rejected", true, "Exclude rejected CVEs")
	cveListCmd.Flags().Int("limit", 20, "Results per page")
	cveListCmd.Flags().Int("offset", 0, "Starting offset")
	cveCmd.AddCommand(cveListCmd)
}
