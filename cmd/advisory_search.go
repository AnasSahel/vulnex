package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/api/ghsa"
	"github.com/trustin-tech/vulnex/internal/model"
)

var advisorySearchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search security advisories",
	Long:  "Search GitHub Advisory Database for security advisories.",
	Example: `  vulnex advisory search "log4j"
  vulnex advisory search "xss" --ecosystem npm --severity critical`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ecosystem, _ := cmd.Flags().GetString("ecosystem")
		severity, _ := cmd.Flags().GetString("severity")
		advType, _ := cmd.Flags().GetString("type")
		limit, _ := cmd.Flags().GetInt("limit")

		params := ghsa.SearchParams{
			Query:     args[0],
			Ecosystem: ecosystem,
			Severity:  severity,
			Type:      advType,
			PerPage:   limit,
		}

		results, err := app.GHSA.Search(cmd.Context(), params)
		if err != nil {
			return err
		}

		// Convert to model.Advisory for formatter
		advisories := make([]model.Advisory, 0, len(results))
		for _, r := range results {
			advisories = append(advisories, model.Advisory{
				ID:       r.GHSAID,
				CVEID:    r.CVEID,
				Source:   "ghsa",
				URL:      r.URL,
				Severity: r.Severity,
				Summary:  r.Summary,
			})
		}

		return app.Formatter.FormatAdvisories(os.Stdout, advisories)
	},
}

func init() {
	advisorySearchCmd.Flags().String("ecosystem", "", "Filter by ecosystem (npm, pip, maven, go, etc.)")
	advisorySearchCmd.Flags().String("severity", "", "Filter by severity (critical, high, medium, low)")
	advisorySearchCmd.Flags().String("type", "reviewed", "Advisory type (reviewed, malware, unreviewed)")
	advisorySearchCmd.Flags().Int("limit", 30, "Maximum results to return")
	advisoryCmd.AddCommand(advisorySearchCmd)
}
