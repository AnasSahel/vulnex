package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/model"
)

var advisoryAffectedCmd = &cobra.Command{
	Use:   "affected <package>",
	Short: "Find advisories affecting a package",
	Long:  "Search for security advisories that affect a specific package.",
	Example: `  vulnex advisory affected lodash --ecosystem npm
  vulnex advisory affected django --ecosystem pip --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ecosystem, _ := cmd.Flags().GetString("ecosystem")
		if ecosystem == "" {
			return cmd.Help()
		}

		results, err := app.GHSA.FindByPackage(cmd.Context(), ecosystem, args[0])
		if err != nil {
			return err
		}

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
	advisoryAffectedCmd.Flags().StringP("ecosystem", "e", "", "Package ecosystem (npm, pip, maven, go, etc.) (required)")
	_ = advisoryAffectedCmd.MarkFlagRequired("ecosystem")
	advisoryCmd.AddCommand(advisoryAffectedCmd)
}
