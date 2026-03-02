package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var kevListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all KEV entries",
	Long:  "List all entries in the CISA Known Exploited Vulnerabilities catalog.",
	Example: `  vulnex kev list
  vulnex kev list --output json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		entries, err := app.KEV.List(cmd.Context())
		if err != nil {
			return err
		}
		return app.Formatter.FormatKEVList(os.Stdout, entries)
	},
}

var kevRecentCmd = &cobra.Command{
	Use:   "recent",
	Short: "Show recently added KEV entries",
	Long:  "Show KEV entries added in the last N days.",
	Example: `  vulnex kev recent --days 7
  vulnex kev recent --days 30 --output csv`,
	RunE: func(cmd *cobra.Command, args []string) error {
		days, _ := cmd.Flags().GetInt("days")
		entries, err := app.KEV.Recent(cmd.Context(), days)
		if err != nil {
			return err
		}
		return app.Formatter.FormatKEVList(os.Stdout, entries)
	},
}

func init() {
	kevRecentCmd.Flags().Int("days", 7, "Number of days to look back")
	kevCmd.AddCommand(kevListCmd)
	kevCmd.AddCommand(kevRecentCmd)
}
