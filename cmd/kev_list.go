package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/model"
)

var kevListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all KEV entries",
	Long:  "List all entries in the CISA Known Exploited Vulnerabilities catalog.",
	Example: `  vulnex kev list
  vulnex kev list --limit 50
  vulnex kev list --limit 20 --offset 40
  vulnex kev list --ransomware
  vulnex kev list --output json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")
		outputFmt, _ := cmd.Flags().GetString("output")
		ransomware, _ := cmd.Flags().GetBool("ransomware")

		entries, err := app.KEV.List(cmd.Context())
		if err != nil {
			return err
		}

		if ransomware {
			entries = filterRansomware(entries)
		}

		// Pagination (table output only, structured formats get all data)
		if outputFmt == "" || outputFmt == "table" {
			total := len(entries)
			if offset > 0 {
				if offset >= total {
					fmt.Fprintf(os.Stderr, "Offset %d exceeds %d total entries\n", offset, total)
					return nil
				}
				entries = entries[offset:]
			}
			if limit > 0 && limit < len(entries) {
				entries = entries[:limit]
			}

			quiet, _ := cmd.Flags().GetBool("quiet")
			if !quiet {
				fmt.Fprintf(os.Stderr, "Showing %d of %d entries", len(entries), total)
				if offset > 0 {
					fmt.Fprintf(os.Stderr, " (offset %d)", offset)
				}
				fmt.Fprintln(os.Stderr)
			}
		}

		return app.Formatter.FormatKEVList(os.Stdout, entries)
	},
}

var kevRecentCmd = &cobra.Command{
	Use:   "recent",
	Short: "Show recently added KEV entries",
	Long:  "Show KEV entries added in the last N days.",
	Example: `  vulnex kev recent --days 7
  vulnex kev recent --days 30 --output csv
  vulnex kev recent --ransomware`,
	RunE: func(cmd *cobra.Command, args []string) error {
		days, _ := cmd.Flags().GetInt("days")
		ransomware, _ := cmd.Flags().GetBool("ransomware")
		entries, err := app.KEV.Recent(cmd.Context(), days)
		if err != nil {
			return err
		}
		if ransomware {
			entries = filterRansomware(entries)
		}
		return app.Formatter.FormatKEVList(os.Stdout, entries)
	},
}

func filterRansomware(entries []model.KEVEntry) []model.KEVEntry {
	var filtered []model.KEVEntry
	for _, e := range entries {
		if strings.EqualFold(e.KnownRansomwareCampaign, "Known") {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func init() {
	kevListCmd.Flags().Int("limit", 20, "Maximum entries to display (0 = all)")
	kevListCmd.Flags().Int("offset", 0, "Skip first N entries")
	kevListCmd.Flags().Bool("ransomware", false, "Show only entries with known ransomware campaigns")
	kevRecentCmd.Flags().Int("days", 7, "Number of days to look back")
	kevRecentCmd.Flags().Bool("ransomware", false, "Show only entries with known ransomware campaigns")
	kevCmd.AddCommand(kevListCmd)
	kevCmd.AddCommand(kevRecentCmd)
}
