package cmd

import (
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"
)

var kevStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show KEV catalog statistics",
	Long:  "Display statistics about the CISA KEV catalog.",
	RunE: func(cmd *cobra.Command, args []string) error {
		noColor, _ := cmd.Flags().GetBool("no-color")
		s := newCmdStyles(noColor)

		stats, err := app.KEV.Stats(cmd.Context())
		if err != nil {
			return err
		}

		fmt.Fprintln(os.Stdout, s.header.Render("KEV Catalog Statistics"))
		fmt.Fprintln(os.Stdout)
		fmt.Fprintf(os.Stdout, "%s %d\n", s.label.Render("Total entries:"), stats.TotalCount)
		fmt.Fprintf(os.Stdout, "%s %d\n", s.label.Render("Added (last 30d):"), stats.RecentCount)
		fmt.Fprintf(os.Stdout, "%s %d\n", s.label.Render("Ransomware:"), stats.RansomwareCount)

		// Sort vendors by count descending
		type vendorCount struct {
			vendor string
			count  int
		}
		var vendors []vendorCount
		for v, c := range stats.TopVendors {
			vendors = append(vendors, vendorCount{v, c})
		}
		sort.Slice(vendors, func(i, j int) bool {
			return vendors[i].count > vendors[j].count
		})

		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, s.header.Render("Top Vendors"))
		limit, _ := cmd.Flags().GetInt("top")
		for i, v := range vendors {
			if i >= limit {
				break
			}
			fmt.Fprintf(os.Stdout, "  %-30s %s\n", s.value.Render(v.vendor), s.muted.Render(fmt.Sprintf("%d", v.count)))
		}

		return nil
	},
}

func init() {
	kevStatsCmd.Flags().Int("top", 10, "Number of top vendors to show")
	kevCmd.AddCommand(kevStatsCmd)
}
