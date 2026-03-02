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
		stats, err := app.KEV.Stats(cmd.Context())
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, "KEV Catalog Statistics\n")
		fmt.Fprintf(os.Stdout, "======================\n")
		fmt.Fprintf(os.Stdout, "Total entries:          %d\n", stats.TotalCount)
		fmt.Fprintf(os.Stdout, "Added in last 30 days:  %d\n", stats.RecentCount)
		fmt.Fprintf(os.Stdout, "Ransomware-associated:  %d\n", stats.RansomwareCount)
		fmt.Fprintf(os.Stdout, "\nTop Vendors:\n")

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

		limit, _ := cmd.Flags().GetInt("top")
		for i, v := range vendors {
			if i >= limit {
				break
			}
			fmt.Fprintf(os.Stdout, "  %-30s %d\n", v.vendor, v.count)
		}

		return nil
	},
}

func init() {
	kevStatsCmd.Flags().Int("top", 10, "Number of top vendors to show")
	kevCmd.AddCommand(kevStatsCmd)
}
