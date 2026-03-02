package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/model"
)

var epssTopCmd = &cobra.Command{
	Use:   "top [N]",
	Short: "Show top CVEs by EPSS score",
	Long:  "Display the top N CVEs ranked by EPSS exploitation probability.",
	Example: `  vulnex epss top
  vulnex epss top 50 --output json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		n := 10
		if len(args) > 0 {
			var err error
			n, err = strconv.Atoi(args[0])
			if err != nil || n <= 0 {
				return fmt.Errorf("invalid number: %s", args[0])
			}
		}

		entries, err := app.EPSS.Top(cmd.Context(), n)
		if err != nil {
			return err
		}

		// Convert to map for formatter
		scores := make(map[string]*model.EPSSScore, len(entries))
		for _, e := range entries {
			scores[e.CVEID] = &model.EPSSScore{
				Score:      e.Score,
				Percentile: e.Percentile,
				Date:       e.Date,
			}
		}

		return app.Formatter.FormatEPSSScores(os.Stdout, scores)
	},
}

func init() {
	epssCmd.AddCommand(epssTopCmd)
}
