package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/model"
)

var scoringCmd = &cobra.Command{
	Use:   "scoring",
	Short: "Show scoring profiles and priority thresholds",
	Long: `Display the built-in scoring profiles and risk priority thresholds
used to compute weighted vulnerability scores.

Profiles control how CVSS, EPSS, and KEV signals are weighted when
computing a composite score (0-100). Use --scoring-profile with
enrich or cve get to select a profile.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		profiles := []model.ScoringProfile{
			model.DefaultProfile(),
			model.ExploitFocusedProfile(),
			model.SeverityFocusedProfile(),
		}

		fmt.Fprintln(os.Stdout, "Scoring Profiles")
		fmt.Fprintln(os.Stdout, "================")
		fmt.Fprintln(os.Stdout)
		for _, p := range profiles {
			fmt.Fprintf(os.Stdout, "  %-20s CVSS=%.2f  EPSS=%.2f  KEV=%.2f\n",
				p.Name, p.CVSSWeight, p.EPSSWeight, p.KEVWeight)
		}

		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, "Risk Priority Thresholds")
		fmt.Fprintln(os.Stdout, "========================")
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, "  P0-CRITICAL   In CISA KEV (regardless of other scores)")
		fmt.Fprintln(os.Stdout, "  P1-HIGH       EPSS >= 0.7 OR CVSS >= 9.0")
		fmt.Fprintln(os.Stdout, "  P2-MEDIUM     EPSS >= 0.3 OR (CVSS >= 7.0 AND EPSS >= 0.1)")
		fmt.Fprintln(os.Stdout, "  P3-LOW        CVSS >= 7.0 but EPSS < 0.1")
		fmt.Fprintln(os.Stdout, "  P4-MINIMAL    CVSS < 7.0 AND EPSS < 0.1")
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, "Use --scoring-profile to select a profile, or --cvss-weight,")
		fmt.Fprintln(os.Stdout, "--epss-weight, --kev-weight to set custom weights.")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(scoringCmd)
}
