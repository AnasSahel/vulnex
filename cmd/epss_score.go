package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var epssScoreCmd = &cobra.Command{
	Use:   "score <CVE-ID...>",
	Short: "Get EPSS scores for CVE(s)",
	Long:  "Fetch EPSS scores for one or more CVEs. Supports batched requests.",
	Example: `  vulnex epss score CVE-2024-3094
  vulnex epss score CVE-2024-3094 CVE-2023-44228 CVE-2021-44228
  cat cves.txt | vulnex epss score --stdin --output csv`,
	RunE: func(cmd *cobra.Command, args []string) error {
		stdin, _ := cmd.Flags().GetBool("stdin")
		ids := args

		if stdin {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && strings.HasPrefix(strings.ToUpper(line), "CVE-") {
					ids = append(ids, strings.ToUpper(line))
				}
			}
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("reading stdin: %w", err)
			}
		}

		if len(ids) == 0 {
			return fmt.Errorf("at least one CVE ID is required")
		}

		scores, err := app.EPSS.GetScores(cmd.Context(), ids)
		if err != nil {
			return err
		}

		return app.Formatter.FormatEPSSScores(os.Stdout, scores)
	},
}

func init() {
	epssScoreCmd.Flags().Bool("stdin", false, "Read CVE IDs from stdin (one per line)")
	epssCmd.AddCommand(epssScoreCmd)
}
