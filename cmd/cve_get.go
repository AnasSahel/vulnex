package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/model"
)

var cveGetCmd = &cobra.Command{
	Use:   "get <CVE-ID...>",
	Short: "Get CVE details from NVD",
	Long: `Fetch one or more CVEs from NVD only (no enrichment from other sources).
Use 'vulnex enrich' to get the full multi-source view.`,
	Example: `  vulnex cve get CVE-2021-44228
  vulnex cve get CVE-2024-3094 CVE-2023-44228 --output json
  echo "CVE-2024-3094" | vulnex cve get --stdin`,
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

		ctx := cmd.Context()

		if len(ids) == 1 {
			cve, err := app.NVD.GetCVE(ctx, ids[0])
			if err != nil {
				return err
			}
			return app.Formatter.FormatCVE(os.Stdout, cve)
		}

		var cves []*model.EnrichedCVE
		for _, id := range ids {
			cve, err := app.NVD.GetCVE(ctx, id)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: %s: %v\n", id, err)
				continue
			}
			cves = append(cves, cve)
		}

		return app.Formatter.FormatCVEList(os.Stdout, cves)
	},
}

func init() {
	cveGetCmd.Flags().Bool("stdin", false, "Read CVE IDs from stdin (one per line)")
	cveCmd.AddCommand(cveGetCmd)
}
