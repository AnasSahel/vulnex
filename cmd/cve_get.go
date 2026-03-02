package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var cveGetCmd = &cobra.Command{
	Use:   "get <CVE-ID...>",
	Short: "Get enriched CVE details",
	Long:  "Fetch one or more CVEs with full enrichment from all data sources.",
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
			cve, err := app.Enricher.Enrich(ctx, ids[0])
			if err != nil {
				return err
			}
			return app.Formatter.FormatCVE(os.Stdout, cve)
		}

		cves, err := app.Enricher.EnrichBatch(ctx, ids)
		if err != nil {
			return err
		}
		return app.Formatter.FormatCVEList(os.Stdout, cves)
	},
}

func init() {
	cveGetCmd.Flags().Bool("stdin", false, "Read CVE IDs from stdin (one per line)")
	cveCmd.AddCommand(cveGetCmd)
}
