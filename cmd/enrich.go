package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var enrichCmd = &cobra.Command{
	Use:   "enrich <CVE-ID...>",
	Short: "Aggregate all data sources for CVE(s)",
	Long: `Enrich one or more CVEs with data from all available sources:
NVD, CISA KEV, EPSS, GitHub Advisory Database, and OSV.dev.

This is the flagship command that provides the most comprehensive
vulnerability intelligence view.`,
	Example: `  vulnex enrich CVE-2021-44228
  vulnex enrich CVE-2024-3094 CVE-2023-44228 --output json
  echo "CVE-2024-3094" | vulnex enrich --stdin --output table
  cat cves.txt | vulnex enrich --stdin --output csv > enriched.csv

  # Use a preset scoring profile
  vulnex enrich CVE-2024-3094 --scoring-profile exploit-focused

  # Custom weights: prioritize severity at 50%, exploit probability at 30%, known-exploited at 20%
  vulnex enrich CVE-2024-3094 --cvss-weight 0.5 --epss-weight 0.3 --kev-weight 0.2

  # Ignore CVSS entirely, score only on real-world exploitation evidence
  vulnex enrich CVE-2024-3094 --cvss-weight 0 --epss-weight 0.7 --kev-weight 0.3`,
	RunE: func(cmd *cobra.Command, args []string) error {
		start := time.Now()
		stdin, _ := cmd.Flags().GetBool("stdin")
		quiet, _ := cmd.Flags().GetBool("quiet")
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
			if !quiet {
				fmt.Fprintf(os.Stderr, "Completed in %s\n", time.Since(start).Round(time.Millisecond))
			}
			return app.Formatter.FormatCVE(os.Stdout, cve)
		}

		cves, err := app.Enricher.EnrichBatch(ctx, ids)
		if err != nil {
			return err
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "Completed in %s\n", time.Since(start).Round(time.Millisecond))
		}
		return app.Formatter.FormatCVEList(os.Stdout, cves)
	},
}

func init() {
	enrichCmd.Flags().Bool("stdin", false, "Read CVE IDs from stdin (one per line)")
	enrichCmd.Flags().String("scoring-profile", "", "Preset weight balance for scoring: default (balanced), exploit-focused, or severity-focused")
	enrichCmd.Flags().Float64("cvss-weight", 0, "How much severity (CVSS) influences the final score, from 0.0 (ignore) to 1.0 (full weight)")
	enrichCmd.Flags().Float64("epss-weight", 0, "How much exploit probability (EPSS) influences the final score, from 0.0 (ignore) to 1.0 (full weight)")
	enrichCmd.Flags().Float64("kev-weight", 0, "How much known-exploited status (KEV) influences the final score, from 0.0 (ignore) to 1.0 (full weight)")
	rootCmd.AddCommand(enrichCmd)
}
