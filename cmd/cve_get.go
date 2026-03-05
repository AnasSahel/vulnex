package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

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
  echo "CVE-2024-3094" | vulnex cve get --stdin

  # Score with a preset profile
  vulnex cve get CVE-2024-3094 --scoring-profile exploit-focused

  # Custom weights: severity 50%, exploit probability 30%, known-exploited 20%
  vulnex cve get CVE-2024-3094 --cvss-weight 0.5 --epss-weight 0.3 --kev-weight 0.2`,
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
			cve, err := app.NVD.GetCVE(ctx, ids[0])
			if err != nil {
				return err
			}
			if !quiet {
				fmt.Fprintf(os.Stderr, "Completed in %s\n", time.Since(start).Round(time.Millisecond))
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

		if !quiet {
			fmt.Fprintf(os.Stderr, "Completed in %s\n", time.Since(start).Round(time.Millisecond))
		}
		return app.Formatter.FormatCVEList(os.Stdout, cves)
	},
}

func init() {
	cveGetCmd.Flags().Bool("stdin", false, "Read CVE IDs from stdin (one per line)")
	cveGetCmd.Flags().String("scoring-profile", "", "Preset weight balance for scoring: default (balanced), exploit-focused, or severity-focused")
	cveGetCmd.Flags().Float64("cvss-weight", 0, "How much severity (CVSS) influences the final score, from 0.0 (ignore) to 1.0 (full weight)")
	cveGetCmd.Flags().Float64("epss-weight", 0, "How much exploit probability (EPSS) influences the final score, from 0.0 (ignore) to 1.0 (full weight)")
	cveGetCmd.Flags().Float64("kev-weight", 0, "How much known-exploited status (KEV) influences the final score, from 0.0 (ignore) to 1.0 (full weight)")
	cveCmd.AddCommand(cveGetCmd)
}
