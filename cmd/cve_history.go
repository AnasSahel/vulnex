package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/api/nvd"
)

var cveHistoryCmd = &cobra.Command{
	Use:   "history <CVE-ID>",
	Short: "Show CVE modification history",
	Long:  "Display the modification history of a CVE from NVD.",
	Example: `  vulnex cve history CVE-2021-44228
  vulnex cve history CVE-2024-3094 --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cveID := args[0]

		// Fetch the CVE with full details
		cve, err := app.NVD.GetCVE(cmd.Context(), cveID)
		if err != nil {
			return err
		}

		// Also search for change history via last modified date range
		params := nvd.SearchParams{
			KeywordSearch:  cveID,
			ResultsPerPage: 1,
		}

		result, err := app.NVD.SearchCVEs(cmd.Context(), params)
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, "CVE: %s\n", cve.ID)
		fmt.Fprintf(os.Stdout, "Status: %s\n", cve.Status)
		fmt.Fprintf(os.Stdout, "Published: %s\n", cve.Published.Format("2006-01-02 15:04:05 UTC"))
		fmt.Fprintf(os.Stdout, "Last Modified: %s\n", cve.LastModified.Format("2006-01-02 15:04:05 UTC"))

		if len(result.CVEs) > 0 && result.CVEs[0] != nil {
			r := result.CVEs[0]
			fmt.Fprintf(os.Stdout, "\nSource: %s\n", r.SourceID)
			if len(r.Tags) > 0 {
				fmt.Fprintf(os.Stdout, "Tags: %v\n", r.Tags)
			}
		}

		// Output CVSS history if multiple scores exist
		if len(cve.CVSS) > 1 {
			fmt.Fprintf(os.Stdout, "\nCVSS Score History:\n")
			for _, s := range cve.CVSS {
				fmt.Fprintf(os.Stdout, "  %s v%s: %.1f (%s) — Source: %s [%s]\n",
					s.Severity, s.Version, s.BaseScore, s.VectorString, s.Source, s.Type)
			}
		}

		outputFmt, _ := cmd.Flags().GetString("output")
		if outputFmt == "json" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(cve)
		}

		return nil
	},
}

func init() {
	cveCmd.AddCommand(cveHistoryCmd)
}
