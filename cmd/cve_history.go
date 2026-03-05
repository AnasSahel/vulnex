package cmd

import (
	"encoding/json"
	"os"

	"github.com/spf13/cobra"
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

		outputFmt, _ := cmd.Flags().GetString("output")
		if outputFmt == "json" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(cve)
		}

		return app.Formatter.FormatCVEHistory(os.Stdout, cve)
	},
}

func init() {
	cveCmd.AddCommand(cveHistoryCmd)
}
