package cmd

import "github.com/spf13/cobra"

var cveCmd = &cobra.Command{
	Use:   "cve",
	Short: "CVE operations",
	Long:  "Search, list, and get detailed CVE information from NVD and other sources.",
}

func init() {
	rootCmd.AddCommand(cveCmd)
}
