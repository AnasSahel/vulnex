package cmd

import "github.com/spf13/cobra"

var kevCmd = &cobra.Command{
	Use:   "kev",
	Short: "CISA KEV catalog operations",
	Long:  "Query the CISA Known Exploited Vulnerabilities catalog.",
}

func init() {
	rootCmd.AddCommand(kevCmd)
}
