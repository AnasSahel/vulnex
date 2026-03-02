package cmd

import "github.com/spf13/cobra"

var epssCmd = &cobra.Command{
	Use:   "epss",
	Short: "EPSS score operations",
	Long:  "Query Exploit Prediction Scoring System (EPSS) scores.",
}

func init() {
	rootCmd.AddCommand(epssCmd)
}
