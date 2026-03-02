package cmd

import "github.com/spf13/cobra"

var advisoryCmd = &cobra.Command{
	Use:   "advisory",
	Short: "Advisory database operations",
	Long:  "Search and retrieve security advisories from GitHub Advisory Database and OSV.",
}

func init() {
	rootCmd.AddCommand(advisoryCmd)
}
