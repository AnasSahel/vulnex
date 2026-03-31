package cmd

import "github.com/spf13/cobra"

var craCmd = &cobra.Command{
	Use:   "cra",
	Short: "EU Cyber Resilience Act compliance tools",
	Long:  "Tools for generating CRA evidence packs and readiness assessments.",
}

func init() {
	rootCmd.AddCommand(craCmd)
}
