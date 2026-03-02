package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var advisoryGetCmd = &cobra.Command{
	Use:   "get <GHSA-ID>",
	Short: "Get a specific advisory",
	Long:  "Retrieve detailed information about a specific GitHub Advisory.",
	Example: `  vulnex advisory get GHSA-jfh8-c2jp-5v3q
  vulnex advisory get GHSA-jfh8-c2jp-5v3q --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		advisory, err := app.GHSA.GetAdvisory(cmd.Context(), args[0])
		if err != nil {
			return err
		}

		if advisory == nil {
			return fmt.Errorf("advisory %s not found", args[0])
		}

		// For detailed single advisory, output as JSON since we have richer data
		// than the Advisory model captures
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(advisory)
	},
}

func init() {
	advisoryCmd.AddCommand(advisoryGetCmd)
}
