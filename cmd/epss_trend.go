package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/trustin-tech/vulnex/internal/api/epss"
)

var epssTrendCmd = &cobra.Command{
	Use:   "trend <CVE-ID>",
	Short: "Show EPSS score history over time",
	Long: `Display the EPSS score time-series for a CVE, showing how the
exploitation probability has changed over time.

Uses the FIRST.org EPSS API with scope=time-series to retrieve
historical score data.`,
	Example: `  vulnex epss trend CVE-2021-44228
  vulnex epss trend CVE-2024-3094 --output json
  vulnex epss trend CVE-2023-44228 --days 30`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cveID := args[0]
		days, _ := cmd.Flags().GetInt("days")
		outputFmt, _ := cmd.Flags().GetString("output")

		entries, err := app.EPSS.GetTimeSeries(cmd.Context(), cveID, days)
		if err != nil {
			return err
		}

		if len(entries) == 0 {
			fmt.Fprintf(os.Stderr, "No EPSS time-series data found for %s\n", cveID)
			return nil
		}

		switch outputFmt {
		case "json":
			return renderTimeSeriesJSON(os.Stdout, cveID, entries)
		default:
			return renderTimeSeriesTable(os.Stdout, cveID, entries)
		}
	},
}

func init() {
	epssTrendCmd.Flags().Int("days", 0, "Limit to the most recent N days (0 = all available)")
	epssCmd.AddCommand(epssTrendCmd)
}

// renderTimeSeriesTable prints the time-series data as a formatted table.
func renderTimeSeriesTable(w *os.File, cveID string, entries []epss.TimeSeriesEntry) error {
	fmt.Fprintf(w, "EPSS Score History: %s (%d data points)\n\n", cveID, len(entries))
	fmt.Fprintf(w, "%-12s  %10s  %10s\n", "DATE", "SCORE", "PERCENTILE")
	fmt.Fprintf(w, "%-12s  %10s  %10s\n", "----", "-----", "----------")

	for _, e := range entries {
		fmt.Fprintf(w, "%-12s  %10.6f  %10.6f\n", e.Date, e.Score, e.Percentile)
	}

	return nil
}

// renderTimeSeriesJSON prints the time-series data as JSON.
func renderTimeSeriesJSON(w *os.File, cveID string, entries []epss.TimeSeriesEntry) error {
	output := struct {
		CVEID   string                `json:"cve_id"`
		Count   int                   `json:"count"`
		Entries []epss.TimeSeriesEntry `json:"entries"`
	}{
		CVEID:   cveID,
		Count:   len(entries),
		Entries: entries,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}
