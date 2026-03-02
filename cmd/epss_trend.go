package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/trustin-tech/vulnex/internal/api/epss"
)

// TimeSeriesEntry represents a single EPSS score data point in a time series.
type TimeSeriesEntry struct {
	Date       string  `json:"date"`
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
}

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

		entries, err := fetchTimeSeries(cmd.Context(), cveID, days)
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

// fetchTimeSeries calls the EPSS API with scope=time-series to retrieve
// historical EPSS scores for the given CVE ID.
func fetchTimeSeries(ctx context.Context, cveID string, days int) ([]TimeSeriesEntry, error) {
	url := fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s&scope=time-series", cveID)

	resp, err := app.EPSS.HTTPClient().Get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetching EPSS time-series for %s: %w", cveID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EPSS API returned status %d for time-series request", resp.StatusCode)
	}

	var apiResp epss.Response
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decoding EPSS time-series response: %w", err)
	}

	entries := make([]TimeSeriesEntry, 0, len(apiResp.Data))
	for _, d := range apiResp.Data {
		score, err := strconv.ParseFloat(d.EPSS, 64)
		if err != nil {
			continue
		}
		percentile, err := strconv.ParseFloat(d.Percentile, 64)
		if err != nil {
			continue
		}
		entries = append(entries, TimeSeriesEntry{
			Date:       d.Date,
			Score:      score,
			Percentile: percentile,
		})
	}

	// Limit to most recent N days if requested.
	if days > 0 && len(entries) > days {
		entries = entries[len(entries)-days:]
	}

	return entries, nil
}

// renderTimeSeriesTable prints the time-series data as a formatted table.
func renderTimeSeriesTable(w *os.File, cveID string, entries []TimeSeriesEntry) error {
	fmt.Fprintf(w, "EPSS Score History: %s (%d data points)\n\n", cveID, len(entries))
	fmt.Fprintf(w, "%-12s  %10s  %10s\n", "DATE", "SCORE", "PERCENTILE")
	fmt.Fprintf(w, "%-12s  %10s  %10s\n", "----", "-----", "----------")

	for _, e := range entries {
		fmt.Fprintf(w, "%-12s  %10.6f  %10.6f\n", e.Date, e.Score, e.Percentile)
	}

	return nil
}

// renderTimeSeriesJSON prints the time-series data as JSON.
func renderTimeSeriesJSON(w *os.File, cveID string, entries []TimeSeriesEntry) error {
	output := struct {
		CVEID   string            `json:"cve_id"`
		Count   int               `json:"count"`
		Entries []TimeSeriesEntry `json:"entries"`
	}{
		CVEID:   cveID,
		Count:   len(entries),
		Entries: entries,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}
