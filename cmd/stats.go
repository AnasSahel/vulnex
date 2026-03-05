package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/api/nvd"
	"github.com/trustin-tech/vulnex/internal/model"
)

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Vulnerability statistics",
	Long: `Query NVD and aggregate vulnerability statistics by month, CWE, or vendor.
Results are displayed as a simple text table with counts.`,
	Example: `  vulnex stats --year 2024
  vulnex stats --group-by cwe --year 2024 --limit 10
  vulnex stats --group-by month --year 2024
  vulnex stats --group-by vendor --vendor "apache" --year 2024`,
	RunE: func(cmd *cobra.Command, args []string) error {
		groupBy, _ := cmd.Flags().GetString("group-by")
		year, _ := cmd.Flags().GetString("year")
		vendor, _ := cmd.Flags().GetString("vendor")
		limit, _ := cmd.Flags().GetInt("limit")
		severity, _ := cmd.Flags().GetString("severity")
		quiet, _ := cmd.Flags().GetBool("quiet")
		noColor, _ := cmd.Flags().GetBool("no-color")

		s := newCmdStyles(noColor)

		// Build search parameters
		params := nvd.SearchParams{
			NoRejected:     true,
			ResultsPerPage: 2000, // NVD max per page
		}

		if year != "" {
			params.PubStartDate = year + "-01-01T00:00:00.000"
			params.PubEndDate = year + "-12-31T23:59:59.999"
		}

		if severity != "" {
			params.CvssV3Severity = strings.ToUpper(severity)
		}

		if vendor != "" && groupBy != "vendor" {
			params.KeywordSearch = vendor
		}

		if vendor != "" && groupBy == "vendor" {
			params.KeywordSearch = vendor
		}

		result, err := app.NVD.SearchCVEs(cmd.Context(), params)
		if err != nil {
			return fmt.Errorf("querying NVD: %w", err)
		}

		if !quiet {
			fmt.Fprintf(os.Stderr, "Fetched %d of %d total CVEs\n", len(result.CVEs), result.TotalResults)
		}

		if len(result.CVEs) == 0 {
			fmt.Fprintln(os.Stderr, "No results found")
			return nil
		}

		// Aggregate by the specified grouping
		switch groupBy {
		case "month":
			return printMonthStats(s, result.CVEs, limit)
		case "cwe":
			return printCWEStats(s, result.CVEs, limit)
		case "vendor":
			return printVendorStats(s, result.CVEs, limit)
		default:
			return printSeverityStats(s, result.CVEs)
		}
	},
}

// statEntry holds a label and count for display.
type statEntry struct {
	Label string
	Count int
}

// printMonthStats groups CVEs by publication month and prints counts.
func printMonthStats(s cmdStyles, cves []*model.EnrichedCVE, limit int) error {
	counts := make(map[string]int)
	for _, cve := range cves {
		if cve.Published.IsZero() {
			continue
		}
		key := cve.Published.Format("2006-01")
		counts[key]++
	}

	entries := sortedEntries(counts)
	// Sort months chronologically
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Label < entries[j].Label
	})

	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}

	printStyledTable(s, "Month", "CVEs", entries, false)
	return nil
}

// printCWEStats groups CVEs by CWE classification and prints counts.
func printCWEStats(s cmdStyles, cves []*model.EnrichedCVE, limit int) error {
	counts := make(map[string]int)
	for _, cve := range cves {
		if len(cve.CWEs) == 0 {
			counts["(none)"]++
			continue
		}
		for _, cwe := range cve.CWEs {
			label := cwe.ID
			if cwe.Description != "" {
				label = cwe.ID + " " + cwe.Description
			}
			counts[label]++
		}
	}

	entries := sortedEntries(counts)

	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}

	printStyledTable(s, "CWE", "CVEs", entries, false)
	return nil
}

// printVendorStats groups CVEs by CPE vendor and prints counts.
func printVendorStats(s cmdStyles, cves []*model.EnrichedCVE, limit int) error {
	counts := make(map[string]int)
	for _, cve := range cves {
		if len(cve.CPEs) == 0 {
			counts["(unknown)"]++
			continue
		}
		// Extract vendor from the first vulnerable CPE
		vendors := make(map[string]bool)
		for _, cpe := range cve.CPEs {
			if !cpe.Vulnerable {
				continue
			}
			v := vendorFromCPE(cpe.CPE23URI)
			if v != "" && !vendors[v] {
				vendors[v] = true
				counts[v]++
			}
		}
		if len(vendors) == 0 {
			counts["(unknown)"]++
		}
	}

	entries := sortedEntries(counts)

	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}

	printStyledTable(s, "Vendor", "CVEs", entries, false)
	return nil
}

// printSeverityStats groups CVEs by CVSS severity and prints counts.
// This is the default grouping when no --group-by is specified.
func printSeverityStats(s cmdStyles, cves []*model.EnrichedCVE) error {
	counts := make(map[string]int)
	for _, cve := range cves {
		sev := cve.Severity()
		counts[sev]++
	}

	// Display severities in a fixed order
	order := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"}
	entries := make([]statEntry, 0)
	for _, sev := range order {
		if c, ok := counts[sev]; ok {
			entries = append(entries, statEntry{Label: sev, Count: c})
		}
	}

	printStyledTable(s, "Severity", "CVEs", entries, true)
	return nil
}

// vendorFromCPE extracts the vendor field from a CPE 2.3 URI string.
// Format: cpe:2.3:<part>:<vendor>:<product>:<version>:...
func vendorFromCPE(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 {
		return ""
	}
	return parts[3]
}

// sortedEntries converts a count map to a sorted slice (descending by count).
func sortedEntries(counts map[string]int) []statEntry {
	entries := make([]statEntry, 0, len(counts))
	for label, count := range counts {
		entries = append(entries, statEntry{Label: label, Count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count != entries[j].Count {
			return entries[i].Count > entries[j].Count
		}
		return entries[i].Label < entries[j].Label
	})
	return entries
}

// printStyledTable renders a two-column text table with styled headers.
// When colorLabels is true, labels are colored using severity styling.
func printStyledTable(s cmdStyles, header1, header2 string, entries []statEntry, colorLabels bool) {
	if len(entries) == 0 {
		return
	}

	// Find the longest label for column sizing
	maxLabel := len(header1)
	for _, e := range entries {
		if len(e.Label) > maxLabel {
			maxLabel = len(e.Label)
		}
	}

	// Print header
	fmt.Fprintf(os.Stdout, "%s  %s\n",
		styledPadCmd(header1, maxLabel, s.header),
		s.header.Render(header2))

	// Print rows
	for _, e := range entries {
		label := e.Label
		if colorLabels {
			label = styledPadCmd(e.Label, maxLabel, s.severity(e.Label))
		} else {
			label = fmt.Sprintf("%-*s", maxLabel, e.Label)
		}
		fmt.Fprintf(os.Stdout, "%s  %d\n", label, e.Count)
	}

	// Print total
	total := 0
	for _, e := range entries {
		total += e.Count
	}
	fmt.Fprintf(os.Stdout, "\n%s %d\n", s.label.Render("Total:"), total)
}

func init() {
	statsCmd.Flags().String("group-by", "", "Group results by: month, cwe, vendor (default: severity)")
	statsCmd.Flags().String("year", "", "Filter by publication year (e.g., 2024)")
	statsCmd.Flags().String("vendor", "", "Filter by vendor keyword")
	statsCmd.Flags().String("severity", "", "Filter by CVSS v3 severity (LOW, MEDIUM, HIGH, CRITICAL)")
	statsCmd.Flags().Int("limit", 20, "Maximum rows to display")

	rootCmd.AddCommand(statsCmd)
}
