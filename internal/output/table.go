package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/trustin-tech/vulnex/internal/cache"
	"github.com/trustin-tech/vulnex/internal/model"
)

// tableFormatter renders data as styled terminal tables using lipgloss.
type tableFormatter struct {
	noColor bool

	// Severity styles
	criticalStyle lipgloss.Style
	highStyle     lipgloss.Style
	mediumStyle   lipgloss.Style
	lowStyle      lipgloss.Style
	noneStyle     lipgloss.Style

	// KEV styles
	kevYesStyle lipgloss.Style
	kevNoStyle  lipgloss.Style

	// General styles
	headerStyle lipgloss.Style
	labelStyle  lipgloss.Style
	valueStyle  lipgloss.Style
}

func newTableFormatter(opts *formatterOpts) *tableFormatter {
	tf := &tableFormatter{
		noColor: opts.NoColor,
	}

	if opts.NoColor {
		tf.criticalStyle = lipgloss.NewStyle()
		tf.highStyle = lipgloss.NewStyle()
		tf.mediumStyle = lipgloss.NewStyle()
		tf.lowStyle = lipgloss.NewStyle()
		tf.noneStyle = lipgloss.NewStyle()
		tf.kevYesStyle = lipgloss.NewStyle()
		tf.kevNoStyle = lipgloss.NewStyle()
		tf.headerStyle = lipgloss.NewStyle().Bold(true)
		tf.labelStyle = lipgloss.NewStyle().Bold(true)
		tf.valueStyle = lipgloss.NewStyle()
	} else {
		tf.criticalStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)  // red bold
		tf.highStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))                 // red
		tf.mediumStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))              // yellow
		tf.lowStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))                 // green
		tf.noneStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))                 // gray
		tf.kevYesStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)    // red bold
		tf.kevNoStyle = lipgloss.NewStyle()
		tf.headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))   // blue bold
		tf.labelStyle = lipgloss.NewStyle().Bold(true).Width(16)
		tf.valueStyle = lipgloss.NewStyle()
	}

	return tf
}

// severityStyle returns the appropriate lipgloss style for a severity string.
func (tf *tableFormatter) severityStyle(severity string) lipgloss.Style {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return tf.criticalStyle
	case "HIGH":
		return tf.highStyle
	case "MEDIUM":
		return tf.mediumStyle
	case "LOW":
		return tf.lowStyle
	default:
		return tf.noneStyle
	}
}

// truncate shortens a string to the specified max length, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// FormatCVE renders a single enriched CVE in a detailed key-value display.
func (tf *tableFormatter) FormatCVE(w io.Writer, cve *model.EnrichedCVE) error {
	severityStr := cve.Severity()
	style := tf.severityStyle(severityStr)

	// CVE ID
	fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("CVE ID:"), tf.headerStyle.Render(cve.ID))

	// Severity
	fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Severity:"), style.Render(severityStr))

	// CVSS Score
	if score := cve.HighestScore(); score != nil {
		cvssStr := fmt.Sprintf("%.1f (v%s)", score.BaseScore, score.Version)
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("CVSS Score:"), style.Render(cvssStr))
	} else {
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("CVSS Score:"), tf.noneStyle.Render("N/A"))
	}

	// EPSS Score
	if cve.EPSS != nil {
		epssStr := fmt.Sprintf("%.5f (percentile: %.4f)", cve.EPSS.Score, cve.EPSS.Percentile)
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("EPSS Score:"), tf.valueStyle.Render(epssStr))
	} else {
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("EPSS Score:"), tf.noneStyle.Render("N/A"))
	}

	// KEV Status
	if cve.IsInKEV() {
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("KEV:"), tf.kevYesStyle.Render("YES"))
	} else {
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("KEV:"), tf.kevNoStyle.Render("No"))
	}

	// Description
	desc := truncate(cve.Description(), 80)
	fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Description:"), tf.valueStyle.Render(desc))

	// Published Date
	published := cve.Published.Format("2006-01-02")
	fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Published:"), tf.valueStyle.Render(published))

	// CWE IDs
	if len(cve.CWEs) > 0 {
		cweIDs := make([]string, len(cve.CWEs))
		for i, cwe := range cve.CWEs {
			cweIDs[i] = cwe.ID
		}
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("CWEs:"), tf.valueStyle.Render(strings.Join(cweIDs, ", ")))
	}

	return nil
}

// FormatCVEList renders a list of enriched CVEs as a table.
func (tf *tableFormatter) FormatCVEList(w io.Writer, cves []*model.EnrichedCVE) error {
	headers := []string{"CVE ID", "Severity", "CVSS", "EPSS", "KEV", "Description"}

	rows := make([][]string, 0, len(cves))
	for _, cve := range cves {
		severity := cve.Severity()
		style := tf.severityStyle(severity)

		cvss := "N/A"
		if score := cve.HighestScore(); score != nil {
			cvss = fmt.Sprintf("%.1f", score.BaseScore)
		}

		epss := "N/A"
		if cve.EPSS != nil {
			epss = fmt.Sprintf("%.5f", cve.EPSS.Score)
		}

		kev := "No"
		if cve.IsInKEV() {
			kev = tf.kevYesStyle.Render("YES")
		}

		desc := truncate(cve.Description(), 50)

		rows = append(rows, []string{
			cve.ID,
			style.Render(severity),
			cvss,
			epss,
			kev,
			desc,
		})
	}

	t := table.New().
		Headers(headers...).
		Rows(rows...).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return tf.headerStyle
			}
			return lipgloss.NewStyle()
		})

	fmt.Fprintln(w, t.Render())
	return nil
}

// FormatKEVList renders a list of KEV entries as a table.
func (tf *tableFormatter) FormatKEVList(w io.Writer, entries []model.KEVEntry) error {
	headers := []string{"CVE ID", "Vendor", "Product", "Date Added", "Due Date", "Ransomware"}

	rows := make([][]string, 0, len(entries))
	for _, entry := range entries {
		ransomware := entry.KnownRansomwareCampaign
		if strings.EqualFold(ransomware, "Known") && !tf.noColor {
			ransomware = tf.kevYesStyle.Render(ransomware)
		}

		rows = append(rows, []string{
			entry.CVEID,
			entry.VendorProject,
			entry.Product,
			entry.DateAdded,
			entry.DueDate,
			ransomware,
		})
	}

	t := table.New().
		Headers(headers...).
		Rows(rows...).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return tf.headerStyle
			}
			return lipgloss.NewStyle()
		})

	fmt.Fprintln(w, t.Render())
	return nil
}

// FormatEPSSScores renders EPSS scores as a table.
func (tf *tableFormatter) FormatEPSSScores(w io.Writer, scores map[string]*model.EPSSScore) error {
	headers := []string{"CVE ID", "EPSS Score", "Percentile", "Date"}

	rows := make([][]string, 0, len(scores))
	for cveID, score := range scores {
		rows = append(rows, []string{
			cveID,
			fmt.Sprintf("%.5f", score.Score),
			fmt.Sprintf("%.4f", score.Percentile),
			score.Date,
		})
	}

	t := table.New().
		Headers(headers...).
		Rows(rows...).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return tf.headerStyle
			}
			return lipgloss.NewStyle()
		})

	fmt.Fprintln(w, t.Render())
	return nil
}

// FormatAdvisories renders advisory data as a table.
func (tf *tableFormatter) FormatAdvisories(w io.Writer, advisories []model.Advisory) error {
	headers := []string{"ID", "Source", "Severity", "Summary"}

	rows := make([][]string, 0, len(advisories))
	for _, adv := range advisories {
		severity := adv.Severity
		style := tf.severityStyle(severity)

		rows = append(rows, []string{
			adv.ID,
			adv.Source,
			style.Render(strings.ToUpper(severity)),
			truncate(adv.Summary, 60),
		})
	}

	t := table.New().
		Headers(headers...).
		Rows(rows...).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return tf.headerStyle
			}
			return lipgloss.NewStyle()
		})

	fmt.Fprintln(w, t.Render())
	return nil
}

// FormatCacheStats renders cache statistics in a simple key-value format.
func (tf *tableFormatter) FormatCacheStats(w io.Writer, stats *cache.Stats) error {
	fmt.Fprintf(w, "%s %d\n", tf.labelStyle.Render("Total Entries:"), stats.TotalEntries)
	fmt.Fprintf(w, "%s %d\n", tf.labelStyle.Render("CVE Entries:"), stats.CVEEntries)
	fmt.Fprintf(w, "%s %d\n", tf.labelStyle.Render("KEV Entries:"), stats.KEVEntries)
	fmt.Fprintf(w, "%s %d\n", tf.labelStyle.Render("EPSS Entries:"), stats.EPSSEntries)
	fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Size:"), formatBytes(stats.SizeBytes))
	return nil
}

// formatBytes converts bytes to a human-readable string.
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
