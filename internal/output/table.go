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
	noColor        bool
	long           bool
	scoringProfile *model.ScoringProfile

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
		noColor:        opts.NoColor,
		long:           opts.Long,
		scoringProfile: opts.ScoringProfile,
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

// styledPad renders text with the given style, then pads with trailing spaces
// so the total visible width equals width. This avoids ANSI escape codes
// breaking fmt's %-Ns padding.
func styledPad(s string, width int, style lipgloss.Style) string {
	rendered := style.Render(s)
	pad := width - len(s)
	if pad <= 0 {
		return rendered
	}
	return rendered + strings.Repeat(" ", pad)
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
	desc := cve.Description()
	if !tf.long {
		desc = truncate(desc, 80)
	}
	fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Description:"), tf.valueStyle.Render(desc))

	// Published Date
	published := cve.Published.Format("2006-01-02")
	fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Published:"), tf.valueStyle.Render(published))

	// Last Modified Date (only if different from Published)
	if !cve.LastModified.IsZero() && cve.LastModified.Format("2006-01-02") != published {
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Last Modified:"), tf.valueStyle.Render(cve.LastModified.Format("2006-01-02")))
	}

	// CWE IDs
	if len(cve.CWEs) > 0 {
		cweIDs := make([]string, len(cve.CWEs))
		for i, cwe := range cve.CWEs {
			cweIDs[i] = cwe.ID
		}
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("CWEs:"), tf.valueStyle.Render(strings.Join(cweIDs, ", ")))
	}

	// Score conflicts
	if len(cve.ScoreConflicts) > 0 {
		fmt.Fprintln(w)
		for _, c := range cve.ScoreConflicts {
			msg := fmt.Sprintf("CVSS v%s conflict: NVD=%.1f vs CNA=%.1f (delta=%.1f, %s)",
				c.Version, c.NVDScore, c.CNAScore, c.Delta, c.Significance)
			fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Warning:"), tf.mediumStyle.Render(msg))
		}
	}

	// --- Enrichment sections (only shown when data is present) ---

	// Risk Score
	risk := model.ComputeRisk(cve)
	if risk.CVSSScore > 0 || risk.EPSSScore > 0 || risk.InKEV {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s %s (score: %.0f/100)\n", tf.labelStyle.Render("Risk Priority:"), tf.severityStyle(string(risk.Priority)).Render(string(risk.Priority)), risk.Score)
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Rationale:"), tf.valueStyle.Render(risk.Rationale))
		if risk.Disagreement != "" {
			fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Signal Conflict:"), tf.mediumStyle.Render(risk.Disagreement))
		}
	}

	// Weighted Score
	if tf.scoringProfile != nil {
		score := model.ComputeWeightedScore(*tf.scoringProfile, cve)
		fmt.Fprintf(w, "%s %.1f/100 (profile: %s, weights: CVSS=%.2f EPSS=%.2f KEV=%.2f)\n",
			tf.labelStyle.Render("Weighted Score:"),
			score,
			tf.scoringProfile.Name,
			tf.scoringProfile.CVSSWeight,
			tf.scoringProfile.EPSSWeight,
			tf.scoringProfile.KEVWeight)
	}

	// KEV details
	if cve.KEV != nil {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s\n", tf.headerStyle.Render("KEV Details"))
		if cve.KEV.VulnerabilityName != "" {
			fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Name:"), tf.valueStyle.Render(cve.KEV.VulnerabilityName))
		}
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Vendor:"), tf.valueStyle.Render(cve.KEV.VendorProject))
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Product:"), tf.valueStyle.Render(cve.KEV.Product))
		if cve.KEV.ShortDescription != "" {
			fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Description:"), tf.valueStyle.Render(cve.KEV.ShortDescription))
		}
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Date Added:"), tf.valueStyle.Render(cve.KEV.DateAdded))
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Due Date:"), tf.valueStyle.Render(cve.KEV.DueDate))
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Required Action:"), tf.valueStyle.Render(cve.KEV.RequiredAction))
		if cve.KEV.KnownRansomwareCampaign != "" {
			fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Ransomware:"), tf.valueStyle.Render(cve.KEV.KnownRansomwareCampaign))
		}
		if cve.KEV.Notes != "" {
			fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Notes:"), tf.valueStyle.Render(cve.KEV.Notes))
		}
	}

	// Advisories
	if len(cve.Advisories) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s\n", tf.headerStyle.Render("Advisories"))
		for _, adv := range cve.Advisories {
			sev := strings.ToUpper(adv.Severity)
			fmt.Fprintf(w, "  %s [%s] %s\n", tf.headerStyle.Render(adv.ID), tf.severityStyle(sev).Render(sev), adv.Summary)
			if adv.URL != "" {
				fmt.Fprintf(w, "    %s\n", tf.noneStyle.Render(adv.URL))
			}
		}
	}

	// Affected Packages
	if len(cve.AffectedPkgs) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s\n", tf.headerStyle.Render("Affected Packages"))
		for _, pkg := range cve.AffectedPkgs {
			fix := pkg.Fixed
			if fix == "" {
				fix = "no fix available"
			}
			fmt.Fprintf(w, "  %s/%s (fixed: %s)\n", tf.valueStyle.Render(pkg.Ecosystem), tf.headerStyle.Render(pkg.Name), fix)
		}
	}

	// Affected Versions (CPE matches)
	if len(cve.CPEs) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s\n", tf.headerStyle.Render("Affected Versions"))
		for _, cpe := range cve.CPEs {
			if !cpe.Vulnerable {
				continue
			}
			product := cpeProduct(cpe.CPE23URI)
			vRange := cpeVersionRange(cpe)
			fmt.Fprintf(w, "  %s %s\n", tf.headerStyle.Render(product), tf.valueStyle.Render(vRange))
		}
	}

	// References
	if len(cve.References) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s\n", tf.headerStyle.Render("References"))
		maxRefs := len(cve.References)
		if !tf.long && maxRefs > 5 {
			maxRefs = 5
		}
		for _, ref := range cve.References[:maxRefs] {
			tags := ""
			if len(ref.Tags) > 0 {
				tags = " [" + strings.Join(ref.Tags, ", ") + "]"
			}
			fmt.Fprintf(w, "  %s%s\n", tf.noneStyle.Render(ref.URL), tf.valueStyle.Render(tags))
		}
		if remaining := len(cve.References) - maxRefs; remaining > 0 {
			fmt.Fprintf(w, "  %s\n", tf.noneStyle.Render(fmt.Sprintf("(%d more...)", remaining)))
		}
	}

	// Data Sources
	if len(cve.DataSources) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Sources:"), tf.noneStyle.Render(strings.Join(cve.DataSources, ", ")))
	}

	return nil
}

// cpeProduct extracts the vendor:product from a CPE 2.3 URI.
func cpeProduct(cpe23 string) string {
	// cpe:2.3:a:vendor:product:version:...
	parts := strings.Split(cpe23, ":")
	if len(parts) >= 5 {
		return parts[3] + ":" + parts[4]
	}
	return cpe23
}

// cpeVersionRange builds a human-readable version range string from a CPEMatch.
func cpeVersionRange(cpe model.CPEMatch) string {
	var parts []string
	if cpe.VersionStartIncl != "" {
		parts = append(parts, ">= "+cpe.VersionStartIncl)
	}
	if cpe.VersionStartExcl != "" {
		parts = append(parts, "> "+cpe.VersionStartExcl)
	}
	if cpe.VersionEndIncl != "" {
		parts = append(parts, "<= "+cpe.VersionEndIncl)
	}
	if cpe.VersionEndExcl != "" {
		parts = append(parts, "< "+cpe.VersionEndExcl)
	}
	if len(parts) == 0 {
		// Try to extract version from CPE URI itself
		p := strings.Split(cpe.CPE23URI, ":")
		if len(p) >= 6 && p[5] != "*" && p[5] != "-" {
			return p[5]
		}
		return "all versions"
	}
	return strings.Join(parts, ", ")
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

		desc := cve.Description()
		if !tf.long {
			desc = truncate(desc, 50)
		}

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

// FormatAdvisory renders a single enriched advisory in a detailed key-value display.
func (tf *tableFormatter) FormatAdvisory(w io.Writer, adv *model.EnrichedAdvisory) error {
	severityStr := strings.ToUpper(adv.Severity)
	style := tf.severityStyle(severityStr)

	// Advisory ID
	fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Advisory:"), tf.headerStyle.Render(adv.ID))

	// CVE ID
	if adv.CVEID != "" {
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("CVE:"), tf.valueStyle.Render(adv.CVEID))
	}

	// Severity
	fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Severity:"), style.Render(severityStr))

	// CVSS Score
	if adv.CVSSScore > 0 {
		cvssStr := fmt.Sprintf("%.1f", adv.CVSSScore)
		if adv.CVSSVector != "" {
			cvssStr += fmt.Sprintf(" (%s)", adv.CVSSVector)
		}
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("CVSS Score:"), style.Render(cvssStr))
	}

	// EPSS Score
	if adv.EPSSScore > 0 {
		epssStr := fmt.Sprintf("%.5f (percentile: %.4f)", adv.EPSSScore, adv.EPSSPctile)
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("EPSS Score:"), tf.valueStyle.Render(epssStr))
	}

	// Published
	if adv.PublishedAt != "" {
		published := adv.PublishedAt
		if len(published) >= 10 {
			published = published[:10]
		}
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Published:"), tf.valueStyle.Render(published))
	}

	// Updated
	if adv.UpdatedAt != "" && adv.UpdatedAt != adv.PublishedAt {
		updated := adv.UpdatedAt
		if len(updated) >= 10 {
			updated = updated[:10]
		}
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Updated:"), tf.valueStyle.Render(updated))
	}

	// Withdrawn
	if adv.WithdrawnAt != "" {
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Withdrawn:"), tf.criticalStyle.Render(adv.WithdrawnAt[:10]))
	}

	// URL
	if adv.URL != "" {
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("URL:"), tf.noneStyle.Render(adv.URL))
	}

	// Summary
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s\n", tf.headerStyle.Render("Summary"))
	fmt.Fprintf(w, "  %s\n", tf.valueStyle.Render(adv.Summary))

	// Description
	if adv.Description != "" {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s\n", tf.headerStyle.Render("Description"))
		desc := adv.Description
		if !tf.long && len(desc) > 300 {
			desc = desc[:297] + "..."
		}
		// Wrap lines for readability
		for _, line := range strings.Split(desc, "\n") {
			fmt.Fprintf(w, "  %s\n", tf.valueStyle.Render(line))
		}
	}

	// CWEs
	if len(adv.CWEs) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s\n", tf.headerStyle.Render("Weaknesses (CWE)"))
		for _, cwe := range adv.CWEs {
			if cwe.Description != "" {
				fmt.Fprintf(w, "  %s: %s\n", tf.headerStyle.Render(cwe.ID), tf.valueStyle.Render(cwe.Description))
			} else {
				fmt.Fprintf(w, "  %s\n", tf.headerStyle.Render(cwe.ID))
			}
		}
	}

	// Affected Packages
	if len(adv.Packages) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s\n", tf.headerStyle.Render("Affected Packages"))
		for _, pkg := range adv.Packages {
			fix := pkg.Fixed
			if fix == "" {
				fix = "no fix available"
			}
			fmt.Fprintf(w, "  %s/%s (fixed: %s)\n", tf.valueStyle.Render(pkg.Ecosystem), tf.headerStyle.Render(pkg.Name), fix)
		}
	}

	// References
	if len(adv.References) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s\n", tf.headerStyle.Render("References"))
		for _, ref := range adv.References {
			fmt.Fprintf(w, "  %s\n", tf.noneStyle.Render(ref))
		}
	}

	return nil
}

// FormatAdvisories renders advisory data as a table.
func (tf *tableFormatter) FormatAdvisories(w io.Writer, advisories []model.Advisory) error {
	headers := []string{"ID", "Source", "Severity", "Summary"}

	rows := make([][]string, 0, len(advisories))
	for _, adv := range advisories {
		severity := adv.Severity
		style := tf.severityStyle(severity)

		summary := adv.Summary
		if !tf.long {
			summary = truncate(summary, 60)
		}

		rows = append(rows, []string{
			adv.ID,
			adv.Source,
			style.Render(strings.ToUpper(severity)),
			summary,
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

// FormatSBOMResult renders SBOM check results grouped by component.
func (tf *tableFormatter) FormatSBOMResult(w io.Writer, result *model.SBOMResult) error {
	if len(result.Findings) == 0 {
		return nil
	}

	// Detect if findings have enrichment data
	enriched := len(result.Findings) > 0 && result.Findings[0].EPSS != nil

	// Group findings by component key (ecosystem/name@version)
	type componentKey struct {
		ecosystem, name, version string
	}
	var order []componentKey
	groups := make(map[componentKey][]model.SBOMFinding)
	for _, f := range result.Findings {
		key := componentKey{f.Ecosystem, f.Name, f.Version}
		if _, exists := groups[key]; !exists {
			order = append(order, key)
		}
		groups[key] = append(groups[key], f)
	}

	// Severity counts
	severityCounts := map[string]int{}
	for _, f := range result.Findings {
		sev := strings.ToUpper(f.Advisory.Severity)
		if sev == "" {
			sev = "UNKNOWN"
		}
		severityCounts[sev]++
	}

	// Render each component group using plain formatted text
	vulnerableComponents := len(order)
	for _, key := range order {
		findings := groups[key]
		header := fmt.Sprintf("%s %s (%s)", key.name, key.version, key.ecosystem)
		fmt.Fprintf(w, "\n%s\n", tf.headerStyle.Render(header))

		// Column widths
		const (
			colID       = 20
			colSeverity = 10
			colCVSS     = 6
			colEPSS     = 8
			colKEV      = 5
			colPriority = 13
			colFixed    = 9
		)

		// Print column headers
		if enriched {
			fmt.Fprintf(w, "  %s %s %s %s %s %s %s\n",
				styledPad("ID", colID, tf.headerStyle),
				styledPad("Severity", colSeverity, tf.headerStyle),
				styledPad("CVSS", colCVSS, tf.headerStyle),
				styledPad("EPSS", colEPSS, tf.headerStyle),
				styledPad("KEV", colKEV, tf.headerStyle),
				styledPad("Priority", colPriority, tf.headerStyle),
				tf.headerStyle.Render("Fixed"))
		} else {
			fmt.Fprintf(w, "  %s %s %s %s\n",
				styledPad("ID", colID, tf.headerStyle),
				styledPad("Severity", colSeverity, tf.headerStyle),
				styledPad("Fixed", colFixed, tf.headerStyle),
				tf.headerStyle.Render("Summary"))
		}

		for _, f := range findings {
			sev := strings.ToUpper(f.Advisory.Severity)
			if sev == "" {
				sev = "UNKNOWN"
			}
			style := tf.severityStyle(sev)

			fixed := f.Fixed
			if fixed == "" {
				fixed = "-"
			}
			if len(fixed) > 8 {
				fixed = fixed[:7] + "~"
			}

			if enriched {
				cvss := "N/A"
				if f.CVSSScore > 0 {
					cvss = fmt.Sprintf("%.1f", f.CVSSScore)
				}

				epssVal := "N/A"
				if f.EPSS != nil {
					epssVal = fmt.Sprintf("%.4f", f.EPSS.Score)
					if f.EPSSTrend != nil {
						switch f.EPSSTrend.Direction {
						case "rising":
							epssVal += "↑"
						case "falling":
							epssVal += "↓"
						}
					}
				}

				kevStr := "-"
				kevStyle := lipgloss.NewStyle()
				if f.KEV != nil {
					kevStr = "YES"
					kevStyle = tf.kevYesStyle
				}

				priorityStr := "-"
				priorityStyle := lipgloss.NewStyle()
				if f.Risk != nil {
					priorityStr = string(f.Risk.Priority)
					priorityStyle = tf.severityStyle(priorityStr)
				}

				fmt.Fprintf(w, "  %-*s %s %-*s %-*s %s %s %s\n",
					colID, f.Advisory.ID,
					styledPad(sev, colSeverity, style),
					colCVSS, cvss,
					colEPSS, epssVal,
					styledPad(kevStr, colKEV, kevStyle),
					styledPad(priorityStr, colPriority, priorityStyle),
					fixed)
			} else {
				summary := f.Advisory.Summary
				if !tf.long {
					summary = truncate(summary, 50)
				}

				fmt.Fprintf(w, "  %-*s %s %-*s %s\n",
					colID, f.Advisory.ID,
					styledPad(sev, colSeverity, style),
					colFixed, fixed,
					summary)
			}
		}
	}

	// Summary footer
	fmt.Fprintf(w, "\nSummary: %d components scanned, %d vulnerable, %d findings\n",
		result.TotalComponents, vulnerableComponents, len(result.Findings))

	// Severity breakdown
	sevOrder := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	parts := make([]string, 0)
	for _, sev := range sevOrder {
		if count, ok := severityCounts[sev]; ok {
			style := tf.severityStyle(sev)
			parts = append(parts, fmt.Sprintf("%s: %d", style.Render(sev), count))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, "  %s\n", strings.Join(parts, "  "))
	}

	if len(result.Suppressed) > 0 {
		fmt.Fprintf(w, "  Suppressed: %d (use --strict to show all)\n", len(result.Suppressed))
	}

	return nil
}

// FormatSBOMDiffResult renders the diff between two SBOM scans grouped by status.
func (tf *tableFormatter) FormatSBOMDiffResult(w io.Writer, result *model.SBOMDiffResult) error {
	sections := []struct {
		prefix   string
		label    string
		findings []model.SBOMFinding
	}{
		{"+", "ADDED", result.Added},
		{"-", "REMOVED", result.Removed},
		{"=", "UNCHANGED", result.Unchanged},
	}

	for _, sec := range sections {
		if len(sec.findings) == 0 {
			continue
		}

		sectionHeader := fmt.Sprintf("%s %s (%d vulnerabilities)", sec.prefix, sec.label, len(sec.findings))
		fmt.Fprintf(w, "\n%s\n", tf.headerStyle.Render(sectionHeader))

		// Group findings by component
		type componentKey struct {
			ecosystem, name, version string
		}
		var order []componentKey
		groups := make(map[componentKey][]model.SBOMFinding)
		for _, f := range sec.findings {
			key := componentKey{f.Ecosystem, f.Name, f.Version}
			if _, exists := groups[key]; !exists {
				order = append(order, key)
			}
			groups[key] = append(groups[key], f)
		}

		for _, key := range order {
			findings := groups[key]
			header := fmt.Sprintf("  %s %s (%s)", key.name, key.version, key.ecosystem)
			fmt.Fprintf(w, "%s\n", tf.headerStyle.Render(header))

			for _, f := range findings {
				sev := strings.ToUpper(f.Advisory.Severity)
				if sev == "" {
					sev = "UNKNOWN"
				}
				style := tf.severityStyle(sev)

				fixed := f.Fixed
				if fixed == "" {
					fixed = "-"
				}
				if len(fixed) > 8 {
					fixed = fixed[:7] + "~"
				}

				summary := f.Advisory.Summary
				if !tf.long {
					summary = truncate(summary, 50)
				}

				fmt.Fprintf(w, "    %-26s%-10s%-9s%s\n",
					f.Advisory.ID,
					style.Render(sev),
					fixed,
					summary)
			}
		}
	}

	// Summary footer
	fmt.Fprintf(w, "\nSummary: old=%d components (%d vulns), new=%d components (%d vulns), +%d added, -%d removed\n",
		result.OldComponents, len(result.Removed)+len(result.Unchanged),
		result.NewComponents, len(result.Added)+len(result.Unchanged),
		len(result.Added), len(result.Removed))

	if len(result.Suppressed) > 0 {
		fmt.Fprintf(w, "  Suppressed: %d (use --strict to show all)\n", len(result.Suppressed))
	}

	return nil
}

// FormatExploitResult renders a single exploit check result as a styled table.
func (tf *tableFormatter) FormatExploitResult(w io.Writer, result *model.ExploitResult) error {
	if result == nil {
		return nil
	}

	// Header
	header := fmt.Sprintf("%s — %d known exploit(s)", result.CVEID, len(result.Exploits))
	fmt.Fprintf(w, "\n%s\n\n", tf.headerStyle.Render(header))

	if len(result.Exploits) == 0 {
		fmt.Fprintf(w, "  No known exploits found.\n")
		return nil
	}

	// Column headers
	fmt.Fprintf(w, "  %-13s%-50s%s\n",
		tf.headerStyle.Render("SOURCE"),
		tf.headerStyle.Render("NAME"),
		tf.headerStyle.Render("URL"))

	for _, ref := range result.Exploits {
		name := ref.Name
		if !tf.long {
			name = truncate(name, 47)
		}
		fmt.Fprintf(w, "  %-13s%-50s%s\n", ref.Source, name, ref.URL)
	}

	// Source breakdown footer
	counts := make(map[string]int)
	for _, ref := range result.Exploits {
		counts[ref.Source]++
	}
	order := []string{"github", "metasploit", "nuclei", "exploitdb"}
	names := map[string]string{
		"github": "GitHub", "metasploit": "Metasploit",
		"nuclei": "Nuclei", "exploitdb": "ExploitDB",
	}
	var parts []string
	for _, src := range order {
		if count, ok := counts[src]; ok {
			parts = append(parts, fmt.Sprintf("%s (%d)", names[src], count))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, "\n%s %s\n", tf.labelStyle.Render("Sources:"), tf.noneStyle.Render(strings.Join(parts, " \u00b7 ")))
	}

	return nil
}

// FormatExploitResults renders multiple exploit check results.
func (tf *tableFormatter) FormatExploitResults(w io.Writer, results []*model.ExploitResult) error {
	for _, result := range results {
		if result == nil {
			continue
		}
		if err := tf.FormatExploitResult(w, result); err != nil {
			return err
		}
	}
	return nil
}

// FormatCVEHistory renders the modification history of a CVE with styled output.
func (tf *tableFormatter) FormatCVEHistory(w io.Writer, cve *model.EnrichedCVE) error {
	// Header
	fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("CVE ID:"), tf.headerStyle.Render(cve.ID))
	fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Status:"), tf.valueStyle.Render(cve.Status))

	// Published
	fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Published:"), tf.valueStyle.Render(cve.Published.Format("2006-01-02")))

	// Last Modified
	if !cve.LastModified.IsZero() {
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Last Modified:"), tf.valueStyle.Render(cve.LastModified.Format("2006-01-02")))
	}

	// Source
	if cve.SourceID != "" {
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Source:"), tf.valueStyle.Render(cve.SourceID))
	}

	// Tags
	if len(cve.Tags) > 0 {
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Tags:"), tf.valueStyle.Render(strings.Join(cve.Tags, ", ")))
	}

	// CVSS Score History
	if len(cve.CVSS) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s\n", tf.headerStyle.Render("CVSS Score History"))

		// Column headers
		fmt.Fprintf(w, "  %s %s %s %s\n",
			styledPad("Version", 10, tf.headerStyle),
			styledPad("Severity", 12, tf.headerStyle),
			styledPad("Score", 8, tf.headerStyle),
			tf.headerStyle.Render("Source"))

		for _, s := range cve.CVSS {
			sev := strings.ToUpper(s.Severity)
			style := tf.severityStyle(sev)

			source := s.Source
			if s.Type != "" {
				source += " [" + s.Type + "]"
			}

			fmt.Fprintf(w, "  %-10s %s %-8s %s\n",
				"v"+s.Version,
				styledPad(sev, 12, style),
				fmt.Sprintf("%.1f", s.BaseScore),
				tf.valueStyle.Render(source))
		}
	}

	return nil
}

// FormatCacheStats renders cache statistics in a simple key-value format.
func (tf *tableFormatter) FormatCacheStats(w io.Writer, stats *cache.Stats) error {
	fmt.Fprintf(w, "%s %d\n", tf.labelStyle.Render("Total Entries:"), stats.TotalEntries)
	fmt.Fprintf(w, "%s %d\n", tf.labelStyle.Render("CVE Entries:"), stats.CVEEntries)
	fmt.Fprintf(w, "%s %d\n", tf.labelStyle.Render("KEV Entries:"), stats.KEVEntries)
	fmt.Fprintf(w, "%s %d\n", tf.labelStyle.Render("EPSS Entries:"), stats.EPSSEntries)
	fmt.Fprintf(w, "%s %d\n", tf.labelStyle.Render("Advisory Entries:"), stats.AdvisoryEntries)
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
