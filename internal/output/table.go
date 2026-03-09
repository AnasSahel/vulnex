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

// FormatKEVList renders a list of KEV entries as a plain space-aligned table.
func (tf *tableFormatter) FormatKEVList(w io.Writer, entries []model.KEVEntry) error {
	if len(entries) == 0 {
		fmt.Fprintln(w, "No KEV entries found.")
		return nil
	}

	const (
		colCVE    = 18
		colVendor = 16
		colProd   = 24
		colDate   = 12
	)

	fmt.Fprintf(w, "%s  %s  %s  %s  %s\n",
		styledPad("CVE ID", colCVE, tf.headerStyle),
		styledPad("Vendor", colVendor, tf.headerStyle),
		styledPad("Product", colProd, tf.headerStyle),
		styledPad("Added", colDate, tf.headerStyle),
		tf.headerStyle.Render("Ransomware"))

	for _, entry := range entries {
		product := entry.Product
		if len(product) > colProd {
			product = product[:colProd-3] + "..."
		}
		vendor := entry.VendorProject
		if len(vendor) > colVendor {
			vendor = vendor[:colVendor-3] + "..."
		}

		ransomware := entry.KnownRansomwareCampaign
		if strings.EqualFold(ransomware, "Known") && !tf.noColor {
			ransomware = tf.kevYesStyle.Render(ransomware)
		}

		fmt.Fprintf(w, "%-*s  %-*s  %-*s  %-*s  %s\n",
			colCVE, entry.CVEID,
			colVendor, vendor,
			colProd, product,
			colDate, entry.DateAdded,
			ransomware)
	}

	fmt.Fprintf(w, "\n%d entries\n", len(entries))
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

// wordWrap wraps text at word boundaries to fit within the given width.
// Each line is prefixed with the indent string.
func wordWrap(text, indent string, width int) string {
	maxLineLen := width - len(indent)
	if maxLineLen <= 0 {
		maxLineLen = width
	}

	var result strings.Builder
	for _, paragraph := range strings.Split(text, "\n") {
		if paragraph == "" {
			result.WriteString(indent)
			result.WriteByte('\n')
			continue
		}
		words := strings.Fields(paragraph)
		if len(words) == 0 {
			result.WriteString(indent)
			result.WriteByte('\n')
			continue
		}
		lineLen := 0
		result.WriteString(indent)
		for i, word := range words {
			wl := len(word)
			if i > 0 && lineLen+1+wl > maxLineLen {
				result.WriteByte('\n')
				result.WriteString(indent)
				lineLen = 0
			} else if i > 0 {
				result.WriteByte(' ')
				lineLen++
			}
			result.WriteString(word)
			lineLen += wl
		}
		result.WriteByte('\n')
	}
	return result.String()
}

// stripMarkdownHeadings converts markdown headings to plain bold-style labels.
func stripMarkdownHeadings(text string) string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			// Strip leading # characters and whitespace
			cleaned := strings.TrimLeft(trimmed, "#")
			cleaned = strings.TrimSpace(cleaned)
			if cleaned != "" {
				lines = append(lines, cleaned)
			}
		} else {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

// labelReference returns a tag label for a reference URL based on URL patterns.
func labelReference(url string) string {
	lower := strings.ToLower(url)
	switch {
	case strings.Contains(lower, "/commit/") || strings.Contains(lower, "/pull/"):
		return "[Patch]"
	case strings.Contains(lower, "nvd.nist.gov"):
		return "[NVD]"
	case strings.Contains(lower, "/advisories/") || strings.Contains(lower, "/security/"):
		return "[Advisory]"
	default:
		return ""
	}
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
	publishedDate := ""
	if adv.PublishedAt != "" {
		publishedDate = adv.PublishedAt
		if len(publishedDate) >= 10 {
			publishedDate = publishedDate[:10]
		}
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Published:"), tf.valueStyle.Render(publishedDate))
	}

	// Updated (only if truncated date differs from Published)
	if adv.UpdatedAt != "" {
		updatedDate := adv.UpdatedAt
		if len(updatedDate) >= 10 {
			updatedDate = updatedDate[:10]
		}
		if updatedDate != publishedDate {
			fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Updated:"), tf.valueStyle.Render(updatedDate))
		}
	}

	// Withdrawn
	if adv.WithdrawnAt != "" {
		withdrawn := adv.WithdrawnAt
		if len(withdrawn) >= 10 {
			withdrawn = withdrawn[:10]
		}
		fmt.Fprintf(w, "%s %s\n", tf.labelStyle.Render("Withdrawn:"), tf.criticalStyle.Render(withdrawn))
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
		desc := stripMarkdownHeadings(adv.Description)
		truncated := false
		if !tf.long && len(desc) > 300 {
			desc = desc[:297] + "..."
			truncated = true
		}
		fmt.Fprint(w, wordWrap(desc, "  ", 80))
		if truncated {
			fmt.Fprintf(w, "  %s\n", tf.noneStyle.Render("(use --long for full output)"))
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
				fix = "no fix"
			}

			versionInfo := fmt.Sprintf("fixed: %s", fix)
			if pkg.VulnerableRange != "" {
				versionInfo = fmt.Sprintf("%s, fixed: %s", pkg.VulnerableRange, fix)
			}

			fmt.Fprintf(w, "  %s/%s (%s)\n", tf.valueStyle.Render(pkg.Ecosystem), tf.headerStyle.Render(pkg.Name), versionInfo)
		}
	}

	// References
	if len(adv.References) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s\n", tf.headerStyle.Render("References"))
		for _, ref := range adv.References {
			label := labelReference(ref)
			if label != "" {
				fmt.Fprintf(w, "  %s %s\n", tf.noneStyle.Render(ref), tf.valueStyle.Render(label))
			} else {
				fmt.Fprintf(w, "  %s\n", tf.noneStyle.Render(ref))
			}
		}
	}

	return nil
}

// FormatAdvisories renders advisory data as a plain space-aligned table.
func (tf *tableFormatter) FormatAdvisories(w io.Writer, advisories []model.Advisory) error {
	if len(advisories) == 0 {
		fmt.Fprintln(w, "No advisories found.")
		return nil
	}

	const (
		colID       = 20
		colSeverity = 10
		colCVE      = 18
	)

	// Header
	fmt.Fprintf(w, "%s  %s  %s  %s\n",
		styledPad("GHSA ID", colID, tf.headerStyle),
		styledPad("Severity", colSeverity, tf.headerStyle),
		styledPad("CVE", colCVE, tf.headerStyle),
		tf.headerStyle.Render("Summary"))

	// Severity counts for footer
	severityCounts := map[string]int{}

	for _, adv := range advisories {
		sev := strings.ToUpper(adv.Severity)
		if sev == "" {
			sev = "UNKNOWN"
		}
		severityCounts[sev]++

		summary := adv.Summary
		if !tf.long {
			summary = truncate(summary, 50)
		}

		cve := adv.CVEID
		if cve == "" {
			cve = "-"
		}

		fmt.Fprintf(w, "%-*s  %s  %-*s  %s\n",
			colID, adv.ID,
			styledPad(sev, colSeverity, tf.severityStyle(sev)),
			colCVE, cve,
			summary)
	}

	// Footer with count and severity breakdown
	fmt.Fprintf(w, "\n%d advisories\n", len(advisories))

	sevOrder := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	var parts []string
	for _, sev := range sevOrder {
		if count, ok := severityCounts[sev]; ok {
			style := tf.severityStyle(sev)
			parts = append(parts, fmt.Sprintf("%s: %d", style.Render(sev), count))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, "  %s\n", strings.Join(parts, "  "))
	}

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

	// Severity counts and priority counts
	severityCounts := map[string]int{}
	actionRequired := 0 // P0 + P1
	canWait := 0        // P2 - P4
	var topFinding *model.SBOMFinding
	for i, f := range result.Findings {
		sev := strings.ToUpper(f.Advisory.Severity)
		if sev == "" {
			sev = "UNKNOWN"
		}
		severityCounts[sev]++

		if f.Risk != nil {
			switch f.Risk.Priority {
			case model.PriorityCritical, model.PriorityHigh:
				actionRequired++
				if topFinding == nil {
					topFinding = &result.Findings[i]
				}
			default:
				canWait++
			}
		}
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
			colEPSS     = 10
			colKEV      = 5
			colPriority = 15
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
					epssVal = fmt.Sprintf("%.1f%%", f.EPSS.Score*100)
					if f.EPSSTrend != nil {
						switch f.EPSSTrend.Direction {
						case "rising":
							epssVal += "↑"
						case "falling":
							epssVal += "↓"
						}
					}
				}

				kevStr := "—"
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

				// Inline policy failure marker
				if result.PolicyFailures != nil {
					if _, failed := result.PolicyFailures[f.Advisory.ID]; failed {
						priorityStr = "[FAIL] " + priorityStr
					}
				}

				fmt.Fprintf(w, "  %-*s %s %-*s %-*s %s %s %s\n",
					colID, f.Advisory.ID,
					styledPad(sev, colSeverity, style),
					colCVSS, cvss,
					colEPSS, epssVal,
					styledPad(kevStr, colKEV, kevStyle),
					styledPad(priorityStr, colPriority, priorityStyle),
					fixed)

				// Rationale line for P0 and P1 findings
				if f.Risk != nil && (f.Risk.Priority == model.PriorityCritical || f.Risk.Priority == model.PriorityHigh) && f.Risk.Rationale != "" {
					rationale := f.Risk.Rationale
					if f.EPSS != nil {
						rationale = fmt.Sprintf("%s, %.0f%% exploitation probability", rationale, f.EPSS.Score*100)
					}
					if fixed != "-" {
						rationale += ". Patch immediately."
					}
					fmt.Fprintf(w, "    → %s\n", rationale)
				}
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

	// Prioritization summary block (only when enriched)
	if enriched && (actionRequired > 0 || canWait > 0) {
		fmt.Fprintf(w, "\n%s\n", tf.headerStyle.Render("Prioritization"))

		if actionRequired > 0 {
			label := "P0+P1"
			if actionRequired == 1 {
				fmt.Fprintf(w, "  Action required    %d finding — patch immediately (%s)\n", actionRequired, label)
			} else {
				fmt.Fprintf(w, "  Action required    %d findings — patch immediately (%s)\n", actionRequired, label)
			}
		}

		if canWait > 0 {
			if canWait == 1 {
				fmt.Fprintf(w, "  Can wait           %d finding — low exploitation risk (P2-P4)\n", canWait)
			} else {
				fmt.Fprintf(w, "  Can wait           %d findings — low exploitation risk (P2-P4)\n", canWait)
			}
		}

		if topFinding != nil {
			fixInfo := ""
			if topFinding.Fixed != "" && topFinding.Fixed != "-" {
				fixInfo = fmt.Sprintf(" — upgrade to %s", topFinding.Fixed)
			}
			fmt.Fprintf(w, "  Top priority       %s in %s%s\n", topFinding.Advisory.ID, topFinding.Name, fixInfo)
		}
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

				fmt.Fprintf(w, "    %-26s %s %-9s %s\n",
					f.Advisory.ID,
					styledPad(sev, 10, style),
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

// FormatExploitResult renders a single exploit check result grouped by source with summary stats.
func (tf *tableFormatter) FormatExploitResult(w io.Writer, result *model.ExploitResult) error {
	if result == nil {
		return nil
	}

	// Header
	header := fmt.Sprintf("%s — %d known exploit(s)", result.CVEID, len(result.Exploits))
	fmt.Fprintf(w, "\n%s\n", tf.headerStyle.Render(header))

	if len(result.Exploits) == 0 {
		fmt.Fprintf(w, "\n  No known exploits found.\n")
		return nil
	}

	// Group by source
	groups := map[string][]model.ExploitRef{}
	for _, ref := range result.Exploits {
		groups[ref.Source] = append(groups[ref.Source], ref)
	}

	sourceOrder := []string{"github", "metasploit", "nuclei", "exploitdb"}
	sourceNames := map[string]string{
		"github": "GitHub", "metasploit": "Metasploit",
		"nuclei": "Nuclei", "exploitdb": "ExploitDB",
	}

	for _, src := range sourceOrder {
		refs, ok := groups[src]
		if !ok || len(refs) == 0 {
			continue
		}

		fmt.Fprintf(w, "\n  %s\n", tf.labelStyle.Render(fmt.Sprintf("%s (%d)", sourceNames[src], len(refs))))

		switch src {
		case "github":
			tf.formatGitHubGroup(w, refs)
		case "metasploit":
			tf.formatMetasploitGroup(w, refs)
		case "nuclei":
			tf.formatNucleiGroup(w, refs)
		case "exploitdb":
			tf.formatExploitDBGroup(w, refs)
		}
	}

	// Summary stats
	tf.formatExploitSummary(w, result.Exploits)

	return nil
}

func (tf *tableFormatter) formatGitHubGroup(w io.Writer, refs []model.ExploitRef) {
	for _, ref := range refs {
		name := ref.ID // full_name like "fullhunt/log4j-scan"
		if !tf.long {
			name = truncate(name, 30)
		}

		stars := ""
		if ref.Stars > 0 {
			stars = fmt.Sprintf("%s ★", formatStars(ref.Stars))
		}

		lang := ref.Language
		if lang == "" {
			lang = "-"
		}

		desc := ref.Description
		if desc == "" {
			desc = ""
		} else if !tf.long {
			desc = truncate(desc, 40)
		}

		fmt.Fprintf(w, "    %-32s %7s  %-8s %s\n", name, stars, lang, tf.noneStyle.Render(desc))
	}
}

func (tf *tableFormatter) formatMetasploitGroup(w io.Writer, refs []model.ExploitRef) {
	for _, ref := range refs {
		// Strip the type prefix from the path for display (show from platform onward)
		path := ref.ID
		parts := strings.SplitN(path, "/", 2)
		displayPath := path
		if len(parts) == 2 {
			displayPath = parts[1]
		}
		if !tf.long {
			displayPath = truncate(displayPath, 45)
		}

		modType := ref.ModuleType
		if modType == "" {
			modType = "-"
		}

		name := ref.Name
		if name == ref.ID {
			name = "" // don't repeat the path
		}
		if name != "" && !tf.long {
			name = truncate(name, 30)
		}

		typeStyle := tf.noneStyle
		if modType == "exploit" {
			typeStyle = tf.criticalStyle
		}

		fmt.Fprintf(w, "    %-47s %s  %s\n", displayPath, typeStyle.Render(fmt.Sprintf("%-11s", modType)), tf.noneStyle.Render(name))
	}
}

func (tf *tableFormatter) formatNucleiGroup(w io.Writer, refs []model.ExploitRef) {
	for _, ref := range refs {
		fmt.Fprintf(w, "    %-47s %s\n", ref.ID, tf.noneStyle.Render("detection template"))
	}
}

func (tf *tableFormatter) formatExploitDBGroup(w io.Writer, refs []model.ExploitRef) {
	for _, ref := range refs {
		platform := ref.Platform
		if platform == "" {
			platform = "-"
		}
		fmt.Fprintf(w, "    EDB-%-42s %s\n", ref.ID, tf.noneStyle.Render(platform))
	}
}

func (tf *tableFormatter) formatExploitSummary(w io.Writer, refs []model.ExploitRef) {
	// Weaponization level
	level, reason := exploitWeaponizationLevel(refs)

	// Breakdown: count exploit types
	var msfExploits, msfAux, githubCount, nucleiCount, edbCount int
	for _, ref := range refs {
		switch ref.Source {
		case "github":
			githubCount++
		case "metasploit":
			if ref.ModuleType == "exploit" {
				msfExploits++
			} else {
				msfAux++
			}
		case "nuclei":
			nucleiCount++
		case "exploitdb":
			edbCount++
		}
	}

	var breakdown []string
	if msfExploits > 0 {
		breakdown = append(breakdown, fmt.Sprintf("%d exploit modules", msfExploits))
	}
	if msfAux > 0 {
		breakdown = append(breakdown, fmt.Sprintf("%d scanners", msfAux))
	}
	if githubCount > 0 {
		breakdown = append(breakdown, fmt.Sprintf("%d PoC/tools", githubCount))
	}
	if nucleiCount > 0 {
		breakdown = append(breakdown, fmt.Sprintf("%d detection", nucleiCount))
	}
	if edbCount > 0 {
		breakdown = append(breakdown, fmt.Sprintf("%d ExploitDB", edbCount))
	}

	// Languages
	langCounts := map[string]int{}
	for _, ref := range refs {
		if ref.Language != "" {
			langCounts[ref.Language]++
		}
	}
	var langs []string
	// Sort by count desc
	for len(langCounts) > 0 {
		maxLang, maxCount := "", 0
		for lang, count := range langCounts {
			if count > maxCount {
				maxLang, maxCount = lang, count
			}
		}
		langs = append(langs, fmt.Sprintf("%s (%d)", maxLang, maxCount))
		delete(langCounts, maxLang)
	}

	// Most starred
	var topRepo string
	var topStars int
	for _, ref := range refs {
		if ref.Stars > topStars {
			topStars = ref.Stars
			topRepo = ref.ID
		}
	}

	// Render
	fmt.Fprintf(w, "\n  %s\n", tf.labelStyle.Render("Summary"))

	// Weaponization level with color
	levelStyle := tf.noneStyle
	switch level {
	case "CRITICAL":
		levelStyle = tf.criticalStyle
	case "HIGH":
		levelStyle = tf.highStyle
	case "MODERATE":
		levelStyle = tf.mediumStyle
	case "LOW":
		levelStyle = tf.lowStyle
	}
	fmt.Fprintf(w, "    %-17s%s — %s\n", tf.labelStyle.Render("Weaponization"), levelStyle.Render(level), reason)

	if len(breakdown) > 0 {
		fmt.Fprintf(w, "    %-17s%s\n", tf.labelStyle.Render("Breakdown"), strings.Join(breakdown, " · "))
	}
	if len(langs) > 0 {
		fmt.Fprintf(w, "    %-17s%s\n", tf.labelStyle.Render("Languages"), strings.Join(langs, " · "))
	}
	if topRepo != "" {
		fmt.Fprintf(w, "    %-17s%s (%s ★)\n", tf.labelStyle.Render("Most starred"), topRepo, formatStars(topStars))
	}

	fmt.Fprintln(w)
}

func exploitWeaponizationLevel(refs []model.ExploitRef) (string, string) {
	var hasMSFExploit, hasMSFAux bool
	var githubCount, maxStars int
	var hasNuclei, hasEDB bool

	for _, ref := range refs {
		switch ref.Source {
		case "metasploit":
			if ref.ModuleType == "exploit" {
				hasMSFExploit = true
			} else {
				hasMSFAux = true
			}
		case "github":
			githubCount++
			if ref.Stars > maxStars {
				maxStars = ref.Stars
			}
		case "nuclei":
			hasNuclei = true
		case "exploitdb":
			hasEDB = true
		}
	}

	if hasMSFExploit {
		return "CRITICAL", "Metasploit exploit modules available"
	}
	if hasMSFAux || (githubCount >= 3 && maxStars >= 500) {
		return "HIGH", "Multiple high-quality PoCs or scanners available"
	}
	if hasNuclei || githubCount > 0 {
		return "MODERATE", "Detection templates or PoCs available"
	}
	if hasEDB {
		return "LOW", "Limited exploit references"
	}
	return "LOW", "Minimal exploit evidence"
}

func formatStars(n int) string {
	if n >= 1000 {
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
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
	fmt.Fprintf(w, "%s %d\n", tf.labelStyle.Render("Snapshots:"), stats.SnapshotEntries)
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
