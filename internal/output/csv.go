package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/trustin-tech/vulnex/internal/cache"
	"github.com/trustin-tech/vulnex/internal/model"
)

// Default field sets for CSV output.
var (
	defaultCVEFields  = []string{"id", "severity", "cvss_score", "epss_score", "epss_percentile", "kev", "description", "published"}
	defaultKEVFields  = []string{"cve_id", "vendor", "product", "date_added", "due_date", "ransomware", "description"}
	defaultEPSSFields = []string{"cve_id", "epss_score", "percentile", "date"}
)

// csvFormatter renders data as CSV output.
type csvFormatter struct {
	fields []string
}

func newCSVFormatter(opts *formatterOpts) *csvFormatter {
	return &csvFormatter{
		fields: opts.Fields,
	}
}

// effectiveFields returns the configured fields or falls back to defaults.
func (cf *csvFormatter) effectiveFields(defaults []string) []string {
	if len(cf.fields) > 0 {
		return cf.fields
	}
	return defaults
}

// FormatCVE renders a single enriched CVE as CSV (header + one data row).
func (cf *csvFormatter) FormatCVE(w io.Writer, cve *model.EnrichedCVE) error {
	return cf.FormatCVEList(w, []*model.EnrichedCVE{cve})
}

// FormatCVEList renders a list of enriched CVEs as CSV.
func (cf *csvFormatter) FormatCVEList(w io.Writer, cves []*model.EnrichedCVE) error {
	fields := cf.effectiveFields(defaultCVEFields)
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write header row
	if err := writer.Write(fields); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	// Write data rows
	for _, cve := range cves {
		row := make([]string, len(fields))
		for i, field := range fields {
			row[i] = cveFieldValue(cve, field)
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("writing CSV row: %w", err)
		}
	}

	return nil
}

// cveFieldValue extracts a string value for the given field name from an EnrichedCVE.
func cveFieldValue(cve *model.EnrichedCVE, field string) string {
	switch field {
	case "id":
		return cve.ID
	case "severity":
		return cve.Severity()
	case "cvss_score":
		if score := cve.HighestScore(); score != nil {
			return fmt.Sprintf("%.1f", score.BaseScore)
		}
		return ""
	case "cvss_version":
		if score := cve.HighestScore(); score != nil {
			return score.Version
		}
		return ""
	case "epss_score":
		if cve.EPSS != nil {
			return fmt.Sprintf("%.5f", cve.EPSS.Score)
		}
		return ""
	case "epss_percentile":
		if cve.EPSS != nil {
			return fmt.Sprintf("%.4f", cve.EPSS.Percentile)
		}
		return ""
	case "kev":
		if cve.IsInKEV() {
			return "true"
		}
		return "false"
	case "description":
		return cve.Description()
	case "published":
		return cve.Published.Format("2006-01-02")
	case "last_modified":
		return cve.LastModified.Format("2006-01-02")
	case "status":
		return cve.Status
	case "cwes":
		cweIDs := make([]string, len(cve.CWEs))
		for i, cwe := range cve.CWEs {
			cweIDs[i] = cwe.ID
		}
		return strings.Join(cweIDs, ";")
	default:
		return ""
	}
}

// FormatKEVList renders a list of KEV entries as CSV.
func (cf *csvFormatter) FormatKEVList(w io.Writer, entries []model.KEVEntry) error {
	fields := cf.effectiveFields(defaultKEVFields)
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write header row
	if err := writer.Write(fields); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	// Write data rows
	for _, entry := range entries {
		row := make([]string, len(fields))
		for i, field := range fields {
			row[i] = kevFieldValue(&entry, field)
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("writing CSV row: %w", err)
		}
	}

	return nil
}

// kevFieldValue extracts a string value for the given field name from a KEVEntry.
func kevFieldValue(entry *model.KEVEntry, field string) string {
	switch field {
	case "cve_id":
		return entry.CVEID
	case "vendor":
		return entry.VendorProject
	case "product":
		return entry.Product
	case "vulnerability_name":
		return entry.VulnerabilityName
	case "date_added":
		return entry.DateAdded
	case "due_date":
		return entry.DueDate
	case "ransomware":
		return entry.KnownRansomwareCampaign
	case "description":
		return entry.ShortDescription
	case "required_action":
		return entry.RequiredAction
	case "notes":
		return entry.Notes
	default:
		return ""
	}
}

// FormatEPSSScores renders EPSS scores as CSV.
func (cf *csvFormatter) FormatEPSSScores(w io.Writer, scores map[string]*model.EPSSScore) error {
	fields := cf.effectiveFields(defaultEPSSFields)
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write header row
	if err := writer.Write(fields); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	// Write data rows
	for cveID, score := range scores {
		row := make([]string, len(fields))
		for i, field := range fields {
			row[i] = epssFieldValue(cveID, score, field)
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("writing CSV row: %w", err)
		}
	}

	return nil
}

// epssFieldValue extracts a string value for the given field name from an EPSS score.
func epssFieldValue(cveID string, score *model.EPSSScore, field string) string {
	switch field {
	case "cve_id":
		return cveID
	case "epss_score":
		return fmt.Sprintf("%.5f", score.Score)
	case "percentile":
		return fmt.Sprintf("%.4f", score.Percentile)
	case "date":
		return score.Date
	default:
		return ""
	}
}

// FormatAdvisory renders a single enriched advisory as CSV.
func (cf *csvFormatter) FormatAdvisory(w io.Writer, advisory *model.EnrichedAdvisory) error {
	headers := []string{"id", "cve_id", "severity", "cvss_score", "epss_score", "published", "url", "summary"}
	writer := csv.NewWriter(w)
	defer writer.Flush()

	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	cvss := ""
	if advisory.CVSSScore > 0 {
		cvss = fmt.Sprintf("%.1f", advisory.CVSSScore)
	}
	epss := ""
	if advisory.EPSSScore > 0 {
		epss = fmt.Sprintf("%.5f", advisory.EPSSScore)
	}
	published := advisory.PublishedAt
	if len(published) >= 10 {
		published = published[:10]
	}

	row := []string{
		advisory.ID,
		advisory.CVEID,
		advisory.Severity,
		cvss,
		epss,
		published,
		advisory.URL,
		advisory.Summary,
	}
	return writer.Write(row)
}

// FormatAdvisories renders advisory data as CSV.
func (cf *csvFormatter) FormatAdvisories(w io.Writer, advisories []model.Advisory) error {
	headers := []string{"id", "source", "severity", "url", "summary"}
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write header row
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	// Write data rows
	for _, adv := range advisories {
		row := []string{
			adv.ID,
			adv.Source,
			adv.Severity,
			adv.URL,
			adv.Summary,
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("writing CSV row: %w", err)
		}
	}

	return nil
}

// FormatSBOMResult renders SBOM check results as flattened CSV rows.
func (cf *csvFormatter) FormatSBOMResult(w io.Writer, result *model.SBOMResult) error {
	headers := []string{"ecosystem", "name", "version", "fixed", "id", "severity", "summary"}
	writer := csv.NewWriter(w)
	defer writer.Flush()

	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	for _, f := range result.Findings {
		row := []string{
			f.Ecosystem,
			f.Name,
			f.Version,
			f.Fixed,
			f.Advisory.ID,
			f.Advisory.Severity,
			f.Advisory.Summary,
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("writing CSV row: %w", err)
		}
	}

	return nil
}

// FormatSBOMDiffResult renders SBOM diff results as flattened CSV rows with a status column.
func (cf *csvFormatter) FormatSBOMDiffResult(w io.Writer, result *model.SBOMDiffResult) error {
	headers := []string{"status", "ecosystem", "name", "version", "fixed", "id", "severity", "summary"}
	writer := csv.NewWriter(w)
	defer writer.Flush()

	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	writeFindings := func(status string, findings []model.SBOMFinding) error {
		for _, f := range findings {
			row := []string{
				status,
				f.Ecosystem,
				f.Name,
				f.Version,
				f.Fixed,
				f.Advisory.ID,
				f.Advisory.Severity,
				f.Advisory.Summary,
			}
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("writing CSV row: %w", err)
			}
		}
		return nil
	}

	if err := writeFindings("added", result.Added); err != nil {
		return err
	}
	if err := writeFindings("removed", result.Removed); err != nil {
		return err
	}
	return writeFindings("unchanged", result.Unchanged)
}

// FormatExploitResult renders a single exploit result as CSV.
func (cf *csvFormatter) FormatExploitResult(w io.Writer, result *model.ExploitResult) error {
	if result == nil {
		return nil
	}
	return cf.FormatExploitResults(w, []*model.ExploitResult{result})
}

// FormatExploitResults renders multiple exploit results as CSV.
func (cf *csvFormatter) FormatExploitResults(w io.Writer, results []*model.ExploitResult) error {
	headers := []string{"cve_id", "source", "id", "name", "url", "description"}
	writer := csv.NewWriter(w)
	defer writer.Flush()

	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	for _, result := range results {
		if result == nil {
			continue
		}
		for _, ref := range result.Exploits {
			row := []string{
				result.CVEID,
				ref.Source,
				ref.ID,
				ref.Name,
				ref.URL,
				ref.Description,
			}
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("writing CSV row: %w", err)
			}
		}
	}

	return nil
}

// FormatCVEHistory renders CVE history as CSV (same as FormatCVE).
func (cf *csvFormatter) FormatCVEHistory(w io.Writer, cve *model.EnrichedCVE) error {
	return cf.FormatCVE(w, cve)
}

// FormatCacheStats renders cache statistics as CSV.
func (cf *csvFormatter) FormatCacheStats(w io.Writer, stats *cache.Stats) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	headers := []string{"metric", "value"}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	rows := [][]string{
		{"total_entries", fmt.Sprintf("%d", stats.TotalEntries)},
		{"cve_entries", fmt.Sprintf("%d", stats.CVEEntries)},
		{"kev_entries", fmt.Sprintf("%d", stats.KEVEntries)},
		{"epss_entries", fmt.Sprintf("%d", stats.EPSSEntries)},
		{"size_bytes", fmt.Sprintf("%d", stats.SizeBytes)},
	}

	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("writing CSV row: %w", err)
		}
	}

	return nil
}
