package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/trustin-tech/vulnex/internal/cache"
	"github.com/trustin-tech/vulnex/internal/model"
)

type markdownFormatter struct{}

func (f *markdownFormatter) FormatCVE(w io.Writer, cve *model.EnrichedCVE) error {
	fmt.Fprintf(w, "# %s\n\n", cve.ID)

	if cve.Status != "" {
		fmt.Fprintf(w, "**Status:** %s  \n", cve.Status)
	}
	fmt.Fprintf(w, "**Published:** %s  \n", cve.Published.Format("2006-01-02"))
	fmt.Fprintf(w, "**Last Modified:** %s  \n\n", cve.LastModified.Format("2006-01-02"))

	// Description
	desc := cve.Description()
	if desc != "" {
		fmt.Fprintf(w, "## Description\n\n%s\n\n", desc)
	}

	// CVSS
	if len(cve.CVSS) > 0 {
		fmt.Fprintf(w, "## CVSS Scores\n\n")
		fmt.Fprintf(w, "| Version | Score | Severity | Source |\n")
		fmt.Fprintf(w, "|---------|-------|----------|--------|\n")
		for _, s := range cve.CVSS {
			fmt.Fprintf(w, "| %s | %.1f | %s | %s |\n", s.Version, s.BaseScore, s.Severity, s.Source)
		}
		fmt.Fprintln(w)
	}

	// EPSS
	if cve.EPSS != nil {
		fmt.Fprintf(w, "## EPSS Score\n\n")
		fmt.Fprintf(w, "- **Score:** %.4f (%.1f%% probability of exploitation in 30 days)\n", cve.EPSS.Score, cve.EPSS.Score*100)
		fmt.Fprintf(w, "- **Percentile:** %.1f%%\n", cve.EPSS.Percentile*100)
		fmt.Fprintf(w, "- **Date:** %s\n\n", cve.EPSS.Date)
	}

	// KEV
	if cve.KEV != nil {
		fmt.Fprintf(w, "## CISA KEV Status\n\n")
		fmt.Fprintf(w, "**In Known Exploited Vulnerabilities catalog**\n\n")
		fmt.Fprintf(w, "- **Vendor:** %s\n", cve.KEV.VendorProject)
		fmt.Fprintf(w, "- **Product:** %s\n", cve.KEV.Product)
		fmt.Fprintf(w, "- **Date Added:** %s\n", cve.KEV.DateAdded)
		fmt.Fprintf(w, "- **Due Date:** %s\n", cve.KEV.DueDate)
		fmt.Fprintf(w, "- **Ransomware:** %s\n", cve.KEV.KnownRansomwareCampaign)
		fmt.Fprintf(w, "- **Required Action:** %s\n\n", cve.KEV.RequiredAction)
	}

	// Risk assessment
	risk := model.ComputeRisk(cve)
	fmt.Fprintf(w, "## Risk Assessment\n\n")
	fmt.Fprintf(w, "- **Priority:** %s\n", risk.Priority)
	fmt.Fprintf(w, "- **Composite Score:** %.0f/100\n", risk.Score)
	fmt.Fprintf(w, "- **Rationale:** %s\n", risk.Rationale)
	if risk.Disagreement != "" {
		fmt.Fprintf(w, "- **Signal Disagreement:** %s\n", risk.Disagreement)
	}
	fmt.Fprintln(w)

	// CWEs
	if len(cve.CWEs) > 0 {
		fmt.Fprintf(w, "## Weaknesses (CWE)\n\n")
		for _, c := range cve.CWEs {
			if c.Description != "" {
				fmt.Fprintf(w, "- %s: %s\n", c.ID, c.Description)
			} else {
				fmt.Fprintf(w, "- %s\n", c.ID)
			}
		}
		fmt.Fprintln(w)
	}

	// Affected packages
	if len(cve.AffectedPkgs) > 0 {
		fmt.Fprintf(w, "## Affected Packages\n\n")
		fmt.Fprintf(w, "| Ecosystem | Package | Fixed Version |\n")
		fmt.Fprintf(w, "|-----------|---------|---------------|\n")
		for _, p := range cve.AffectedPkgs {
			fixed := p.Fixed
			if fixed == "" {
				fixed = "-"
			}
			fmt.Fprintf(w, "| %s | %s | %s |\n", p.Ecosystem, p.Name, fixed)
		}
		fmt.Fprintln(w)
	}

	// References
	if len(cve.References) > 0 {
		fmt.Fprintf(w, "## References\n\n")
		for _, r := range cve.References {
			tags := ""
			if len(r.Tags) > 0 {
				tags = " (" + strings.Join(r.Tags, ", ") + ")"
			}
			fmt.Fprintf(w, "- %s%s\n", r.URL, tags)
		}
		fmt.Fprintln(w)
	}

	// Data sources
	if len(cve.DataSources) > 0 {
		fmt.Fprintf(w, "---\n\n*Data sources: %s*\n", strings.Join(cve.DataSources, ", "))
	}

	return nil
}

func (f *markdownFormatter) FormatCVEList(w io.Writer, cves []*model.EnrichedCVE) error {
	fmt.Fprintf(w, "| CVE ID | Severity | CVSS | EPSS | KEV | Description |\n")
	fmt.Fprintf(w, "|--------|----------|------|------|-----|-------------|\n")
	for _, cve := range cves {
		if cve == nil {
			continue
		}
		cvss := "-"
		severity := "UNKNOWN"
		if s := cve.HighestScore(); s != nil {
			cvss = fmt.Sprintf("%.1f", s.BaseScore)
			severity = s.Severity
		}
		epssStr := "-"
		if cve.EPSS != nil {
			epssStr = fmt.Sprintf("%.4f", cve.EPSS.Score)
		}
		kevStr := "No"
		if cve.IsInKEV() {
			kevStr = "**YES**"
		}
		desc := cve.Description()
		if len(desc) > 60 {
			desc = desc[:57] + "..."
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s |\n", cve.ID, severity, cvss, epssStr, kevStr, desc)
	}
	return nil
}

func (f *markdownFormatter) FormatKEVList(w io.Writer, entries []model.KEVEntry) error {
	fmt.Fprintf(w, "| CVE ID | Vendor | Product | Date Added | Due Date | Ransomware |\n")
	fmt.Fprintf(w, "|--------|--------|---------|------------|----------|------------|\n")
	for _, e := range entries {
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s |\n",
			e.CVEID, e.VendorProject, e.Product, e.DateAdded, e.DueDate, e.KnownRansomwareCampaign)
	}
	return nil
}

func (f *markdownFormatter) FormatEPSSScores(w io.Writer, scores map[string]*model.EPSSScore) error {
	fmt.Fprintf(w, "| CVE ID | EPSS Score | Percentile | Date |\n")
	fmt.Fprintf(w, "|--------|-----------|------------|------|\n")
	for id, s := range scores {
		fmt.Fprintf(w, "| %s | %.4f | %.2f%% | %s |\n", id, s.Score, s.Percentile*100, s.Date)
	}
	return nil
}

func (f *markdownFormatter) FormatAdvisories(w io.Writer, advisories []model.Advisory) error {
	fmt.Fprintf(w, "| ID | Source | Severity | Summary |\n")
	fmt.Fprintf(w, "|----|--------|----------|---------|\n")
	for _, a := range advisories {
		summary := a.Summary
		if len(summary) > 60 {
			summary = summary[:57] + "..."
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s |\n", a.ID, a.Source, a.Severity, summary)
	}
	return nil
}

func (f *markdownFormatter) FormatCacheStats(w io.Writer, stats *cache.Stats) error {
	fmt.Fprintf(w, "## Cache Statistics\n\n")
	fmt.Fprintf(w, "| Metric | Value |\n")
	fmt.Fprintf(w, "|--------|-------|\n")
	fmt.Fprintf(w, "| Total entries | %d |\n", stats.TotalEntries)
	fmt.Fprintf(w, "| CVE entries | %d |\n", stats.CVEEntries)
	fmt.Fprintf(w, "| KEV entries | %d |\n", stats.KEVEntries)
	fmt.Fprintf(w, "| EPSS entries | %d |\n", stats.EPSSEntries)
	fmt.Fprintf(w, "| Size | %s |\n", formatBytes(stats.SizeBytes))
	return nil
}
