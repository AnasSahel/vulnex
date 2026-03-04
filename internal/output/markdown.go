package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/trustin-tech/vulnex/internal/cache"
	"github.com/trustin-tech/vulnex/internal/model"
)

type markdownFormatter struct {
	scoringProfile *model.ScoringProfile
}

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

	// Score conflicts
	if len(cve.ScoreConflicts) > 0 {
		fmt.Fprintf(w, "## CVSS Score Conflicts\n\n")
		fmt.Fprintf(w, "| Version | NVD Score | CNA Score | Delta | Significance |\n")
		fmt.Fprintf(w, "|---------|-----------|-----------|-------|--------------|\n")
		for _, c := range cve.ScoreConflicts {
			fmt.Fprintf(w, "| %s | %.1f | %.1f | %.1f | %s |\n", c.Version, c.NVDScore, c.CNAScore, c.Delta, c.Significance)
		}
		fmt.Fprintln(w)
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

	// Weighted Score
	if f.scoringProfile != nil {
		score := model.ComputeWeightedScore(*f.scoringProfile, cve)
		fmt.Fprintf(w, "## Weighted Score\n\n")
		fmt.Fprintf(w, "- **Score:** %.1f/100\n", score)
		fmt.Fprintf(w, "- **Profile:** %s\n", f.scoringProfile.Name)
		fmt.Fprintf(w, "- **Weights:** CVSS=%.2f EPSS=%.2f KEV=%.2f\n\n", f.scoringProfile.CVSSWeight, f.scoringProfile.EPSSWeight, f.scoringProfile.KEVWeight)
	}

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

func (f *markdownFormatter) FormatAdvisory(w io.Writer, adv *model.EnrichedAdvisory) error {
	fmt.Fprintf(w, "# %s\n\n", adv.ID)

	if adv.CVEID != "" {
		fmt.Fprintf(w, "**CVE:** %s  \n", adv.CVEID)
	}
	fmt.Fprintf(w, "**Severity:** %s  \n", strings.ToUpper(adv.Severity))
	if adv.CVSSScore > 0 {
		fmt.Fprintf(w, "**CVSS Score:** %.1f  \n", adv.CVSSScore)
	}
	if adv.EPSSScore > 0 {
		fmt.Fprintf(w, "**EPSS Score:** %.5f (percentile: %.4f)  \n", adv.EPSSScore, adv.EPSSPctile)
	}
	if adv.PublishedAt != "" {
		published := adv.PublishedAt
		if len(published) >= 10 {
			published = published[:10]
		}
		fmt.Fprintf(w, "**Published:** %s  \n", published)
	}
	if adv.URL != "" {
		fmt.Fprintf(w, "**URL:** %s  \n", adv.URL)
	}
	fmt.Fprintln(w)

	// Summary
	fmt.Fprintf(w, "## Summary\n\n%s\n\n", adv.Summary)

	// Description
	if adv.Description != "" {
		fmt.Fprintf(w, "## Description\n\n%s\n\n", adv.Description)
	}

	// CWEs
	if len(adv.CWEs) > 0 {
		fmt.Fprintf(w, "## Weaknesses (CWE)\n\n")
		for _, c := range adv.CWEs {
			if c.Description != "" {
				fmt.Fprintf(w, "- %s: %s\n", c.ID, c.Description)
			} else {
				fmt.Fprintf(w, "- %s\n", c.ID)
			}
		}
		fmt.Fprintln(w)
	}

	// Affected packages
	if len(adv.Packages) > 0 {
		fmt.Fprintf(w, "## Affected Packages\n\n")
		fmt.Fprintf(w, "| Ecosystem | Package | Fixed Version |\n")
		fmt.Fprintf(w, "|-----------|---------|---------------|\n")
		for _, p := range adv.Packages {
			fixed := p.Fixed
			if fixed == "" {
				fixed = "-"
			}
			fmt.Fprintf(w, "| %s | %s | %s |\n", p.Ecosystem, p.Name, fixed)
		}
		fmt.Fprintln(w)
	}

	// References
	if len(adv.References) > 0 {
		fmt.Fprintf(w, "## References\n\n")
		for _, r := range adv.References {
			fmt.Fprintf(w, "- %s\n", r)
		}
		fmt.Fprintln(w)
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

func (f *markdownFormatter) FormatSBOMResult(w io.Writer, result *model.SBOMResult) error {
	fmt.Fprintf(w, "# SBOM Vulnerability Check\n\n")
	fmt.Fprintf(w, "**File:** %s  \n", result.File)
	fmt.Fprintf(w, "**Components scanned:** %d  \n\n", result.TotalComponents)

	if len(result.Findings) == 0 {
		fmt.Fprintf(w, "No vulnerabilities found.\n")
		return nil
	}

	// Group findings by component
	type componentKey struct {
		ecosystem, name, version string
	}
	var order []componentKey
	groups := make(map[componentKey][]model.SBOMFinding)
	for _, finding := range result.Findings {
		key := componentKey{finding.Ecosystem, finding.Name, finding.Version}
		if _, exists := groups[key]; !exists {
			order = append(order, key)
		}
		groups[key] = append(groups[key], finding)
	}

	for _, key := range order {
		findings := groups[key]
		fmt.Fprintf(w, "## %s %s (%s)\n\n", key.name, key.version, key.ecosystem)
		fmt.Fprintf(w, "| ID | Severity | Fixed | Summary |\n")
		fmt.Fprintf(w, "|----|----------|-------|---------|\n")
		for _, finding := range findings {
			sev := strings.ToUpper(finding.Advisory.Severity)
			if sev == "" {
				sev = "UNKNOWN"
			}
			fixed := finding.Fixed
			if fixed == "" {
				fixed = "-"
			}
			summary := finding.Advisory.Summary
			if len(summary) > 60 {
				summary = summary[:57] + "..."
			}
			fmt.Fprintf(w, "| %s | %s | %s | %s |\n", finding.Advisory.ID, sev, fixed, summary)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "---\n\n*%d components scanned, %d vulnerable, %d findings*\n",
		result.TotalComponents, len(order), len(result.Findings))

	if len(result.Suppressed) > 0 {
		fmt.Fprintf(w, "\n> **Note:** %d finding(s) suppressed via `.vulnexignore`. Use `--strict` to show all.\n", len(result.Suppressed))
	}

	return nil
}

func (f *markdownFormatter) FormatSBOMDiffResult(w io.Writer, result *model.SBOMDiffResult) error {
	fmt.Fprintf(w, "# SBOM Vulnerability Diff\n\n")
	fmt.Fprintf(w, "**Old:** %s (%d components)  \n", result.OldFile, result.OldComponents)
	fmt.Fprintf(w, "**New:** %s (%d components)  \n\n", result.NewFile, result.NewComponents)

	sections := []struct {
		title    string
		findings []model.SBOMFinding
	}{
		{"Added", result.Added},
		{"Removed", result.Removed},
		{"Unchanged", result.Unchanged},
	}

	for _, sec := range sections {
		if len(sec.findings) == 0 {
			continue
		}

		fmt.Fprintf(w, "## %s (%d vulnerabilities)\n\n", sec.title, len(sec.findings))
		fmt.Fprintf(w, "| Ecosystem | Name | Version | ID | Severity | Fixed | Summary |\n")
		fmt.Fprintf(w, "|-----------|------|---------|----|----------|-------|---------|\n")
		for _, finding := range sec.findings {
			sev := strings.ToUpper(finding.Advisory.Severity)
			if sev == "" {
				sev = "UNKNOWN"
			}
			fixed := finding.Fixed
			if fixed == "" {
				fixed = "-"
			}
			summary := finding.Advisory.Summary
			if len(summary) > 60 {
				summary = summary[:57] + "..."
			}
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s |\n",
				finding.Ecosystem, finding.Name, finding.Version,
				finding.Advisory.ID, sev, fixed, summary)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "---\n\n*old=%d components (%d vulns), new=%d components (%d vulns), +%d added, -%d removed*\n",
		result.OldComponents, len(result.Removed)+len(result.Unchanged),
		result.NewComponents, len(result.Added)+len(result.Unchanged),
		len(result.Added), len(result.Removed))

	if len(result.Suppressed) > 0 {
		fmt.Fprintf(w, "\n> **Note:** %d added finding(s) suppressed via `.vulnexignore`. Use `--strict` to show all.\n", len(result.Suppressed))
	}

	return nil
}

func (f *markdownFormatter) FormatExploitResult(w io.Writer, result *model.ExploitResult) error {
	if result == nil {
		return nil
	}

	fmt.Fprintf(w, "## %s\n\n", result.CVEID)

	if len(result.Exploits) == 0 {
		fmt.Fprintf(w, "No known exploits found.\n\n")
		return nil
	}

	fmt.Fprintf(w, "| Source | Name | URL |\n")
	fmt.Fprintf(w, "|--------|------|-----|\n")
	for _, ref := range result.Exploits {
		fmt.Fprintf(w, "| %s | %s | %s |\n", ref.Source, ref.Name, ref.URL)
	}
	fmt.Fprintln(w)

	return nil
}

func (f *markdownFormatter) FormatExploitResults(w io.Writer, results []*model.ExploitResult) error {
	fmt.Fprintf(w, "# Exploit Check Results\n\n")
	for _, result := range results {
		if result == nil {
			continue
		}
		if err := f.FormatExploitResult(w, result); err != nil {
			return err
		}
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
