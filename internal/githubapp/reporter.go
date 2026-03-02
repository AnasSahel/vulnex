package githubapp

import (
	"fmt"
	"strings"

	"github.com/trustin-tech/vulnex/internal/sbom"
)

const maxCheckRunText = 65000

// FormatCheckRun returns the conclusion, summary, and text for a GitHub Check Run.
func FormatCheckRun(result *sbom.CheckResult, err error) (conclusion, summary, text string) {
	if err != nil {
		return "failure", fmt.Sprintf("vulnex scan failed: %v", err), ""
	}

	if len(result.Findings) == 0 {
		return "success",
			fmt.Sprintf("No vulnerabilities found across %d components.", result.TotalComponents),
			""
	}

	counts := severityCounts(result)
	hasCriticalOrHigh := counts["critical"] > 0 || counts["high"] > 0

	if hasCriticalOrHigh {
		conclusion = "action_required"
	} else {
		conclusion = "neutral"
	}

	summary = formatSeveritySummary(result, counts)
	text = formatFindingsTable(result)

	if len(text) > maxCheckRunText {
		text = text[:maxCheckRunText-20] + "\n\n...(truncated)"
	}

	return conclusion, summary, text
}

// FormatPRComment builds a markdown PR comment from the check results.
func FormatPRComment(result *sbom.CheckResult) string {
	if len(result.Findings) == 0 {
		return fmt.Sprintf(
			"## vulnex scan\n\n"+
				"No vulnerabilities found across %d components.\n\n"+
				"---\n*Powered by [vulnex](https://github.com/AnasSahel/vulnex)*",
			result.TotalComponents,
		)
	}

	counts := severityCounts(result)

	var b strings.Builder
	b.WriteString("## vulnex scan\n\n")

	// Severity summary table
	b.WriteString("| Severity | Count |\n")
	b.WriteString("|----------|-------|\n")
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if c := counts[sev]; c > 0 {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", strings.ToUpper(sev), c))
		}
	}
	if c := counts[""]; c > 0 {
		b.WriteString(fmt.Sprintf("| UNKNOWN | %d |\n", c))
	}
	b.WriteString("\n")

	// Findings grouped by component
	type componentKey struct {
		ecosystem, name, version string
	}
	grouped := make(map[componentKey][]int)
	var order []componentKey

	for i, f := range result.Findings {
		key := componentKey{f.Ecosystem, f.Name, f.Version}
		if _, exists := grouped[key]; !exists {
			order = append(order, key)
		}
		grouped[key] = append(grouped[key], i)
	}

	for _, key := range order {
		indices := grouped[key]
		label := fmt.Sprintf("%s/%s@%s", key.ecosystem, key.name, key.version)
		b.WriteString(fmt.Sprintf("<details>\n<summary><b>%s</b> (%d vulnerabilities)</summary>\n\n", label, len(indices)))
		b.WriteString("| Advisory | Severity | Fixed | Summary |\n")
		b.WriteString("|----------|----------|-------|---------|\n")

		for _, idx := range indices {
			f := result.Findings[idx]
			sev := f.Advisory.Severity
			if sev == "" {
				sev = "unknown"
			}
			fixed := f.Fixed
			if fixed == "" {
				fixed = "-"
			}
			summary := f.Advisory.Summary
			if len(summary) > 80 {
				summary = summary[:77] + "..."
			}
			b.WriteString(fmt.Sprintf("| [%s](%s) | %s | %s | %s |\n",
				f.Advisory.ID,
				f.Advisory.URL,
				strings.ToUpper(sev),
				fixed,
				summary,
			))
		}
		b.WriteString("\n</details>\n\n")
	}

	b.WriteString("---\n*Powered by [vulnex](https://github.com/AnasSahel/vulnex)*")

	result_str := b.String()
	if len(result_str) > maxCheckRunText {
		result_str = result_str[:maxCheckRunText-20] + "\n\n...(truncated)"
	}
	return result_str
}

func severityCounts(result *sbom.CheckResult) map[string]int {
	counts := make(map[string]int)
	for _, f := range result.Findings {
		counts[strings.ToLower(f.Advisory.Severity)]++
	}
	return counts
}

func formatSeveritySummary(result *sbom.CheckResult, counts map[string]int) string {
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if c := counts[sev]; c > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c, strings.ToUpper(sev)))
		}
	}
	if c := counts[""]; c > 0 {
		parts = append(parts, fmt.Sprintf("%d UNKNOWN", c))
	}

	return fmt.Sprintf("Found %d vulnerabilities across %d components: %s",
		len(result.Findings), result.TotalComponents, strings.Join(parts, ", "))
}

func formatFindingsTable(result *sbom.CheckResult) string {
	var b strings.Builder
	b.WriteString("| Component | Version | Advisory | Severity | Fixed | Summary |\n")
	b.WriteString("|-----------|---------|----------|----------|-------|---------|\n")

	for _, f := range result.Findings {
		sev := f.Advisory.Severity
		if sev == "" {
			sev = "unknown"
		}
		fixed := f.Fixed
		if fixed == "" {
			fixed = "-"
		}
		summary := f.Advisory.Summary
		if len(summary) > 60 {
			summary = summary[:57] + "..."
		}
		b.WriteString(fmt.Sprintf("| %s/%s | %s | [%s](%s) | %s | %s | %s |\n",
			f.Ecosystem, f.Name,
			f.Version,
			f.Advisory.ID, f.Advisory.URL,
			strings.ToUpper(sev),
			fixed,
			summary,
		))
	}

	return b.String()
}
