package cmd

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/model"
)

var scoringCmd = &cobra.Command{
	Use:   "scoring",
	Short: "Show scoring profiles and priority thresholds",
	Long: `Display the built-in scoring profiles and risk priority thresholds
used to compute weighted vulnerability scores.

Profiles control how CVSS, EPSS, and KEV signals are weighted when
computing a composite score (0-100). Use --scoring-profile with
enrich or cve get to select a profile.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		noColor, _ := cmd.Flags().GetBool("no-color")
		s := newCmdStyles(noColor)

		profiles := []model.ScoringProfile{
			model.DefaultProfile(),
			model.ExploitFocusedProfile(),
			model.SeverityFocusedProfile(),
		}

		fmt.Fprintln(os.Stdout, s.header.Render("Scoring Profiles"))
		fmt.Fprintln(os.Stdout)
		fmt.Fprintf(os.Stdout, "  %s %s  %s  %s\n",
			styledPadCmd("Profile", 20, s.header),
			styledPadCmd("CVSS", 6, s.header),
			styledPadCmd("EPSS", 6, s.header),
			s.header.Render("KEV"))
		for _, p := range profiles {
			fmt.Fprintf(os.Stdout, "  %-20s %s  %s  %s\n",
				s.value.Render(p.Name),
				styledPadCmd(fmt.Sprintf("%.2f", p.CVSSWeight), 6, s.value),
				styledPadCmd(fmt.Sprintf("%.2f", p.EPSSWeight), 6, s.value),
				fmt.Sprintf("%.2f", p.KEVWeight))
		}

		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, s.header.Render("Risk Priority Thresholds"))
		fmt.Fprintln(os.Stdout)

		tiers := []struct {
			label string
			desc  string
		}{
			{"P0-CRITICAL", "In CISA KEV (regardless of other scores)"},
			{"P1-HIGH", "EPSS >= 0.7 OR CVSS >= 9.0"},
			{"P2-MEDIUM", "EPSS >= 0.3 OR (CVSS >= 7.0 AND EPSS >= 0.1)"},
			{"P3-LOW", "CVSS >= 7.0 but EPSS < 0.1"},
			{"P4-MINIMAL", "CVSS < 7.0 AND EPSS < 0.1"},
		}
		for _, t := range tiers {
			fmt.Fprintf(os.Stdout, "  %s  %s\n",
				styledPadCmd(t.label, 14, s.priority(t.label)),
				s.value.Render(t.desc))
		}

		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, s.muted.Render("Use --scoring-profile to select a profile, or --cvss-weight,"))
		fmt.Fprintln(os.Stdout, s.muted.Render("--epss-weight, --kev-weight to set custom weights."))

		return nil
	},
}

// styledPadCmd renders text with a style, then pads to a fixed visible width.
func styledPadCmd(text string, width int, style lipgloss.Style) string {
	rendered := style.Render(text)
	pad := width - len(text)
	if pad <= 0 {
		return rendered
	}
	return rendered + fmt.Sprintf("%*s", pad, "")
}

// styledRightPad renders text with a style, right-aligned within a fixed visible width.
func styledRightPad(text string, width int, style lipgloss.Style) string {
	rendered := style.Render(text)
	pad := width - len(text)
	if pad <= 0 {
		return rendered
	}
	return fmt.Sprintf("%*s", pad, "") + rendered
}

func init() {
	rootCmd.AddCommand(scoringCmd)
}
