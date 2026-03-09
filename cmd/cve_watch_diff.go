package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/enricher"
	"github.com/trustin-tech/vulnex/internal/model"
)

var cveWatchDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Show what changed in your watch list",
	Long: `Compare current enrichment data for watched CVEs against stored
snapshots and surface meaningful changes — priority escalations,
EPSS spikes, KEV additions, and new exploits.

Automatically refreshes and snapshots all watched CVEs before comparing.`,
	Example: `  vulnex cve watch diff
  vulnex cve watch diff --since 7d
  vulnex cve watch diff --since 24h
  vulnex cve watch diff --date 2026-03-01
  vulnex cve watch diff --all
  vulnex cve watch diff --output json`,
	RunE: runWatchDiff,
}

func runWatchDiff(cmd *cobra.Command, args []string) error {
	noColor, _ := cmd.Flags().GetBool("no-color")
	sinceFlag, _ := cmd.Flags().GetString("since")
	dateFlag, _ := cmd.Flags().GetString("date")
	showAll, _ := cmd.Flags().GetBool("all")
	outputFmt, _ := cmd.Flags().GetString("output")
	quiet, _ := cmd.Flags().GetBool("quiet")

	if app.Cache == nil {
		return fmt.Errorf("cache is required for watch diff (cache is disabled)")
	}

	ctx := cmd.Context()

	// Get watch list
	ids, err := getWatchList(ctx)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		fmt.Fprintln(os.Stdout, "Watch list is empty. Add CVEs with: vulnex cve watch <CVE-ID...>")
		return nil
	}

	// Determine comparison time
	sinceTime, sinceLabel, err := parseSinceFlag(sinceFlag, dateFlag)
	if err != nil {
		return err
	}

	// Load previous snapshots
	previousSnapshots := make(map[string]*model.Snapshot, len(ids))
	for _, id := range ids {
		snapshots, err := app.Cache.GetSnapshots(ctx, id, sinceTime)
		if err != nil {
			return fmt.Errorf("loading snapshots for %s: %w", id, err)
		}
		if len(snapshots) > 0 {
			s := snapshots[0] // oldest snapshot in range = our baseline
			previousSnapshots[id] = &s
		}
	}

	// Refresh: enrich all watched CVEs and save new snapshots
	if !quiet {
		fmt.Fprintf(os.Stderr, "Refreshing %d watched CVEs...\n", len(ids))
	}

	cves, err := app.Enricher.EnrichBatch(ctx, ids)
	if err != nil {
		return err
	}
	enricher.SaveSnapshots(ctx, app.Cache, cves)

	// Compute changes
	diff := model.WatchDiff{
		Since:     sinceLabel,
		TotalCVEs: len(ids),
	}

	for i, cve := range cves {
		if cve == nil {
			continue
		}

		risk := model.ComputeRisk(cve)
		current := model.SnapshotFromEnriched(cve, risk)
		previous := previousSnapshots[ids[i]]

		change := model.ComputeChange(&current, previous)

		switch change.Type {
		case ChangeType(model.ChangeEscalated):
			diff.Escalated = append(diff.Escalated, change)
		case ChangeType(model.ChangeDeescalated):
			diff.Deescalated = append(diff.Deescalated, change)
		case ChangeType(model.ChangeNewExploits):
			diff.NewExploits = append(diff.NewExploits, change)
		case ChangeType(model.ChangeEPSSMovement):
			diff.EPSSMoved = append(diff.EPSSMoved, change)
		case ChangeType(model.ChangeNew):
			diff.NewEntries = append(diff.NewEntries, change)
		default:
			diff.Stable = append(diff.Stable, change)
		}
	}

	diff.ChangedCVEs = len(diff.Escalated) + len(diff.Deescalated) + len(diff.NewExploits) + len(diff.EPSSMoved) + len(diff.NewEntries)
	diff.HasEscalation = len(diff.Escalated) > 0

	// Render output
	switch outputFmt {
	case "json":
		return renderDiffJSON(os.Stdout, &diff, showAll)
	default:
		s := newCmdStyles(noColor)
		renderDiffTable(os.Stdout, s, &diff, showAll)
	}

	if diff.HasEscalation {
		os.Exit(1)
	}
	return nil
}

// ChangeType alias to avoid import cycle in switch statement.
type ChangeType = model.ChangeType

func renderDiffTable(w *os.File, s cmdStyles, diff *model.WatchDiff, showAll bool) {
	// Header
	fmt.Fprintf(w, "\n %s  %s\n\n",
		s.header.Render(fmt.Sprintf("WATCH LIST CHANGES (%s)", diff.Since)),
		s.muted.Render(fmt.Sprintf("%d of %d CVEs changed", diff.ChangedCVEs, diff.TotalCVEs)))

	if diff.ChangedCVEs == 0 && len(diff.NewEntries) == 0 {
		fmt.Fprintf(w, " %s\n\n", s.success.Render("No changes detected. Your risk posture is stable."))
		return
	}

	// Escalated
	if len(diff.Escalated) > 0 {
		fmt.Fprintf(w, " %s\n", s.critical.Render("▲ ESCALATED"))
		for _, c := range diff.Escalated {
			renderChangeLine(w, s, c)
		}
		fmt.Fprintln(w)
	}

	// De-escalated
	if len(diff.Deescalated) > 0 {
		fmt.Fprintf(w, " %s\n", s.success.Render("▼ DE-ESCALATED"))
		for _, c := range diff.Deescalated {
			renderChangeLine(w, s, c)
		}
		fmt.Fprintln(w)
	}

	// New exploits
	if len(diff.NewExploits) > 0 {
		fmt.Fprintf(w, " %s\n", s.high.Render("● NEW EXPLOITS"))
		for _, c := range diff.NewExploits {
			renderChangeLine(w, s, c)
		}
		fmt.Fprintln(w)
	}

	// EPSS movement
	if len(diff.EPSSMoved) > 0 {
		fmt.Fprintf(w, " %s\n", s.medium.Render("◆ EPSS MOVEMENT"))
		for _, c := range diff.EPSSMoved {
			renderChangeLine(w, s, c)
		}
		fmt.Fprintln(w)
	}

	// New entries (no previous snapshot)
	if len(diff.NewEntries) > 0 {
		fmt.Fprintf(w, " %s\n", s.header.Render("★ NEW"))
		for _, c := range diff.NewEntries {
			fmt.Fprintf(w, "   %s  %s\n",
				s.cveID.Render(fmt.Sprintf("%-18s", c.CVEID)),
				s.priority(string(c.NewPriority)).Render(string(c.NewPriority)))
		}
		fmt.Fprintln(w)
	}

	// Stable
	stableCount := len(diff.Stable)
	if showAll && stableCount > 0 {
		fmt.Fprintf(w, " %s\n", s.muted.Render("○ STABLE"))
		for _, c := range diff.Stable {
			fmt.Fprintf(w, "   %s  %s\n",
				s.muted.Render(fmt.Sprintf("%-18s", c.CVEID)),
				s.muted.Render(string(c.NewPriority)))
		}
		fmt.Fprintln(w)
	} else if stableCount > 0 {
		fmt.Fprintf(w, " %s\n\n",
			s.muted.Render(fmt.Sprintf("○ STABLE (%d CVEs unchanged)", stableCount)))
	}
}

func renderChangeLine(w *os.File, s cmdStyles, c model.CVEChange) {
	var parts []string

	// Priority transition
	if c.OldPriority != "" && c.OldPriority != c.NewPriority {
		parts = append(parts, fmt.Sprintf("%s → %s",
			string(c.OldPriority), s.priority(string(c.NewPriority)).Render(string(c.NewPriority))))
	} else {
		parts = append(parts, s.priority(string(c.NewPriority)).Render(string(c.NewPriority)))
	}

	// EPSS change
	if c.EPSSDelta != 0 && isSignificant(c.OldEPSS, c.NewEPSS) {
		sign := "+"
		if c.EPSSDelta < 0 {
			sign = ""
		}
		pctStr := ""
		if c.EPSSPctChg != 0 {
			pctStr = fmt.Sprintf(" (%s%.0f%%)", sign, c.EPSSPctChg)
		}
		parts = append(parts, fmt.Sprintf("EPSS %.3f→%.3f%s", c.OldEPSS, c.NewEPSS, pctStr))
	}

	// KEV addition
	if c.KEVAdded {
		parts = append(parts, s.critical.Render("Added to KEV"))
	}

	// Exploit change
	if c.NewExploits > c.OldExploits {
		parts = append(parts, fmt.Sprintf("+%d exploits", c.NewExploits-c.OldExploits))
	}

	fmt.Fprintf(w, "   %s  %s\n",
		s.cveID.Render(fmt.Sprintf("%-18s", c.CVEID)),
		strings.Join(parts, "  "))
}

func isSignificant(old, new float64) bool {
	delta := new - old
	if delta < 0 {
		delta = -delta
	}
	return delta > 0.005 // show any meaningful EPSS change in detail lines
}

func renderDiffJSON(w *os.File, diff *model.WatchDiff, showAll bool) error {
	output := diff
	if !showAll {
		// Remove stable entries from JSON output
		cleaned := *diff
		cleaned.Stable = nil
		output = &cleaned
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

// parseSinceFlag parses --since and --date flags into a time.Time and label.
func parseSinceFlag(since, date string) (time.Time, string, error) {
	if date != "" {
		t, err := time.Parse("2006-01-02", date)
		if err != nil {
			return time.Time{}, "", fmt.Errorf("invalid date %q (expected YYYY-MM-DD): %w", date, err)
		}
		return t, fmt.Sprintf("since %s", date), nil
	}

	if since == "" {
		since = "7d"
	}

	d, err := parseDuration(since)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("invalid duration %q: %w", since, err)
	}

	return time.Now().Add(-d), fmt.Sprintf("last %s", since), nil
}

// parseDuration parses a duration string with support for days (d) and weeks (w)
// in addition to Go's standard duration units.
func parseDuration(s string) (time.Duration, error) {
	// Try standard Go duration first
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}

	// Handle day/week suffixes
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid day duration: %s", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	if strings.HasSuffix(s, "w") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "w"))
		if err != nil {
			return 0, fmt.Errorf("invalid week duration: %s", s)
		}
		return time.Duration(n) * 7 * 24 * time.Hour, nil
	}

	return 0, fmt.Errorf("unsupported duration format: %s (use 7d, 24h, 2w, etc.)", s)
}

func init() {
	cveWatchDiffCmd.Flags().String("since", "7d", "Compare against snapshot from N days/hours ago (e.g., 7d, 24h, 2w)")
	cveWatchDiffCmd.Flags().String("date", "", "Compare against a specific date (YYYY-MM-DD)")
	cveWatchDiffCmd.Flags().Bool("all", false, "Show all CVEs including stable ones")
	cveWatchCmd.AddCommand(cveWatchDiffCmd)
}
