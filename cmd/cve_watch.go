package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/enricher"
)

var cveWatchCmd = &cobra.Command{
	Use:   "watch <CVE-ID...>",
	Short: "Manage CVE watch list",
	Long: `Add or list CVEs in your watch list. Watched CVEs are stored locally
in the cache and can be refreshed with 'vulnex cve watch --refresh'.`,
	Example: `  vulnex cve watch CVE-2024-3094 CVE-2021-44228
  vulnex cve watch --list
  vulnex cve watch --refresh`,
	RunE: func(cmd *cobra.Command, args []string) error {
		listFlag, _ := cmd.Flags().GetBool("list")
		refreshFlag, _ := cmd.Flags().GetBool("refresh")
		removeFlag, _ := cmd.Flags().GetBool("remove")
		stdinFlag, _ := cmd.Flags().GetBool("stdin")
		noColor, _ := cmd.Flags().GetBool("no-color")

		if app.Cache == nil {
			return fmt.Errorf("cache is required for watch list (cache is disabled)")
		}

		s := newCmdStyles(noColor)
		ctx := cmd.Context()

		if listFlag {
			return listWatchedCVEs(ctx, s)
		}

		ids := args
		if stdinFlag {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && strings.HasPrefix(strings.ToUpper(line), "CVE-") {
					ids = append(ids, strings.ToUpper(line))
				}
			}
		}

		if refreshFlag {
			return refreshWatchList(ctx, s)
		}

		if removeFlag {
			return removeFromWatchList(ctx, s, ids)
		}

		if len(ids) == 0 {
			return listWatchedCVEs(ctx, s)
		}

		return addToWatchList(ctx, s, ids)
	},
}

func listWatchedCVEs(ctx context.Context, s cmdStyles) error {
	data, err := app.Cache.GetMetadata(ctx, "watch_list")
	if err != nil {
		return err
	}
	if data == "" {
		fmt.Fprintln(os.Stdout, "Watch list is empty.")
		return nil
	}

	var ids []string
	if err := json.Unmarshal([]byte(data), &ids); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "%d CVEs in watch list:\n", len(ids))
	for _, id := range ids {
		fmt.Fprintf(os.Stdout, "  %s\n", s.cveID.Render(id))
	}
	return nil
}

func addToWatchList(ctx context.Context, s cmdStyles, newIDs []string) error {
	ids, err := getWatchList(ctx)
	if err != nil {
		return err
	}

	added := 0
	for _, id := range newIDs {
		if !contains(ids, id) {
			ids = append(ids, id)
			added++
		}
	}

	if err := saveWatchList(ctx, ids); err != nil {
		return err
	}

	msg := fmt.Sprintf("Added %d CVEs to watch list (%d total)", added, len(ids))
	fmt.Fprintln(os.Stdout, s.success.Render(msg))
	return nil
}

func removeFromWatchList(ctx context.Context, s cmdStyles, removeIDs []string) error {
	ids, err := getWatchList(ctx)
	if err != nil {
		return err
	}

	filtered := make([]string, 0, len(ids))
	removed := 0
	for _, id := range ids {
		if contains(removeIDs, id) {
			removed++
		} else {
			filtered = append(filtered, id)
		}
	}

	if err := saveWatchList(ctx, filtered); err != nil {
		return err
	}

	msg := fmt.Sprintf("Removed %d, %d remaining", removed, len(filtered))
	fmt.Fprintln(os.Stdout, s.success.Render(msg))
	return nil
}

func refreshWatchList(ctx context.Context, s cmdStyles) error {
	ids, err := getWatchList(ctx)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		fmt.Fprintln(os.Stdout, "Watch list is empty.")
		return nil
	}

	fmt.Fprintf(os.Stderr, "Refreshing %d watched CVEs...\n", len(ids))
	cves, err := app.Enricher.EnrichBatch(ctx, ids)
	if err != nil {
		return err
	}

	enricher.SaveSnapshots(ctx, app.Cache, cves)

	for _, cve := range cves {
		severity := cve.Severity()
		sevStyle := s.severity(severity)

		cvss := "N/A"
		if score := cve.HighestScore(); score != nil {
			cvss = fmt.Sprintf("%.1f", score.BaseScore)
		}

		desc := cve.Description()
		if len(desc) > 50 {
			desc = desc[:47] + "..."
		}

		sevLabel := sevStyle.Render(fmt.Sprintf("%s (%s)", severity, cvss))
		fmt.Fprintf(os.Stdout, "  %s  %s  %s\n",
			s.cveID.Render(fmt.Sprintf("%-16s", cve.ID)),
			sevLabel,
			desc)
	}

	return nil
}

func getWatchList(ctx context.Context) ([]string, error) {
	data, err := app.Cache.GetMetadata(ctx, "watch_list")
	if err != nil {
		return nil, err
	}
	if data == "" {
		return nil, nil
	}
	var ids []string
	return ids, json.Unmarshal([]byte(data), &ids)
}

func saveWatchList(ctx context.Context, ids []string) error {
	data, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	return app.Cache.SetMetadata(ctx, "watch_list", string(data))
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, val) {
			return true
		}
	}
	return false
}

func init() {
	cveWatchCmd.Flags().Bool("list", false, "List all watched CVEs")
	cveWatchCmd.Flags().Bool("refresh", false, "Refresh data for all watched CVEs")
	cveWatchCmd.Flags().Bool("remove", false, "Remove CVEs from watch list")
	cveWatchCmd.Flags().Bool("stdin", false, "Read CVE IDs from stdin")
	cveCmd.AddCommand(cveWatchCmd)
}
