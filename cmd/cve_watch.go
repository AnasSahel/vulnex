package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
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

		if app.Cache == nil {
			return fmt.Errorf("cache is required for watch list (cache is disabled)")
		}

		ctx := cmd.Context()

		if listFlag {
			return listWatchedCVEs(ctx)
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
			return refreshWatchList(ctx)
		}

		if removeFlag {
			return removeFromWatchList(ctx, ids)
		}

		if len(ids) == 0 {
			return listWatchedCVEs(ctx)
		}

		return addToWatchList(ctx, ids)
	},
}

func listWatchedCVEs(ctx context.Context) error {
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

	fmt.Fprintf(os.Stdout, "Watched CVEs (%d):\n", len(ids))
	for _, id := range ids {
		fmt.Fprintf(os.Stdout, "  %s\n", id)
	}
	return nil
}

func addToWatchList(ctx context.Context, newIDs []string) error {
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

	fmt.Fprintf(os.Stdout, "Added %d CVE(s) to watch list (total: %d)\n", added, len(ids))
	return nil
}

func removeFromWatchList(ctx context.Context, removeIDs []string) error {
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

	fmt.Fprintf(os.Stdout, "Removed %d CVE(s) from watch list (remaining: %d)\n", removed, len(filtered))
	return nil
}

func refreshWatchList(ctx context.Context) error {
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

	return app.Formatter.FormatCVEList(os.Stdout, cves)
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
