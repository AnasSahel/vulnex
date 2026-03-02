package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/config"
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Cache management",
	Long:  "Manage the local vulnerability data cache.",
}

var cacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear the local cache",
	Long:  "Remove all cached vulnerability data.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if app.Cache == nil {
			return fmt.Errorf("cache is not enabled")
		}
		if err := app.Cache.Clear(cmd.Context()); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "Cache cleared successfully.")
		return nil
	},
}

var cacheStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show cache statistics",
	Long:  "Display information about the local cache.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if app.Cache == nil {
			return fmt.Errorf("cache is not enabled")
		}

		stats, err := app.Cache.Stats(cmd.Context())
		if err != nil {
			return err
		}

		return app.Formatter.FormatCacheStats(os.Stdout, stats)
	},
}

var cacheUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Force cache refresh",
	Long:  "Force a refresh of cached data from all sources.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if app.Cache == nil {
			return fmt.Errorf("cache is not enabled")
		}

		fmt.Fprintln(os.Stderr, "Updating KEV catalog...")
		if _, err := app.KEV.FetchCatalog(cmd.Context()); err != nil {
			fmt.Fprintf(os.Stderr, "KEV update failed: %v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, "KEV catalog updated.")
		}

		fmt.Fprintf(os.Stdout, "Cache updated. Location: %s\n", config.CacheDir())
		return nil
	},
}

func init() {
	cacheCmd.AddCommand(cacheClearCmd)
	cacheCmd.AddCommand(cacheStatsCmd)
	cacheCmd.AddCommand(cacheUpdateCmd)
	rootCmd.AddCommand(cacheCmd)
}
