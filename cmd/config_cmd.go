package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/trustin-tech/vulnex/internal/config"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management",
	Long:  "Manage vulnex configuration settings.",
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfgPath := config.ConfigFilePath()
		fmt.Fprintf(os.Stdout, "Config file: %s\n\n", cfgPath)

		cfg := app.Config
		fmt.Fprintf(os.Stdout, "Output format:    %s\n", cfg.Output.Format)
		fmt.Fprintf(os.Stdout, "Color:            %s\n", cfg.Output.Color)
		fmt.Fprintf(os.Stdout, "Cache enabled:    %v\n", cfg.Cache.Enabled)
		fmt.Fprintf(os.Stdout, "Cache directory:  %s\n", config.CacheDir())
		fmt.Fprintf(os.Stdout, "Cache TTL (CVE):  %s\n", cfg.Cache.TTL.CVE)
		fmt.Fprintf(os.Stdout, "Cache TTL (KEV):  %s\n", cfg.Cache.TTL.KEV)
		fmt.Fprintf(os.Stdout, "Cache TTL (EPSS): %s\n", cfg.Cache.TTL.EPSS)

		if cfg.APIKeys.NVD != "" {
			fmt.Fprintf(os.Stdout, "NVD API key:      %s...%s\n", cfg.APIKeys.NVD[:4], cfg.APIKeys.NVD[len(cfg.APIKeys.NVD)-4:])
		} else {
			fmt.Fprintf(os.Stdout, "NVD API key:      (not set)\n")
		}
		if cfg.APIKeys.GitHub != "" {
			fmt.Fprintf(os.Stdout, "GitHub token:     %s...%s\n", cfg.APIKeys.GitHub[:4], cfg.APIKeys.GitHub[len(cfg.APIKeys.GitHub)-4:])
		} else {
			fmt.Fprintf(os.Stdout, "GitHub token:     (not set)\n")
		}

		return nil
	},
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Long: `Set a configuration key to a value. Keys use dot notation.

Available keys:
  api_keys.nvd          NVD API key
  api_keys.github       GitHub personal access token
  output.format         Default output format (table, json, csv, markdown, yaml)
  output.color          Color mode (auto, always, never)
  cache.enabled         Enable/disable cache (true/false)
  cache.ttl.cve         CVE cache TTL (e.g., 2h, 30m)
  cache.ttl.kev         KEV cache TTL
  cache.ttl.epss        EPSS cache TTL`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		key, value := args[0], args[1]

		cfgDir := config.ConfigDir()
		if err := os.MkdirAll(cfgDir, 0o755); err != nil {
			return fmt.Errorf("creating config directory: %w", err)
		}

		v := viper.New()
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(cfgDir)
		_ = v.ReadInConfig()

		v.Set(key, value)

		cfgPath := filepath.Join(cfgDir, "config.yaml")
		if err := v.WriteConfigAs(cfgPath); err != nil {
			return fmt.Errorf("writing config: %w", err)
		}

		fmt.Fprintf(os.Stdout, "Set %s = %s\n", key, value)
		return nil
	},
}

var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get a configuration value",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		v := viper.New()
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(config.ConfigDir())
		v.SetEnvPrefix("VULNEX")
		v.AutomaticEnv()
		_ = v.ReadInConfig()

		val := v.Get(args[0])
		if val == nil {
			return fmt.Errorf("key %q not found", args[0])
		}
		fmt.Fprintln(os.Stdout, val)
		return nil
	},
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create default configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfgDir := config.ConfigDir()
		if err := os.MkdirAll(cfgDir, 0o755); err != nil {
			return fmt.Errorf("creating config directory: %w", err)
		}

		cfgPath := filepath.Join(cfgDir, "config.yaml")
		if _, err := os.Stat(cfgPath); err == nil {
			return fmt.Errorf("config file already exists at %s", cfgPath)
		}

		defaultCfg := `# vulnex configuration
# See: vulnex config set --help

# API keys
api_keys:
  nvd: ""
  github: ""

# Output settings
output:
  format: table
  color: auto
  pager: auto

# Cache settings
cache:
  enabled: true
  directory: ""
  ttl:
    cve: 2h
    kev: 6h
    epss: 24h
    advisory: 4h

# Rate limits (requests per second)
rate_limits:
  nvd: 1.6
  epss: 1.0
  github: 1.4
  osv: 2.0

# Default filters
defaults:
  severity: ""
  no_rejected: true
  results_per_page: 20
`
		if err := os.WriteFile(cfgPath, []byte(defaultCfg), 0o644); err != nil {
			return fmt.Errorf("writing config: %w", err)
		}

		fmt.Fprintf(os.Stdout, "Configuration file created at %s\n", cfgPath)
		return nil
	},
}

func init() {
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configGetCmd)
	configCmd.AddCommand(configInitCmd)
	rootCmd.AddCommand(configCmd)
}
