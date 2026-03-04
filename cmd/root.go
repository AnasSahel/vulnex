package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/trustin-tech/vulnex/internal/api"
	"github.com/trustin-tech/vulnex/internal/api/epss"
	"github.com/trustin-tech/vulnex/internal/api/exploit"
	"github.com/trustin-tech/vulnex/internal/api/ghsa"
	"github.com/trustin-tech/vulnex/internal/api/kev"
	"github.com/trustin-tech/vulnex/internal/api/nvd"
	"github.com/trustin-tech/vulnex/internal/api/osv"
	"github.com/trustin-tech/vulnex/internal/cache"
	"github.com/trustin-tech/vulnex/internal/config"
	"github.com/trustin-tech/vulnex/internal/enricher"
	"github.com/trustin-tech/vulnex/internal/model"
	"github.com/trustin-tech/vulnex/internal/output"
	"github.com/trustin-tech/vulnex/internal/ratelimit"
)

// Version info set via ldflags.
var (
	versionStr = "dev"
	commitStr  = "none"
	dateStr    = "unknown"
)

// SetVersionInfo sets build-time version information.
func SetVersionInfo(version, commit, date string) {
	versionStr = version
	commitStr = commit
	dateStr = date
}

// AppContext holds all initialized dependencies for the CLI commands.
type AppContext struct {
	Config         *config.Config
	Cache          cache.Cache
	Enricher       *enricher.Enricher
	Formatter      output.Formatter
	ScoringProfile *model.ScoringProfile
	NVD            *nvd.Client
	KEV            *kev.Client
	EPSS           *epss.Client
	GHSA           *ghsa.Client
	OSV            *osv.Client
	Exploit        *exploit.Client
}

var app AppContext

var rootCmd = &cobra.Command{
	Use:   "vulnex",
	Short: "Multi-source vulnerability intelligence CLI",
	Long: `vulnex aggregates CVE, NVD, KEV, EPSS, GitHub Advisory, and OSV data
into a unified CLI experience with local caching, composite risk scoring,
and pipe-friendly output.

This product uses the NVD API but is not endorsed or certified by the NVD.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip bootstrap for completion and version commands
		if cmd.Name() == "completion" || cmd.Name() == "version" || cmd.Name() == "__complete" || cmd.Name() == "scoring" {
			return nil
		}
		return bootstrap(cmd)
	},
}

func init() {
	rootCmd.PersistentFlags().StringP("output", "o", "table", "Output format: table, json, csv, markdown, yaml, sarif")
	rootCmd.PersistentFlags().BoolP("long", "l", false, "Show full descriptions instead of truncated")
	rootCmd.PersistentFlags().Bool("no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "Suppress non-essential output")
	rootCmd.PersistentFlags().String("config", "", "Path to config file")
	rootCmd.PersistentFlags().String("cache-dir", "", "Path to cache directory")
	rootCmd.PersistentFlags().Bool("no-cache", false, "Bypass cache for this request")
	rootCmd.PersistentFlags().Bool("offline", false, "Only use cached data")
	rootCmd.PersistentFlags().String("api-key", "", "NVD API key (overrides config/env)")
	rootCmd.PersistentFlags().Duration("timeout", 0, "HTTP request timeout")

	_ = viper.BindPFlag("output.format", rootCmd.PersistentFlags().Lookup("output"))
	_ = viper.BindPFlag("output.no_color", rootCmd.PersistentFlags().Lookup("no-color"))
}

func bootstrap(cmd *cobra.Command) error {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Warn("loading config", "error", err)
		cfg = config.DefaultConfig()
	}
	app.Config = cfg

	// Override with CLI flags
	if v, _ := cmd.Flags().GetString("api-key"); v != "" {
		cfg.APIKeys.NVD = v
	}

	// Setup verbose logging
	verbose, _ := cmd.Flags().GetBool("verbose")
	if verbose {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	// Initialize cache
	noCache, _ := cmd.Flags().GetBool("no-cache")
	if !noCache && cfg.Cache.Enabled {
		cacheDir, _ := cmd.Flags().GetString("cache-dir")
		if cacheDir == "" {
			cacheDir = config.CacheDir()
		}
		c, err := cache.NewSQLite(cacheDir)
		if err != nil {
			slog.Warn("cache initialization failed, proceeding without cache", "error", err)
		} else {
			app.Cache = c
		}
	}

	// Initialize rate limiter
	limiter := ratelimit.New()
	if cfg.RateLimits.NVD > 0 {
		limiter.SetLimit("services.nvd.nist.gov", cfg.RateLimits.NVD)
	}
	if cfg.RateLimits.EPSS > 0 {
		limiter.SetLimit("api.first.org", cfg.RateLimits.EPSS)
	}
	if cfg.RateLimits.GitHub > 0 {
		limiter.SetLimit("api.github.com", cfg.RateLimits.GitHub)
	}
	if cfg.RateLimits.OSV > 0 {
		limiter.SetLimit("api.osv.dev", cfg.RateLimits.OSV)
	}

	// Initialize HTTP client with API keys
	var clientOpts []api.ClientOption
	if cfg.APIKeys.NVD != "" {
		clientOpts = append(clientOpts, api.WithAPIKey("services.nvd.nist.gov", cfg.APIKeys.NVD))
	}
	if cfg.APIKeys.GitHub != "" {
		clientOpts = append(clientOpts, api.WithAPIKey("api.github.com", cfg.APIKeys.GitHub))
	}
	if timeout, _ := cmd.Flags().GetDuration("timeout"); timeout > 0 {
		clientOpts = append(clientOpts, api.WithTimeout(timeout))
	}

	httpClient := api.NewClient(limiter, clientOpts...)

	// Initialize API clients
	app.NVD = nvd.NewClient(httpClient, app.Cache)
	app.KEV = kev.NewClient(httpClient, app.Cache)
	app.EPSS = epss.NewClient(httpClient, app.Cache)
	app.GHSA = ghsa.NewClient(httpClient, app.Cache)
	app.OSV = osv.NewClient(httpClient, app.Cache)
	app.Exploit = exploit.NewClient(httpClient)

	// Initialize enricher
	app.Enricher = enricher.New(app.NVD, app.KEV, app.EPSS, app.GHSA, app.OSV)

	// Initialize formatter
	format, _ := cmd.Flags().GetString("output")
	noColor, _ := cmd.Flags().GetBool("no-color")
	long, _ := cmd.Flags().GetBool("long")

	// Resolve scoring profile if the flag exists on this command
	if f := cmd.Flags().Lookup("scoring-profile"); f != nil && f.Value.String() != "" {
		profileName := f.Value.String()
		var profile model.ScoringProfile
		switch profileName {
		case "default":
			profile = model.DefaultProfile()
		case "exploit-focused":
			profile = model.ExploitFocusedProfile()
		case "severity-focused":
			profile = model.SeverityFocusedProfile()
		default:
			return fmt.Errorf("unknown scoring profile %q (supported: default, exploit-focused, severity-focused)", profileName)
		}

		// Override individual weights if explicitly set
		if f := cmd.Flags().Lookup("cvss-weight"); f != nil && f.Changed {
			v, _ := cmd.Flags().GetFloat64("cvss-weight")
			profile.CVSSWeight = v
			profile.Name = "custom"
		}
		if f := cmd.Flags().Lookup("epss-weight"); f != nil && f.Changed {
			v, _ := cmd.Flags().GetFloat64("epss-weight")
			profile.EPSSWeight = v
			profile.Name = "custom"
		}
		if f := cmd.Flags().Lookup("kev-weight"); f != nil && f.Changed {
			v, _ := cmd.Flags().GetFloat64("kev-weight")
			profile.KEVWeight = v
			profile.Name = "custom"
		}

		app.ScoringProfile = &profile
	}

	var fmtOpts []output.FormatterOption
	fmtOpts = append(fmtOpts, output.WithVersion(versionStr))
	if noColor {
		fmtOpts = append(fmtOpts, output.WithNoColor())
	}
	if long {
		fmtOpts = append(fmtOpts, output.WithLong())
	}
	if app.ScoringProfile != nil {
		fmtOpts = append(fmtOpts, output.WithScoringProfile(app.ScoringProfile))
	}

	formatter, err := output.NewFormatter(format, fmtOpts...)
	if err != nil {
		return fmt.Errorf("invalid output format %q: %w", format, err)
	}
	app.Formatter = formatter

	return nil
}

// Execute runs the root command.
func Execute() error {
	err := rootCmd.Execute()
	if app.Cache != nil {
		_ = app.Cache.Close()
	}
	return err
}
