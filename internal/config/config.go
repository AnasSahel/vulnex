package config

import (
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for vulnex.
type Config struct {
	APIKeys    APIKeys    `mapstructure:"api_keys"`
	Output     Output     `mapstructure:"output"`
	Cache      CacheConf  `mapstructure:"cache"`
	RateLimits RateLimits `mapstructure:"rate_limits"`
	Defaults   Defaults   `mapstructure:"defaults"`
}

// APIKeys holds API keys for various data sources.
type APIKeys struct {
	NVD        string `mapstructure:"nvd"`
	GitHub     string `mapstructure:"github"`
	VulnCheck  string `mapstructure:"vulncheck"`
}

// Output holds output format configuration.
type Output struct {
	Format string `mapstructure:"format"` // table, json, csv, markdown, yaml
	Color  string `mapstructure:"color"`  // auto, always, never
	Pager  string `mapstructure:"pager"`  // auto, always, never
}

// CacheConf holds cache configuration.
type CacheConf struct {
	Enabled   bool     `mapstructure:"enabled"`
	Directory string   `mapstructure:"directory"`
	TTL       CacheTTL `mapstructure:"ttl"`
}

// CacheTTL holds per-data-type TTL configuration.
type CacheTTL struct {
	CVE      time.Duration `mapstructure:"cve"`
	KEV      time.Duration `mapstructure:"kev"`
	EPSS     time.Duration `mapstructure:"epss"`
	Advisory time.Duration `mapstructure:"advisory"`
}

// RateLimits holds per-source rate limits (requests per second).
type RateLimits struct {
	NVD    float64 `mapstructure:"nvd"`
	EPSS   float64 `mapstructure:"epss"`
	GitHub float64 `mapstructure:"github"`
	OSV    float64 `mapstructure:"osv"`
}

// Defaults holds default filter configuration.
type Defaults struct {
	Severity       string `mapstructure:"severity"`
	NoRejected     bool   `mapstructure:"no_rejected"`
	ResultsPerPage int    `mapstructure:"results_per_page"`
}

// DefaultConfig returns a Config with sensible default values.
func DefaultConfig() *Config {
	return &Config{
		Output: Output{
			Format: "table",
			Color:  "auto",
			Pager:  "auto",
		},
		Cache: CacheConf{
			Enabled: true,
			TTL: CacheTTL{
				CVE:      2 * time.Hour,
				KEV:      6 * time.Hour,
				EPSS:     24 * time.Hour,
				Advisory: 4 * time.Hour,
			},
		},
		RateLimits: RateLimits{
			NVD:    1.6,
			EPSS:   1.0,
			GitHub: 1.4,
			OSV:    2.0,
		},
		Defaults: Defaults{
			NoRejected:     true,
			ResultsPerPage: 20,
		},
	}
}

// ConfigDir returns the configuration directory path following XDG conventions.
func ConfigDir() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "vulnex")
	}
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "vulnex")
	}
	return filepath.Join(home, ".config", "vulnex")
}

// CacheDir returns the cache directory path following XDG conventions.
func CacheDir() string {
	if dir := os.Getenv("XDG_CACHE_HOME"); dir != "" {
		return filepath.Join(dir, "vulnex")
	}
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Caches", "vulnex")
	}
	return filepath.Join(home, ".cache", "vulnex")
}

// ConfigFilePath returns the path to the configuration file.
func ConfigFilePath() string {
	return filepath.Join(ConfigDir(), "config.yaml")
}

// Load reads and returns the configuration, merging file, env, and defaults.
func Load() (*Config, error) {
	cfg := DefaultConfig()

	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(ConfigDir())
	v.SetEnvPrefix("VULNEX")
	v.AutomaticEnv()

	// Set defaults for viper
	v.SetDefault("output.format", cfg.Output.Format)
	v.SetDefault("output.color", cfg.Output.Color)
	v.SetDefault("output.pager", cfg.Output.Pager)
	v.SetDefault("cache.enabled", cfg.Cache.Enabled)
	v.SetDefault("cache.ttl.cve", cfg.Cache.TTL.CVE)
	v.SetDefault("cache.ttl.kev", cfg.Cache.TTL.KEV)
	v.SetDefault("cache.ttl.epss", cfg.Cache.TTL.EPSS)
	v.SetDefault("cache.ttl.advisory", cfg.Cache.TTL.Advisory)
	v.SetDefault("rate_limits.nvd", cfg.RateLimits.NVD)
	v.SetDefault("rate_limits.epss", cfg.RateLimits.EPSS)
	v.SetDefault("rate_limits.github", cfg.RateLimits.GitHub)
	v.SetDefault("rate_limits.osv", cfg.RateLimits.OSV)
	v.SetDefault("defaults.no_rejected", cfg.Defaults.NoRejected)
	v.SetDefault("defaults.results_per_page", cfg.Defaults.ResultsPerPage)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return cfg, err
		}
		// Config file not found is fine, use defaults.
	}

	if err := v.Unmarshal(cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}
