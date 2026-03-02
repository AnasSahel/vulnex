package githubapp

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds the GitHub App server configuration.
type Config struct {
	AppID          int64
	WebhookSecret  string
	PrivateKeyPath string
	PrivateKey     []byte
	Port           int
}

// LoadConfigFromEnv reads GitHub App configuration from environment variables.
func LoadConfigFromEnv() (*Config, error) {
	cfg := &Config{
		Port: 8080,
	}

	// Required: App ID
	appIDStr := os.Getenv("VULNEX_APP_ID")
	if appIDStr == "" {
		return nil, fmt.Errorf("VULNEX_APP_ID is required")
	}
	appID, err := strconv.ParseInt(appIDStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("VULNEX_APP_ID must be a number: %w", err)
	}
	cfg.AppID = appID

	// Required: Webhook secret
	cfg.WebhookSecret = os.Getenv("VULNEX_APP_WEBHOOK_SECRET")
	if cfg.WebhookSecret == "" {
		return nil, fmt.Errorf("VULNEX_APP_WEBHOOK_SECRET is required")
	}

	// Private key: inline or from file (one required)
	cfg.PrivateKeyPath = os.Getenv("VULNEX_APP_PRIVATE_KEY_PATH")
	pkInline := os.Getenv("VULNEX_APP_PRIVATE_KEY")

	switch {
	case pkInline != "":
		cfg.PrivateKey = []byte(pkInline)
	case cfg.PrivateKeyPath != "":
		data, err := os.ReadFile(cfg.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("reading private key file: %w", err)
		}
		cfg.PrivateKey = data
	default:
		return nil, fmt.Errorf("one of VULNEX_APP_PRIVATE_KEY or VULNEX_APP_PRIVATE_KEY_PATH is required")
	}

	// Optional: port
	if portStr := os.Getenv("VULNEX_APP_PORT"); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("VULNEX_APP_PORT must be a number: %w", err)
		}
		cfg.Port = port
	}

	return cfg, nil
}
