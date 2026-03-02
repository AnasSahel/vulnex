package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/githubapp"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the GitHub App webhook server",
	Long: `Start an HTTP server that receives GitHub webhook events and scans
pull requests for vulnerable dependencies using SBOM analysis.

Required environment variables:
  VULNEX_APP_ID               GitHub App ID
  VULNEX_APP_WEBHOOK_SECRET   Webhook signing secret
  VULNEX_APP_PRIVATE_KEY      PEM private key (inline)
  VULNEX_APP_PRIVATE_KEY_PATH Path to PEM private key file

Optional:
  VULNEX_APP_PORT             Listen port (default: 8080)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := githubapp.LoadConfigFromEnv()
		if err != nil {
			return err
		}

		handler := githubapp.NewHandler(cfg)
		srv := githubapp.NewServer(cfg, handler)

		// Graceful shutdown on SIGINT/SIGTERM
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		errCh := make(chan error, 1)
		go func() {
			errCh <- srv.ListenAndServe()
		}()

		select {
		case err := <-errCh:
			return err
		case <-ctx.Done():
			slog.Info("shutting down server")
			return srv.Shutdown(context.Background())
		}
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
