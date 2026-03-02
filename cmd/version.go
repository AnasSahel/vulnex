package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(os.Stdout, "vulnex %s\n", versionStr)
		fmt.Fprintf(os.Stdout, "  commit:  %s\n", commitStr)
		fmt.Fprintf(os.Stdout, "  built:   %s\n", dateStr)
		fmt.Fprintf(os.Stdout, "  go:      %s\n", runtime.Version())
		fmt.Fprintf(os.Stdout, "  os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
