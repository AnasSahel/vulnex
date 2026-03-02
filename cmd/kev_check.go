package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/model"
)

var kevCheckCmd = &cobra.Command{
	Use:   "check <CVE-ID...>",
	Short: "Check if CVE(s) are in KEV",
	Long:  "Check whether one or more CVEs are in the CISA KEV catalog.",
	Example: `  vulnex kev check CVE-2021-44228
  vulnex kev check CVE-2024-3094 CVE-2023-44228
  echo "CVE-2024-3094" | vulnex kev check --stdin`,
	RunE: func(cmd *cobra.Command, args []string) error {
		stdin, _ := cmd.Flags().GetBool("stdin")
		ids := args

		if stdin {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && strings.HasPrefix(strings.ToUpper(line), "CVE-") {
					ids = append(ids, strings.ToUpper(line))
				}
			}
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("reading stdin: %w", err)
			}
		}

		if len(ids) == 0 {
			return fmt.Errorf("at least one CVE ID is required")
		}

		ctx := cmd.Context()
		var entries []model.KEVEntry

		for _, id := range ids {
			entry, err := app.KEV.Check(ctx, id)
			if err != nil {
				return err
			}
			if entry != nil {
				entries = append(entries, *entry)
			} else {
				quiet, _ := cmd.Flags().GetBool("quiet")
				if !quiet {
					fmt.Fprintf(os.Stderr, "%s: not in KEV\n", id)
				}
			}
		}

		if len(entries) > 0 {
			return app.Formatter.FormatKEVList(os.Stdout, entries)
		}
		return nil
	},
}

func init() {
	kevCheckCmd.Flags().Bool("stdin", false, "Read CVE IDs from stdin (one per line)")
	kevCmd.AddCommand(kevCheckCmd)
}
