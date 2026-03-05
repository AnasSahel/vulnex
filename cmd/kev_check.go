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
		outputFmt, _ := cmd.Flags().GetString("output")
		noColor, _ := cmd.Flags().GetBool("no-color")
		long, _ := cmd.Flags().GetBool("long")
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

		if len(entries) == 0 {
			return nil
		}

		// Non-table formats use the standard formatter
		if outputFmt != "" && outputFmt != "table" {
			return app.Formatter.FormatKEVList(os.Stdout, entries)
		}

		// Table format: render each entry as label-value rows
		s := newCmdStyles(noColor)
		truncate := func(text string) string {
			if long || len(text) <= 80 {
				return text
			}
			return text[:77] + "..."
		}

		for i, entry := range entries {
			if i > 0 {
				fmt.Fprintln(os.Stdout)
			}
			fmt.Fprintf(os.Stdout, "%s %s\n", s.label.Render("CVE ID:"), s.cveID.Render(entry.CVEID))
			if entry.VulnerabilityName != "" {
				fmt.Fprintf(os.Stdout, "%s %s\n", s.label.Render("Name:"), truncate(entry.VulnerabilityName))
			}
			fmt.Fprintf(os.Stdout, "%s %s\n", s.label.Render("Vendor:"), entry.VendorProject)
			fmt.Fprintf(os.Stdout, "%s %s\n", s.label.Render("Product:"), entry.Product)
			if entry.ShortDescription != "" {
				fmt.Fprintf(os.Stdout, "%s %s\n", s.label.Render("Description:"), truncate(entry.ShortDescription))
			}
			fmt.Fprintf(os.Stdout, "%s %s\n", s.label.Render("Date Added:"), entry.DateAdded)
			fmt.Fprintf(os.Stdout, "%s %s\n", s.label.Render("Due Date:"), entry.DueDate)
			fmt.Fprintf(os.Stdout, "%s %s\n", s.label.Render("Required Action:"), truncate(entry.RequiredAction))
			if entry.KnownRansomwareCampaign != "" {
				label := entry.KnownRansomwareCampaign
				if strings.EqualFold(label, "Known") {
					label = s.critical.Render(label)
				}
				fmt.Fprintf(os.Stdout, "%s %s\n", s.label.Render("Ransomware:"), label)
			}
			if entry.Notes != "" {
				fmt.Fprintf(os.Stdout, "%s %s\n", s.label.Render("Notes:"), truncate(entry.Notes))
			}
		}

		return nil
	},
}

func init() {
	kevCheckCmd.Flags().Bool("stdin", false, "Read CVE IDs from stdin (one per line)")
	kevCmd.AddCommand(kevCheckCmd)
}
