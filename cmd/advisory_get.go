package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/trustin-tech/vulnex/internal/api/ghsa"
	"github.com/trustin-tech/vulnex/internal/model"
)

var advisoryGetCmd = &cobra.Command{
	Use:   "get <GHSA-ID>",
	Short: "Get a specific advisory",
	Long:  "Retrieve detailed information about a specific GitHub Advisory.",
	Example: `  vulnex advisory get GHSA-jfh8-c2jp-5v3q
  vulnex advisory get GHSA-jfh8-c2jp-5v3q --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		advisory, err := app.GHSA.GetAdvisory(cmd.Context(), args[0])
		if err != nil {
			return err
		}

		if advisory == nil {
			return fmt.Errorf("advisory %s not found", args[0])
		}

		enriched := toEnrichedAdvisory(advisory)
		return app.Formatter.FormatAdvisory(os.Stdout, enriched)
	},
}

func toEnrichedAdvisory(a *ghsa.GHSAdvisory) *model.EnrichedAdvisory {
	adv := &model.EnrichedAdvisory{
		ID:          a.GHSAID,
		CVEID:       a.CVEID,
		Source:      "ghsa",
		URL:         a.URL,
		Severity:    a.Severity,
		Summary:     a.Summary,
		Description: a.Description,
		References:  a.References,
		PublishedAt: a.PublishedAt,
		UpdatedAt:   a.UpdatedAt,
	}

	if a.WithdrawnAt != nil {
		adv.WithdrawnAt = *a.WithdrawnAt
	}

	if a.CVSS != nil {
		adv.CVSSScore = a.CVSS.Score
		adv.CVSSVector = a.CVSS.VectorString
	}

	if a.EPSS != nil {
		adv.EPSSScore = a.EPSS.Percentage
		adv.EPSSPctile = a.EPSS.Percentile
	}

	for _, cwe := range a.CWEs {
		adv.CWEs = append(adv.CWEs, model.CWEEntry{
			ID:          cwe.CWEID,
			Description: cwe.Name,
		})
	}

	for _, v := range a.Vulnerabilities {
		pkg := model.AffectedPkg{
			Ecosystem: v.Package.Ecosystem,
			Name:      v.Package.Name,
		}
		if v.FirstPatchedVersion != nil {
			pkg.Fixed = *v.FirstPatchedVersion
		} else if v.PatchedVersions != "" {
			pkg.Fixed = v.PatchedVersions
		}
		adv.Packages = append(adv.Packages, pkg)
	}

	return adv
}

func init() {
	advisoryCmd.AddCommand(advisoryGetCmd)
}
