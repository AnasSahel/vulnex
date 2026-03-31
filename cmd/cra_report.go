package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	githubapi "github.com/trustin-tech/vulnex/internal/api/github"
	"github.com/trustin-tech/vulnex/internal/cra"
	"github.com/trustin-tech/vulnex/internal/sbom"
)

var craReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a CRA evidence pack for a GitHub release",
	Long: `Generate a structured CRA (EU Cyber Resilience Act) evidence pack for a
specific GitHub repository release.

The evidence pack includes six sections:
  1. Product identity and release metadata
  2. SBOM component inventory           (requires --sbom)
  3. Known vulnerabilities and VEX       (requires --sbom)
  4. Vulnerability handling record       (requires --handling)
  5. Secure development lifecycle        (requires GitHub token with repo scope)
  6. Annex I obligation mapping table

Output defaults to stdout. Use --output-file to write to a file.`,
	Example: `  vulnex cra report --repo owner/repo --release v1.2.3
  vulnex cra report --repo owner/repo --release v1.2.3 --sbom bom.json
  vulnex cra report --repo owner/repo --release v1.2.3 --sbom bom.json --handling decisions.json
  vulnex cra report --repo owner/repo --release v1.2.3 --format json
  vulnex cra report --repo owner/repo --release v1.2.3 --output-file evidence.html`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCRAReport(cmd)
	},
}

func init() {
	craReportCmd.Flags().String("repo", "", "GitHub repository in owner/repo format (required)")
	craReportCmd.Flags().String("release", "", "Release tag, e.g. v1.2.3 (required)")
	craReportCmd.Flags().String("sbom", "", "Path to CycloneDX or SPDX SBOM file (optional)")
	craReportCmd.Flags().String("handling", "", "Path to JSON vulnerability handling decisions file (optional)")
	craReportCmd.Flags().String("format", "html", "Output format: html or json")
	craReportCmd.Flags().String("output-file", "", "Write output to file instead of stdout")
	craReportCmd.Flags().String("branch", "main", "Branch to check for protection rules")

	_ = craReportCmd.MarkFlagRequired("repo")
	_ = craReportCmd.MarkFlagRequired("release")

	craCmd.AddCommand(craReportCmd)
}

func runCRAReport(cmd *cobra.Command) error {
	repoFlag, _ := cmd.Flags().GetString("repo")
	releaseTag, _ := cmd.Flags().GetString("release")
	sbomFile, _ := cmd.Flags().GetString("sbom")
	handlingFile, _ := cmd.Flags().GetString("handling")
	format, _ := cmd.Flags().GetString("format")
	outputFile, _ := cmd.Flags().GetString("output-file")
	branch, _ := cmd.Flags().GetString("branch")

	// Validate --repo format
	parts := strings.SplitN(repoFlag, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("repo must be in owner/repo format (got %q)", repoFlag)
	}
	owner, repo := parts[0], parts[1]

	report := &cra.Report{
		Meta: cra.ReportMeta{
			Repo:    repoFlag,
			Release: releaseTag,
			Branch:  branch,
		},
		CLIVersion: versionStr,
	}

	// --- Section 1: release metadata + commit info ---
	ghClient := githubapi.NewClient(app.Config.APIKeys.GitHub)

	release, err := ghClient.GetRelease(cmd.Context(), owner, repo, releaseTag)
	if err != nil {
		return fmt.Errorf("fetching release: %w", err)
	}

	report.Product = cra.ProductSection{
		Name:         repo,
		Version:      releaseTag,
		TagName:      release.TagName,
		PublishedAt:  release.PublishedAt,
		ReleaseURL:   release.HTMLURL,
		ReleaseNotes: release.Body,
	}

	// Fetch commit signing info (pass tag name; GitHub resolves it to a commit)
	commitInfo, err := ghClient.GetCommit(cmd.Context(), owner, repo, releaseTag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not fetch commit info: %v\n", err)
	} else if commitInfo != nil {
		report.Product.CommitSHA = commitInfo.SHA
		report.Product.CommitAuthor = commitInfo.AuthorName
		report.Product.CommitDate = commitInfo.AuthorDate
		report.Product.CommitVerification = commitInfo.VerificationStatus
	}

	// --- Section 2 + 3: SBOM and vulnerabilities ---
	if sbomFile != "" {
		components, parseErr := sbom.ParseFile(sbomFile)
		if parseErr != nil {
			return fmt.Errorf("parsing SBOM %s: %w", sbomFile, parseErr)
		}

		sbomSection := cra.SBOMSection{Provided: true, FilePath: sbomFile}
		for _, c := range components {
			sbomSection.Components = append(sbomSection.Components, cra.SBOMComponent{
				Name:      c.Name,
				Version:   c.Version,
				Ecosystem: c.Ecosystem,
				PURL:      c.PURL,
			})
		}
		report.SBOM = sbomSection

		// Vulnerability scan reuses the existing scanSBOM pipeline
		_, findings, _, scanErr := scanSBOM(cmd.Context(), sbomFile, "", true)
		if scanErr != nil {
			fmt.Fprintf(os.Stderr, "warning: vulnerability scan failed: %v\n", scanErr)
		} else {
			vulnSection := cra.VulnSection{Provided: len(findings) > 0}
			for _, f := range findings {
				severity := ""
				if f.Risk != nil {
					severity = string(f.Risk.Priority)
				}
				vulnSection.Findings = append(vulnSection.Findings, cra.VulnFinding{
					ID:        f.Advisory.ID,
					Summary:   f.Advisory.Summary,
					Severity:  severity,
					Package:   f.Name,
					Version:   f.Version,
					Ecosystem: f.Ecosystem,
				})
			}
			report.Vulns = vulnSection
		}
	}

	// --- Section 4: vulnerability handling decisions ---
	if handlingFile != "" {
		data, readErr := os.ReadFile(handlingFile)
		if readErr != nil {
			return fmt.Errorf("reading handling file %s: %w", handlingFile, readErr)
		}
		var decisions []cra.VulnDecision
		if unmarshalErr := json.Unmarshal(data, &decisions); unmarshalErr != nil {
			return fmt.Errorf("parsing handling file %s (expected JSON array): %w", handlingFile, unmarshalErr)
		}
		report.Handling = cra.HandlingSection{Provided: true, Decisions: decisions}
	}

	// --- Section 5: SDL attestation ---
	bp, bpErr := ghClient.GetBranchProtection(cmd.Context(), owner, repo, branch)
	if bpErr != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", bpErr)
		report.SDL = cra.SDLSection{
			Available:  false,
			Skipped:    true,
			SkipReason: bpErr.Error(),
		}
	} else if bp == nil {
		report.SDL = cra.SDLSection{Available: true, BranchProtected: false}
	} else {
		report.SDL = cra.SDLSection{
			Available:           true,
			BranchProtected:     true,
			RequiredReviews:     bp.RequiredReviewCount,
			DismissStaleReviews: bp.DismissStaleReviews,
			EnforceAdmins:       bp.EnforceAdmins,
			CommitSigned:        report.Product.CommitVerification == "verified",
		}
	}

	// --- Section 6: Annex I mapping ---
	report.AnnexI = buildAnnexI(report)

	// --- Output ---
	out := cmd.OutOrStdout()
	if outputFile != "" {
		f, createErr := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if createErr != nil {
			return fmt.Errorf("opening output file %s: %w", outputFile, createErr)
		}
		defer f.Close()
		out = f
	}

	return cra.Render(out, report, format)
}

// buildAnnexI constructs the CRA Annex I obligation mapping from report data.
func buildAnnexI(r *cra.Report) cra.AnnexISection {
	return cra.AnnexISection{
		Items: []cra.AnnexIItem{
			{
				Obligation: "SBOM available (Annex I, §1)",
				Evidence:   sbomEvidence(r),
				Status:     sbomStatus(r),
			},
			{
				Obligation: "Known vulnerabilities addressed (Annex I, §2)",
				Evidence:   vulnEvidence(r),
				Status:     vulnStatus(r),
			},
			{
				Obligation: "Vulnerability handling policy (Annex I, §3)",
				Evidence:   handlingEvidence(r),
				Status:     handlingStatus(r),
			},
			{
				Obligation: "Vulnerability reporting within 24h (Annex I, §4)",
				Evidence:   "Manual input required — populate via --disclosures",
				Status:     "manual_input",
			},
			{
				Obligation: "Secure development lifecycle (Annex I, §5)",
				Evidence:   sdlEvidence(r),
				Status:     sdlStatus(r),
			},
			{
				Obligation: "Release documentation (Annex I, §6)",
				Evidence:   releaseEvidence(r),
				Status:     releaseStatus(r),
			},
		},
	}
}

func sbomEvidence(r *cra.Report) string {
	if r.SBOM.Provided {
		return fmt.Sprintf("SBOM provided — %d components (%s)", len(r.SBOM.Components), r.SBOM.FilePath)
	}
	return "Not provided — run with --sbom <file>"
}

func sbomStatus(r *cra.Report) string {
	if r.SBOM.Provided {
		return "covered"
	}
	return "not_covered"
}

func vulnEvidence(r *cra.Report) string {
	if !r.SBOM.Provided {
		return "Requires SBOM — run with --sbom <file>"
	}
	if len(r.Vulns.Findings) == 0 {
		return "SBOM scanned — no vulnerabilities found"
	}
	return fmt.Sprintf("%d findings in SBOM scan", len(r.Vulns.Findings))
}

func vulnStatus(r *cra.Report) string {
	if !r.SBOM.Provided {
		return "not_covered"
	}
	if r.Handling.Provided || len(r.Vulns.Findings) == 0 {
		return "covered"
	}
	return "partial"
}

func handlingEvidence(r *cra.Report) string {
	if r.Handling.Provided {
		return fmt.Sprintf("%d handling decisions recorded", len(r.Handling.Decisions))
	}
	return "Not provided — run with --handling <decisions.json>"
}

func handlingStatus(r *cra.Report) string {
	if r.Handling.Provided {
		return "covered"
	}
	return "manual_input"
}

func sdlEvidence(r *cra.Report) string {
	if r.SDL.Skipped {
		return "Section skipped: " + r.SDL.SkipReason
	}
	if !r.SDL.Available {
		return "Not available — requires GitHub token with repo scope"
	}
	if r.SDL.BranchProtected {
		return fmt.Sprintf("Branch protection enabled — required reviews: %d, enforce admins: %v", r.SDL.RequiredReviews, r.SDL.EnforceAdmins)
	}
	return "Branch protection not configured"
}

func sdlStatus(r *cra.Report) string {
	if r.SDL.Skipped || !r.SDL.Available {
		return "manual_input"
	}
	if r.SDL.BranchProtected && r.SDL.RequiredReviews > 0 {
		return "covered"
	}
	if r.SDL.BranchProtected {
		return "partial"
	}
	return "not_covered"
}

func releaseEvidence(r *cra.Report) string {
	if r.Product.ReleaseURL != "" {
		return fmt.Sprintf("GitHub Release: %s (tag: %s)", r.Product.ReleaseURL, r.Product.TagName)
	}
	return fmt.Sprintf("Tag: %s (no GitHub Release found)", r.Product.TagName)
}

func releaseStatus(r *cra.Report) string {
	if r.Product.TagName != "" {
		return "covered"
	}
	return "not_covered"
}
