package cra_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trustin-tech/vulnex/internal/cra"
)

// minimalReport returns a report with all required fields set.
func minimalReport() *cra.Report {
	return &cra.Report{
		Meta: cra.ReportMeta{
			Repo:    "owner/repo",
			Release: "v1.0.0",
			Branch:  "main",
		},
		Product: cra.ProductSection{
			Name:    "repo",
			Version: "v1.0.0",
			TagName: "v1.0.0",
		},
		CLIVersion:  "0.1.0",
		GeneratedAt: "2026-03-01T10:00:00Z",
		AnnexI: cra.AnnexISection{
			Items: []cra.AnnexIItem{
				{Obligation: "SBOM available", Evidence: "Not provided", Status: "not_covered"},
				{Obligation: "Vulnerabilities addressed", Evidence: "Requires SBOM", Status: "not_covered"},
				{Obligation: "Handling policy", Evidence: "Not provided", Status: "manual_input"},
				{Obligation: "24h reporting", Evidence: "Manual input required", Status: "manual_input"},
				{Obligation: "SDL", Evidence: "Branch protection enabled", Status: "covered"},
				{Obligation: "Release docs", Evidence: "Tag: v1.0.0", Status: "covered"},
			},
		},
	}
}

func TestRender_HTML_ContainsExpectedSections(t *testing.T) {
	r := minimalReport()
	var buf bytes.Buffer
	if err := cra.Render(&buf, r, "html"); err != nil {
		t.Fatalf("Render HTML: %v", err)
	}
	out := buf.String()

	checks := []string{
		"CRA Evidence Pack",
		"owner/repo",
		"v1.0.0",
		"vulnex 0.1.0",
		"2026-03-01T10:00:00Z",
		"Product Identity",
		"Software Bill of Materials",
		"Known Vulnerabilities",
		"Vulnerability Handling Record",
		"Secure Development Lifecycle",
		"Annex I Obligation Mapping",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("HTML output missing %q", want)
		}
	}
}

func TestRender_HTML_XSSEscaped(t *testing.T) {
	r := minimalReport()
	r.Vulns = cra.VulnSection{
		Provided: true,
		Findings: []cra.VulnFinding{
			{
				ID:      "CVE-2026-0001",
				Summary: "<script>alert('xss')</script>",
				Package: "evil-pkg",
				Version: "1.0.0",
			},
		},
	}
	r.SBOM = cra.SBOMSection{Provided: true, FilePath: "bom.json"}

	var buf bytes.Buffer
	if err := cra.Render(&buf, r, "html"); err != nil {
		t.Fatalf("Render HTML: %v", err)
	}
	out := buf.String()

	if strings.Contains(out, "<script>alert") {
		t.Error("HTML output contains unescaped <script> tag — XSS risk")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("HTML output should contain escaped &lt;script&gt;")
	}
}

func TestRender_HTML_SBOMOmitted_ShowsPlaceholder(t *testing.T) {
	r := minimalReport()
	// SBOM.Provided = false (default)

	var buf bytes.Buffer
	if err := cra.Render(&buf, r, "html"); err != nil {
		t.Fatalf("Render HTML: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "--sbom") {
		t.Error("HTML output should show --sbom placeholder when SBOM not provided")
	}
}

func TestRender_HTML_HandlingOmitted_ShowsPlaceholder(t *testing.T) {
	r := minimalReport()
	// Handling.Provided = false (default)

	var buf bytes.Buffer
	if err := cra.Render(&buf, r, "html"); err != nil {
		t.Fatalf("Render HTML: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "--handling") {
		t.Error("HTML output should show --handling placeholder when handling not provided")
	}
}

func TestRender_HTML_CLIVersionInHeader(t *testing.T) {
	r := minimalReport()
	r.CLIVersion = "1.2.3"

	var buf bytes.Buffer
	if err := cra.Render(&buf, r, "html"); err != nil {
		t.Fatalf("Render HTML: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "vulnex 1.2.3") {
		t.Errorf("HTML output should contain CLI version 1.2.3; got output starting with: %q", out[:min(200, len(out))])
	}
}

func TestRender_HTML_WithFullSBOMAndVulns(t *testing.T) {
	r := minimalReport()
	r.SBOM = cra.SBOMSection{
		Provided: true,
		FilePath: "bom.json",
		Components: []cra.SBOMComponent{
			{Name: "lodash", Version: "4.17.21", Ecosystem: "npm", PURL: "pkg:npm/lodash@4.17.21"},
		},
	}
	r.Vulns = cra.VulnSection{
		Provided: true,
		Findings: []cra.VulnFinding{
			{ID: "CVE-2026-9999", Summary: "Prototype pollution", Severity: "HIGH", Package: "lodash", Version: "4.17.21"},
		},
	}
	r.Handling = cra.HandlingSection{
		Provided: true,
		Decisions: []cra.VulnDecision{
			{VulnID: "CVE-2026-9999", Status: "accepted", Rationale: "Risk accepted", Date: "2026-03-01"},
		},
	}

	var buf bytes.Buffer
	if err := cra.Render(&buf, r, "html"); err != nil {
		t.Fatalf("Render HTML with full data: %v", err)
	}
	out := buf.String()

	for _, want := range []string{"lodash", "CVE-2026-9999", "Prototype pollution", "accepted", "Risk accepted"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML output missing %q", want)
		}
	}
}

func TestRender_HTML_SDLSkipped(t *testing.T) {
	r := minimalReport()
	r.SDL = cra.SDLSection{
		Skipped:    true,
		SkipReason: "access denied: requires token",
	}

	var buf bytes.Buffer
	if err := cra.Render(&buf, r, "html"); err != nil {
		t.Fatalf("Render HTML: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "access denied: requires token") {
		t.Error("HTML output should show SDL skip reason")
	}
}

func TestRender_JSON_ValidStructure(t *testing.T) {
	r := minimalReport()
	var buf bytes.Buffer
	if err := cra.Render(&buf, r, "json"); err != nil {
		t.Fatalf("Render JSON: %v", err)
	}

	var decoded cra.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v", err)
	}
	if decoded.Meta.Repo != "owner/repo" {
		t.Errorf("Meta.Repo = %q, want %q", decoded.Meta.Repo, "owner/repo")
	}
	if decoded.CLIVersion != "0.1.0" {
		t.Errorf("CLIVersion = %q, want %q", decoded.CLIVersion, "0.1.0")
	}
}

func TestRender_JSON_IsIndented(t *testing.T) {
	r := minimalReport()
	var buf bytes.Buffer
	if err := cra.Render(&buf, r, "json"); err != nil {
		t.Fatalf("Render JSON: %v", err)
	}
	if !strings.Contains(buf.String(), "\n  ") {
		t.Error("JSON output should be indented")
	}
}

func TestRender_UnknownFormat_ReturnsError(t *testing.T) {
	r := minimalReport()
	var buf bytes.Buffer
	err := cra.Render(&buf, r, "pdf")
	if err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
	if !strings.Contains(err.Error(), "pdf") {
		t.Errorf("error should mention format name; got: %v", err)
	}
}

func TestRender_NilReport_ReturnsError(t *testing.T) {
	var buf bytes.Buffer
	err := cra.Render(&buf, nil, "html")
	if err == nil {
		t.Fatal("expected error for nil report, got nil")
	}
}

func TestRender_HTML_EmptyFormat_DefaultsToHTML(t *testing.T) {
	r := minimalReport()
	var buf bytes.Buffer
	if err := cra.Render(&buf, r, ""); err != nil {
		t.Fatalf("Render with empty format: %v", err)
	}
	if !strings.Contains(buf.String(), "<!DOCTYPE html>") {
		t.Error("empty format should default to HTML output")
	}
}

func TestRender_GeneratedAt_AutoSet(t *testing.T) {
	r := minimalReport()
	r.GeneratedAt = "" // clear it

	var buf bytes.Buffer
	if err := cra.Render(&buf, r, "html"); err != nil {
		t.Fatalf("Render HTML: %v", err)
	}
	if r.GeneratedAt == "" {
		t.Error("GeneratedAt should be auto-populated when empty")
	}
}

func TestRender_HTML_AnnexIStatusClasses(t *testing.T) {
	r := minimalReport()
	r.AnnexI = cra.AnnexISection{
		Items: []cra.AnnexIItem{
			{Obligation: "Item A", Evidence: "Evidence", Status: "covered"},
			{Obligation: "Item B", Evidence: "Evidence", Status: "partial"},
			{Obligation: "Item C", Evidence: "Evidence", Status: "not_covered"},
			{Obligation: "Item D", Evidence: "Evidence", Status: "manual_input"},
		},
	}

	var buf bytes.Buffer
	if err := cra.Render(&buf, r, "html"); err != nil {
		t.Fatalf("Render HTML: %v", err)
	}
	out := buf.String()

	for _, want := range []string{"status-covered", "status-partial", "status-not-covered", "status-manual"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML output missing CSS class %q", want)
		}
	}
}

func TestRender_HTML_CommitVerificationBadges(t *testing.T) {
	cases := []struct {
		status string
		badge  string
	}{
		{"verified", "badge-verified"},
		{"unverified", "badge-unverified"},
		{"unknown", "badge-unknown"},
	}
	for _, tc := range cases {
		r := minimalReport()
		r.Product.CommitVerification = tc.status

		var buf bytes.Buffer
		if err := cra.Render(&buf, r, "html"); err != nil {
			t.Fatalf("Render HTML for %q: %v", tc.status, err)
		}
		if !strings.Contains(buf.String(), tc.badge) {
			t.Errorf("status=%q: expected badge class %q in output", tc.status, tc.badge)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
