package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trustin-tech/vulnex/internal/model"
)

// testDiffResult returns an SBOMDiffResult with known data for testing formatters.
func testDiffResult() *model.SBOMDiffResult {
	return &model.SBOMDiffResult{
		OldFile:       "old-sbom.json",
		NewFile:       "new-sbom.json",
		OldComponents: 10,
		NewComponents: 12,
		Added: []model.SBOMFinding{
			{
				Ecosystem: "PyPI",
				Name:      "django",
				Version:   "4.1.0",
				Fixed:     "4.1.7",
				Advisory: model.Advisory{
					ID:       "GHSA-aaaa-bbbb-cccc",
					Source:   "osv",
					URL:      "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc",
					Severity: "critical",
					Summary:  "SQL injection in QuerySet.values()",
				},
			},
			{
				Ecosystem: "npm",
				Name:      "express",
				Version:   "4.17.1",
				Fixed:     "4.17.3",
				Advisory: model.Advisory{
					ID:       "GHSA-dddd-eeee-ffff",
					Source:   "osv",
					URL:      "https://osv.dev/vulnerability/GHSA-dddd-eeee-ffff",
					Severity: "high",
					Summary:  "Open redirect in express",
				},
			},
		},
		Removed: []model.SBOMFinding{
			{
				Ecosystem: "npm",
				Name:      "lodash",
				Version:   "4.17.20",
				Fixed:     "4.17.21",
				Advisory: model.Advisory{
					ID:       "GHSA-xxxx-yyyy-zzzz",
					Source:   "osv",
					URL:      "https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz",
					Severity: "high",
					Summary:  "Prototype pollution in lodash",
				},
			},
		},
		Unchanged: []model.SBOMFinding{
			{
				Ecosystem: "Go",
				Name:      "golang.org/x/net",
				Version:   "0.0.0-20210226172049-e18ecbb05110",
				Fixed:     "0.7.0",
				Advisory: model.Advisory{
					ID:       "GHSA-1111-2222-3333",
					Source:   "osv",
					URL:      "https://osv.dev/vulnerability/GHSA-1111-2222-3333",
					Severity: "medium",
					Summary:  "HTTP/2 rapid reset in golang.org/x/net",
				},
			},
		},
	}
}

// testEmptyDiffResult returns an SBOMDiffResult with no findings.
func testEmptyDiffResult() *model.SBOMDiffResult {
	return &model.SBOMDiffResult{
		OldFile:       "old.json",
		NewFile:       "new.json",
		OldComponents: 5,
		NewComponents: 5,
		Added:         nil,
		Removed:       nil,
		Unchanged:     nil,
	}
}

// --- Table formatter tests ---

func TestTableFormatSBOMDiffResult(t *testing.T) {
	f := newTableFormatter(&formatterOpts{NoColor: true})
	var buf bytes.Buffer

	err := f.FormatSBOMDiffResult(&buf, testDiffResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()

	// Verify section headers present
	for _, want := range []string{"ADDED", "REMOVED", "UNCHANGED"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing section %q", want)
		}
	}

	// Verify advisory IDs present
	for _, id := range []string{"GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff", "GHSA-xxxx-yyyy-zzzz", "GHSA-1111-2222-3333"} {
		if !strings.Contains(out, id) {
			t.Errorf("output missing advisory ID %q", id)
		}
	}

	// Verify component names present
	for _, name := range []string{"django", "express", "lodash", "golang.org/x/net"} {
		if !strings.Contains(out, name) {
			t.Errorf("output missing component name %q", name)
		}
	}

	// Verify summary footer
	if !strings.Contains(out, "Summary:") {
		t.Error("output missing Summary footer")
	}
	if !strings.Contains(out, "+2 added") {
		t.Errorf("output missing '+2 added' in summary, got:\n%s", out)
	}
	if !strings.Contains(out, "-1 removed") {
		t.Errorf("output missing '-1 removed' in summary, got:\n%s", out)
	}
}

func TestTableFormatSBOMDiffResult_Empty(t *testing.T) {
	f := newTableFormatter(&formatterOpts{NoColor: true})
	var buf bytes.Buffer

	err := f.FormatSBOMDiffResult(&buf, testEmptyDiffResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()

	// Empty diff should not contain section headers
	for _, section := range []string{"ADDED", "REMOVED", "UNCHANGED"} {
		if strings.Contains(out, section) {
			t.Errorf("empty diff should not contain section %q", section)
		}
	}

	// Should still have a summary line
	if !strings.Contains(out, "Summary:") {
		t.Error("empty diff missing Summary footer")
	}
}

func TestTableFormatSBOMDiffResult_SeverityRendered(t *testing.T) {
	f := newTableFormatter(&formatterOpts{NoColor: true})
	var buf bytes.Buffer

	err := f.FormatSBOMDiffResult(&buf, testDiffResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	// Severities should be uppercased in table output
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM"} {
		if !strings.Contains(out, sev) {
			t.Errorf("output missing severity %q", sev)
		}
	}
}

func TestTableFormatSBOMDiffResult_FixedVersionTruncated(t *testing.T) {
	result := &model.SBOMDiffResult{
		OldFile:       "a.json",
		NewFile:       "b.json",
		OldComponents: 1,
		NewComponents: 1,
		Added: []model.SBOMFinding{
			{
				Ecosystem: "Go",
				Name:      "example.com/pkg",
				Version:   "1.0.0",
				Fixed:     "1.2.3-beta.456789", // longer than 8 chars
				Advisory: model.Advisory{
					ID:       "GHSA-trunc-test",
					Severity: "low",
					Summary:  "test truncation",
				},
			},
		},
	}

	f := newTableFormatter(&formatterOpts{NoColor: true})
	var buf bytes.Buffer
	if err := f.FormatSBOMDiffResult(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	// Fixed version should be truncated to 7 chars + "~"
	if !strings.Contains(out, "1.2.3-b~") {
		t.Errorf("expected truncated fixed version '1.2.3-b~' in output, got:\n%s", out)
	}
}

// --- JSON formatter tests ---

func TestJSONFormatSBOMDiffResult(t *testing.T) {
	f := newJSONFormatter(&formatterOpts{})
	var buf bytes.Buffer

	err := f.FormatSBOMDiffResult(&buf, testDiffResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify valid JSON
	var parsed model.SBOMDiffResult
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if parsed.OldFile != "old-sbom.json" {
		t.Errorf("OldFile = %q, want %q", parsed.OldFile, "old-sbom.json")
	}
	if parsed.NewFile != "new-sbom.json" {
		t.Errorf("NewFile = %q, want %q", parsed.NewFile, "new-sbom.json")
	}
	if parsed.OldComponents != 10 {
		t.Errorf("OldComponents = %d, want 10", parsed.OldComponents)
	}
	if parsed.NewComponents != 12 {
		t.Errorf("NewComponents = %d, want 12", parsed.NewComponents)
	}
	if len(parsed.Added) != 2 {
		t.Errorf("Added count = %d, want 2", len(parsed.Added))
	}
	if len(parsed.Removed) != 1 {
		t.Errorf("Removed count = %d, want 1", len(parsed.Removed))
	}
	if len(parsed.Unchanged) != 1 {
		t.Errorf("Unchanged count = %d, want 1", len(parsed.Unchanged))
	}
}

func TestJSONFormatSBOMDiffResult_Compact(t *testing.T) {
	f := newJSONFormatter(&formatterOpts{Compact: true})
	var buf bytes.Buffer

	err := f.FormatSBOMDiffResult(&buf, testDiffResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	// Compact JSON should not have indentation newlines (except the trailing newline from Fprintln)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 {
		t.Errorf("compact JSON should be single line, got %d lines", len(lines))
	}
}

func TestJSONFormatSBOMDiffResult_Empty(t *testing.T) {
	f := newJSONFormatter(&formatterOpts{})
	var buf bytes.Buffer

	err := f.FormatSBOMDiffResult(&buf, testEmptyDiffResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed model.SBOMDiffResult
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if len(parsed.Added) != 0 {
		t.Errorf("Added count = %d, want 0", len(parsed.Added))
	}
	if len(parsed.Removed) != 0 {
		t.Errorf("Removed count = %d, want 0", len(parsed.Removed))
	}
	if len(parsed.Unchanged) != 0 {
		t.Errorf("Unchanged count = %d, want 0", len(parsed.Unchanged))
	}
}

func TestJSONFormatSBOMDiffResult_RoundTrip(t *testing.T) {
	original := testDiffResult()
	f := newJSONFormatter(&formatterOpts{})
	var buf bytes.Buffer

	if err := f.FormatSBOMDiffResult(&buf, original); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed model.SBOMDiffResult
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Verify all added findings round-trip correctly
	if len(parsed.Added) != len(original.Added) {
		t.Fatalf("Added count mismatch: %d != %d", len(parsed.Added), len(original.Added))
	}
	for i, f := range parsed.Added {
		want := original.Added[i]
		if f.Advisory.ID != want.Advisory.ID {
			t.Errorf("Added[%d].Advisory.ID = %q, want %q", i, f.Advisory.ID, want.Advisory.ID)
		}
		if f.Ecosystem != want.Ecosystem {
			t.Errorf("Added[%d].Ecosystem = %q, want %q", i, f.Ecosystem, want.Ecosystem)
		}
		if f.Name != want.Name {
			t.Errorf("Added[%d].Name = %q, want %q", i, f.Name, want.Name)
		}
		if f.Version != want.Version {
			t.Errorf("Added[%d].Version = %q, want %q", i, f.Version, want.Version)
		}
		if f.Fixed != want.Fixed {
			t.Errorf("Added[%d].Fixed = %q, want %q", i, f.Fixed, want.Fixed)
		}
	}
}

// --- CSV formatter tests ---

func TestCSVFormatSBOMDiffResult(t *testing.T) {
	f := newCSVFormatter(&formatterOpts{})
	var buf bytes.Buffer

	err := f.FormatSBOMDiffResult(&buf, testDiffResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// 1 header + 2 added + 1 removed + 1 unchanged = 5
	if len(lines) != 5 {
		t.Errorf("expected 5 lines, got %d:\n%s", len(lines), buf.String())
	}

	// Verify header
	header := lines[0]
	expectedHeader := "status,ecosystem,name,version,fixed,id,severity,summary"
	if header != expectedHeader {
		t.Errorf("header = %q, want %q", header, expectedHeader)
	}

	// Verify status values appear
	statuses := map[string]bool{}
	for _, line := range lines[1:] {
		parts := strings.SplitN(line, ",", 2)
		statuses[parts[0]] = true
	}
	for _, want := range []string{"added", "removed", "unchanged"} {
		if !statuses[want] {
			t.Errorf("missing status %q in CSV output", want)
		}
	}
}

func TestCSVFormatSBOMDiffResult_Empty(t *testing.T) {
	f := newCSVFormatter(&formatterOpts{})
	var buf bytes.Buffer

	err := f.FormatSBOMDiffResult(&buf, testEmptyDiffResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// Only header row
	if len(lines) != 1 {
		t.Errorf("expected 1 line (header only), got %d:\n%s", len(lines), buf.String())
	}
}

func TestCSVFormatSBOMDiffResult_FieldOrder(t *testing.T) {
	f := newCSVFormatter(&formatterOpts{})
	var buf bytes.Buffer

	result := &model.SBOMDiffResult{
		OldFile:       "a.json",
		NewFile:       "b.json",
		OldComponents: 1,
		NewComponents: 1,
		Added: []model.SBOMFinding{
			{
				Ecosystem: "npm",
				Name:      "lodash",
				Version:   "4.17.20",
				Fixed:     "4.17.21",
				Advisory: model.Advisory{
					ID:       "GHSA-test-1234",
					Severity: "high",
					Summary:  "test vuln",
				},
			},
		},
	}

	if err := f.FormatSBOMDiffResult(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	// Parse second line and verify field values
	data := lines[1]
	// status,ecosystem,name,version,fixed,id,severity,summary
	want := "added,npm,lodash,4.17.20,4.17.21,GHSA-test-1234,high,test vuln"
	if data != want {
		t.Errorf("CSV data row = %q, want %q", data, want)
	}
}

// --- Markdown formatter tests ---

func TestMarkdownFormatSBOMDiffResult(t *testing.T) {
	f := &markdownFormatter{}
	var buf bytes.Buffer

	err := f.FormatSBOMDiffResult(&buf, testDiffResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()

	// Verify title
	if !strings.Contains(out, "# SBOM Vulnerability Diff") {
		t.Error("output missing title")
	}

	// Verify file metadata
	if !strings.Contains(out, "old-sbom.json") {
		t.Error("output missing old file name")
	}
	if !strings.Contains(out, "new-sbom.json") {
		t.Error("output missing new file name")
	}

	// Verify H2 section headers
	for _, section := range []string{"## Added", "## Removed", "## Unchanged"} {
		if !strings.Contains(out, section) {
			t.Errorf("output missing section header %q", section)
		}
	}

	// Verify markdown table structure
	if !strings.Contains(out, "| Ecosystem | Name |") {
		t.Error("output missing markdown table header")
	}

	// Verify advisory IDs in table
	for _, id := range []string{"GHSA-aaaa-bbbb-cccc", "GHSA-xxxx-yyyy-zzzz", "GHSA-1111-2222-3333"} {
		if !strings.Contains(out, id) {
			t.Errorf("output missing advisory ID %q", id)
		}
	}

	// Verify summary footer
	if !strings.Contains(out, "+2 added") {
		t.Errorf("output missing '+2 added' in footer")
	}
	if !strings.Contains(out, "-1 removed") {
		t.Errorf("output missing '-1 removed' in footer")
	}
}

func TestMarkdownFormatSBOMDiffResult_Empty(t *testing.T) {
	f := &markdownFormatter{}
	var buf bytes.Buffer

	err := f.FormatSBOMDiffResult(&buf, testEmptyDiffResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()

	// Should still have the title and metadata
	if !strings.Contains(out, "# SBOM Vulnerability Diff") {
		t.Error("empty diff missing title")
	}

	// Should not contain section headers for empty sections
	for _, section := range []string{"## Added", "## Removed", "## Unchanged"} {
		if strings.Contains(out, section) {
			t.Errorf("empty diff should not contain section %q", section)
		}
	}
}

func TestMarkdownFormatSBOMDiffResult_LongSummaryTruncated(t *testing.T) {
	f := &markdownFormatter{}
	var buf bytes.Buffer

	longSummary := strings.Repeat("A", 100)
	result := &model.SBOMDiffResult{
		OldFile:       "a.json",
		NewFile:       "b.json",
		OldComponents: 1,
		NewComponents: 1,
		Added: []model.SBOMFinding{
			{
				Ecosystem: "npm",
				Name:      "pkg",
				Version:   "1.0.0",
				Advisory: model.Advisory{
					ID:       "GHSA-long",
					Severity: "low",
					Summary:  longSummary,
				},
			},
		},
	}

	if err := f.FormatSBOMDiffResult(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	// Summary should be truncated at 60 chars: 57 + "..."
	if strings.Contains(out, longSummary) {
		t.Error("long summary should be truncated but was not")
	}
	if !strings.Contains(out, "...") {
		t.Error("truncated summary should end with '...'")
	}
}

// --- YAML formatter tests ---

func TestYAMLFormatSBOMDiffResult(t *testing.T) {
	f := &yamlFormatter{}
	var buf bytes.Buffer

	err := f.FormatSBOMDiffResult(&buf, testDiffResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()

	// Verify top-level keys are present in YAML output
	for _, key := range []string{"old_file:", "new_file:", "old_components:", "new_components:", "added:", "removed:", "unchanged:"} {
		if !strings.Contains(out, key) {
			t.Errorf("output missing YAML key %q", key)
		}
	}

	// Verify values
	if !strings.Contains(out, "old-sbom.json") {
		t.Error("output missing old file name value")
	}
	if !strings.Contains(out, "GHSA-aaaa-bbbb-cccc") {
		t.Error("output missing advisory ID in YAML")
	}
}

func TestYAMLFormatSBOMDiffResult_Empty(t *testing.T) {
	f := &yamlFormatter{}
	var buf bytes.Buffer

	err := f.FormatSBOMDiffResult(&buf, testEmptyDiffResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "old_file:") {
		t.Error("empty diff YAML missing old_file key")
	}
}

// --- Template formatter tests ---

func TestTemplateFormatSBOMDiffResult(t *testing.T) {
	tmpl := `Old: {{.OldFile}} New: {{.NewFile}} Added: {{len .Added}} Removed: {{len .Removed}} Unchanged: {{len .Unchanged}}`
	f := newTemplateFormatter(tmpl)
	var buf bytes.Buffer

	err := f.FormatSBOMDiffResult(&buf, testDiffResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	want := "Old: old-sbom.json New: new-sbom.json Added: 2 Removed: 1 Unchanged: 1"
	if out != want {
		t.Errorf("template output = %q, want %q", out, want)
	}
}

func TestTemplateFormatSBOMDiffResult_InvalidTemplate(t *testing.T) {
	tmpl := `{{.InvalidField.Nested}}`
	f := newTemplateFormatter(tmpl)
	var buf bytes.Buffer

	err := f.FormatSBOMDiffResult(&buf, testDiffResult())
	if err == nil {
		t.Error("expected error for invalid template, got nil")
	}
}

func TestTemplateFormatSBOMDiffResult_IterateFindings(t *testing.T) {
	tmpl := `{{range .Added}}{{.Advisory.ID}} {{end}}`
	f := newTemplateFormatter(tmpl)
	var buf bytes.Buffer

	if err := f.FormatSBOMDiffResult(&buf, testDiffResult()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "GHSA-aaaa-bbbb-cccc") {
		t.Errorf("template output missing first advisory ID")
	}
	if !strings.Contains(out, "GHSA-dddd-eeee-ffff") {
		t.Errorf("template output missing second advisory ID")
	}
}

// --- Cross-format consistency tests ---

func TestAllFormatters_NoError(t *testing.T) {
	formats := []string{"table", "json", "csv", "markdown", "yaml"}
	result := testDiffResult()

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			f, err := NewFormatter(format, WithNoColor())
			if err != nil {
				t.Fatalf("NewFormatter(%q) error: %v", format, err)
			}

			var buf bytes.Buffer
			if err := f.FormatSBOMDiffResult(&buf, result); err != nil {
				t.Errorf("FormatSBOMDiffResult error for %s: %v", format, err)
			}

			if buf.Len() == 0 {
				t.Errorf("FormatSBOMDiffResult for %s produced empty output", format)
			}
		})
	}
}

func TestAllFormatters_EmptyResult(t *testing.T) {
	formats := []string{"table", "json", "csv", "markdown", "yaml"}
	result := testEmptyDiffResult()

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			f, err := NewFormatter(format, WithNoColor())
			if err != nil {
				t.Fatalf("NewFormatter(%q) error: %v", format, err)
			}

			var buf bytes.Buffer
			if err := f.FormatSBOMDiffResult(&buf, result); err != nil {
				t.Errorf("FormatSBOMDiffResult error for %s: %v", format, err)
			}
		})
	}
}

// --- Edge case tests ---

func TestFormatSBOMDiffResult_OnlyAdded(t *testing.T) {
	result := &model.SBOMDiffResult{
		OldFile:       "a.json",
		NewFile:       "b.json",
		OldComponents: 0,
		NewComponents: 1,
		Added: []model.SBOMFinding{
			{
				Ecosystem: "npm",
				Name:      "express",
				Version:   "4.17.1",
				Advisory: model.Advisory{
					ID:       "GHSA-only-added",
					Severity: "medium",
					Summary:  "only added vuln",
				},
			},
		},
	}

	f := newTableFormatter(&formatterOpts{NoColor: true})
	var buf bytes.Buffer

	if err := f.FormatSBOMDiffResult(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "ADDED") {
		t.Error("output missing ADDED section")
	}
	if strings.Contains(out, "REMOVED") {
		t.Error("output should not contain REMOVED section")
	}
	if strings.Contains(out, "UNCHANGED") {
		t.Error("output should not contain UNCHANGED section")
	}
}

func TestFormatSBOMDiffResult_OnlyRemoved(t *testing.T) {
	result := &model.SBOMDiffResult{
		OldFile:       "a.json",
		NewFile:       "b.json",
		OldComponents: 1,
		NewComponents: 0,
		Removed: []model.SBOMFinding{
			{
				Ecosystem: "PyPI",
				Name:      "flask",
				Version:   "1.0.0",
				Advisory: model.Advisory{
					ID:       "GHSA-only-removed",
					Severity: "low",
					Summary:  "only removed vuln",
				},
			},
		},
	}

	f := newTableFormatter(&formatterOpts{NoColor: true})
	var buf bytes.Buffer

	if err := f.FormatSBOMDiffResult(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "ADDED") {
		t.Error("output should not contain ADDED section")
	}
	if !strings.Contains(out, "REMOVED") {
		t.Error("output missing REMOVED section")
	}
	if strings.Contains(out, "UNCHANGED") {
		t.Error("output should not contain UNCHANGED section")
	}
}

func TestFormatSBOMDiffResult_EmptyFixedVersion(t *testing.T) {
	result := &model.SBOMDiffResult{
		OldFile:       "a.json",
		NewFile:       "b.json",
		OldComponents: 1,
		NewComponents: 1,
		Added: []model.SBOMFinding{
			{
				Ecosystem: "npm",
				Name:      "pkg",
				Version:   "1.0.0",
				Fixed:     "", // no fix available
				Advisory: model.Advisory{
					ID:       "GHSA-nofix",
					Severity: "high",
					Summary:  "no fix available",
				},
			},
		},
	}

	f := newTableFormatter(&formatterOpts{NoColor: true})
	var buf bytes.Buffer
	if err := f.FormatSBOMDiffResult(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	// Empty fixed should render as "-"
	if !strings.Contains(out, "-") {
		t.Error("empty fixed version should render as '-'")
	}
}

func TestFormatSBOMDiffResult_EmptySeverity(t *testing.T) {
	result := &model.SBOMDiffResult{
		OldFile:       "a.json",
		NewFile:       "b.json",
		OldComponents: 1,
		NewComponents: 1,
		Added: []model.SBOMFinding{
			{
				Ecosystem: "npm",
				Name:      "pkg",
				Version:   "1.0.0",
				Advisory: model.Advisory{
					ID:       "GHSA-nosev",
					Severity: "", // unknown severity
					Summary:  "unknown severity",
				},
			},
		},
	}

	f := newTableFormatter(&formatterOpts{NoColor: true})
	var buf bytes.Buffer
	if err := f.FormatSBOMDiffResult(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "UNKNOWN") {
		t.Error("empty severity should render as 'UNKNOWN'")
	}
}

func TestFormatSBOMDiffResult_MultipleComponentsSameSection(t *testing.T) {
	result := &model.SBOMDiffResult{
		OldFile:       "a.json",
		NewFile:       "b.json",
		OldComponents: 2,
		NewComponents: 2,
		Added: []model.SBOMFinding{
			{
				Ecosystem: "npm",
				Name:      "lodash",
				Version:   "4.17.20",
				Advisory:  model.Advisory{ID: "GHSA-1", Severity: "high", Summary: "vuln 1"},
			},
			{
				Ecosystem: "npm",
				Name:      "lodash",
				Version:   "4.17.20",
				Advisory:  model.Advisory{ID: "GHSA-2", Severity: "medium", Summary: "vuln 2"},
			},
			{
				Ecosystem: "PyPI",
				Name:      "django",
				Version:   "3.2.0",
				Advisory:  model.Advisory{ID: "GHSA-3", Severity: "critical", Summary: "vuln 3"},
			},
		},
	}

	f := newTableFormatter(&formatterOpts{NoColor: true})
	var buf bytes.Buffer
	if err := f.FormatSBOMDiffResult(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	// Both lodash findings should be grouped together
	if !strings.Contains(out, "lodash") {
		t.Error("output missing lodash component")
	}
	if !strings.Contains(out, "django") {
		t.Error("output missing django component")
	}
	// All three advisory IDs present
	for _, id := range []string{"GHSA-1", "GHSA-2", "GHSA-3"} {
		if !strings.Contains(out, id) {
			t.Errorf("output missing advisory %q", id)
		}
	}
}
