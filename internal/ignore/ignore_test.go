package ignore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/trustin-tech/vulnex/internal/model"
)

var now = time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, ".vulnexignore", `
suppressions:
  - id: GHSA-2gwj-7jmv-h26r
    package: django
    reason: "mitigated at WAF"
    expires: "2026-06-01"
    approved_by: security-team
  - id: GHSA-xxxx-yyyy-zzzz
    reason: "false positive"
`)

	f, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f.Suppressions) != 2 {
		t.Fatalf("expected 2 suppressions, got %d", len(f.Suppressions))
	}
	if f.Suppressions[0].ID != "GHSA-2gwj-7jmv-h26r" {
		t.Errorf("expected ID GHSA-2gwj-7jmv-h26r, got %s", f.Suppressions[0].ID)
	}
	if f.Suppressions[0].ApprovedBy != "security-team" {
		t.Errorf("expected approved_by security-team, got %s", f.Suppressions[0].ApprovedBy)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	f, err := Load("/nonexistent/.vulnexignore")
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if len(f.Suppressions) != 0 {
		t.Fatalf("expected 0 suppressions, got %d", len(f.Suppressions))
	}
}

func TestLoad_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, ".vulnexignore", `not: [valid: yaml: {`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
}

func TestApply_ExactIDMatch(t *testing.T) {
	f := &File{
		Suppressions: []Suppression{
			{ID: "GHSA-2gwj-7jmv-h26r", Reason: "accepted risk"},
		},
	}
	findings := []model.SBOMFinding{
		{Name: "django", Advisory: model.Advisory{ID: "GHSA-2gwj-7jmv-h26r"}},
		{Name: "lodash", Advisory: model.Advisory{ID: "GHSA-other"}},
	}

	active, suppressed := f.Apply(findings, now)
	if len(suppressed) != 1 || suppressed[0].Advisory.ID != "GHSA-2gwj-7jmv-h26r" {
		t.Errorf("expected 1 suppressed finding (GHSA-2gwj-7jmv-h26r), got %d", len(suppressed))
	}
	if len(active) != 1 || active[0].Advisory.ID != "GHSA-other" {
		t.Errorf("expected 1 active finding (GHSA-other), got %d", len(active))
	}
}

func TestApply_IDAndPackageScoped(t *testing.T) {
	f := &File{
		Suppressions: []Suppression{
			{ID: "GHSA-2gwj-7jmv-h26r", Package: "django", Reason: "scoped"},
		},
	}
	findings := []model.SBOMFinding{
		{Name: "django", Advisory: model.Advisory{ID: "GHSA-2gwj-7jmv-h26r"}},
		{Name: "flask", Advisory: model.Advisory{ID: "GHSA-2gwj-7jmv-h26r"}},
	}

	active, suppressed := f.Apply(findings, now)
	if len(suppressed) != 1 || suppressed[0].Name != "django" {
		t.Errorf("expected django suppressed, got %v", suppressed)
	}
	if len(active) != 1 || active[0].Name != "flask" {
		t.Errorf("expected flask active, got %v", active)
	}
}

func TestApply_WrongPackageNotSuppressed(t *testing.T) {
	f := &File{
		Suppressions: []Suppression{
			{ID: "GHSA-2gwj-7jmv-h26r", Package: "django", Reason: "scoped to django"},
		},
	}
	findings := []model.SBOMFinding{
		{Name: "flask", Advisory: model.Advisory{ID: "GHSA-2gwj-7jmv-h26r"}},
	}

	active, suppressed := f.Apply(findings, now)
	if len(suppressed) != 0 {
		t.Errorf("expected 0 suppressed, got %d", len(suppressed))
	}
	if len(active) != 1 {
		t.Errorf("expected 1 active, got %d", len(active))
	}
}

func TestApply_ExpiredEntryNotSuppressed(t *testing.T) {
	f := &File{
		Suppressions: []Suppression{
			{ID: "GHSA-2gwj-7jmv-h26r", Reason: "expired", Expires: "2026-01-01"},
		},
	}
	findings := []model.SBOMFinding{
		{Name: "django", Advisory: model.Advisory{ID: "GHSA-2gwj-7jmv-h26r"}},
	}

	active, suppressed := f.Apply(findings, now)
	if len(suppressed) != 0 {
		t.Errorf("expected 0 suppressed (expired), got %d", len(suppressed))
	}
	if len(active) != 1 {
		t.Errorf("expected 1 active, got %d", len(active))
	}
}

func TestApply_NoExpiryAlwaysSuppresses(t *testing.T) {
	f := &File{
		Suppressions: []Suppression{
			{ID: "GHSA-2gwj-7jmv-h26r", Reason: "no expiry"},
		},
	}
	findings := []model.SBOMFinding{
		{Name: "django", Advisory: model.Advisory{ID: "GHSA-2gwj-7jmv-h26r"}},
	}

	active, suppressed := f.Apply(findings, now)
	if len(suppressed) != 1 {
		t.Errorf("expected 1 suppressed, got %d", len(suppressed))
	}
	if len(active) != 0 {
		t.Errorf("expected 0 active, got %d", len(active))
	}
}

func TestApply_MalformedExpiryTreatedAsNoExpiry(t *testing.T) {
	f := &File{
		Suppressions: []Suppression{
			{ID: "GHSA-2gwj-7jmv-h26r", Reason: "bad date", Expires: "not-a-date"},
		},
	}
	findings := []model.SBOMFinding{
		{Name: "django", Advisory: model.Advisory{ID: "GHSA-2gwj-7jmv-h26r"}},
	}

	active, suppressed := f.Apply(findings, now)
	if len(suppressed) != 1 {
		t.Errorf("expected 1 suppressed (malformed date = no expiry), got %d", len(suppressed))
	}
	if len(active) != 0 {
		t.Errorf("expected 0 active, got %d", len(active))
	}
}

func TestApply_EmptySuppressions(t *testing.T) {
	f := &File{}
	findings := []model.SBOMFinding{
		{Name: "django", Advisory: model.Advisory{ID: "GHSA-2gwj-7jmv-h26r"}},
	}

	active, suppressed := f.Apply(findings, now)
	if len(suppressed) != 0 {
		t.Errorf("expected 0 suppressed, got %d", len(suppressed))
	}
	if len(active) != 1 {
		t.Errorf("expected 1 active, got %d", len(active))
	}
}

func TestApply_CaseInsensitiveMatch(t *testing.T) {
	f := &File{
		Suppressions: []Suppression{
			{ID: "ghsa-2gwj-7jmv-h26r", Package: "Django", Reason: "case test"},
		},
	}
	findings := []model.SBOMFinding{
		{Name: "django", Advisory: model.Advisory{ID: "GHSA-2gwj-7jmv-h26r"}},
	}

	_, suppressed := f.Apply(findings, now)
	if len(suppressed) != 1 {
		t.Errorf("expected case-insensitive match, got %d suppressed", len(suppressed))
	}
}
