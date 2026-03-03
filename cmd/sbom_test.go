package cmd

import (
	"testing"

	"github.com/trustin-tech/vulnex/internal/model"
)

func TestFilterBySeverity(t *testing.T) {
	findings := []model.SBOMFinding{
		{Name: "a", Advisory: model.Advisory{ID: "1", Severity: "critical"}},
		{Name: "b", Advisory: model.Advisory{ID: "2", Severity: "high"}},
		{Name: "c", Advisory: model.Advisory{ID: "3", Severity: "medium"}},
		{Name: "d", Advisory: model.Advisory{ID: "4", Severity: "low"}},
		{Name: "e", Advisory: model.Advisory{ID: "5", Severity: "critical"}},
	}

	tests := []struct {
		name     string
		severity string
		wantIDs  []string
	}{
		{"critical", "critical", []string{"1", "5"}},
		{"high", "high", []string{"2"}},
		{"medium", "medium", []string{"3"}},
		{"low", "low", []string{"4"}},
		{"case insensitive", "CRITICAL", []string{"1", "5"}},
		{"mixed case", "High", []string{"2"}},
		{"no match", "unknown", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterBySeverity(findings, tt.severity)
			if len(got) != len(tt.wantIDs) {
				t.Fatalf("filterBySeverity(%q) returned %d findings, want %d", tt.severity, len(got), len(tt.wantIDs))
			}
			for i, f := range got {
				if f.Advisory.ID != tt.wantIDs[i] {
					t.Errorf("filterBySeverity(%q)[%d].Advisory.ID = %q, want %q", tt.severity, i, f.Advisory.ID, tt.wantIDs[i])
				}
			}
		})
	}
}

func TestFilterBySeverity_EmptyInput(t *testing.T) {
	got := filterBySeverity(nil, "critical")
	if len(got) != 0 {
		t.Errorf("filterBySeverity(nil) returned %d findings, want 0", len(got))
	}

	got = filterBySeverity([]model.SBOMFinding{}, "high")
	if len(got) != 0 {
		t.Errorf("filterBySeverity([]) returned %d findings, want 0", len(got))
	}
}

func TestMapEcosystemToOSV(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"npm", "npm"},
		{"pypi", "PyPI"},
		{"pip", "PyPI"},
		{"maven", "Maven"},
		{"go", "Go"},
		{"golang", "Go"},
		{"cargo", "crates.io"},
		{"nuget", "NuGet"},
		{"gem", "RubyGems"},
		{"rubygems", "RubyGems"},
		{"composer", "Packagist"},
		{"hex", "Hex"},
		{"pub", "Pub"},
		{"swift", "SwiftURL"},
		{"unknown", "unknown"},
		{"NPM", "npm"},
		{"PyPI", "PyPI"},
		{"MAVEN", "Maven"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := mapEcosystemToOSV(tt.input)
			if got != tt.want {
				t.Errorf("mapEcosystemToOSV(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
