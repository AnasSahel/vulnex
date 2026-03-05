package scanner

import (
	"bytes"
	"os"
	"testing"
)

func TestDetect_Trivy(t *testing.T) {
	data, err := os.ReadFile("../../testdata/trivy-sample.json")
	if err != nil {
		t.Fatal(err)
	}

	parser, format, err := Detect(data)
	if err != nil {
		t.Fatal(err)
	}
	if format != "trivy" {
		t.Errorf("expected format trivy, got %s", format)
	}
	if _, ok := parser.(*TrivyParser); !ok {
		t.Errorf("expected TrivyParser, got %T", parser)
	}
}

func TestDetect_Grype(t *testing.T) {
	data, err := os.ReadFile("../../testdata/grype-sample.json")
	if err != nil {
		t.Fatal(err)
	}

	parser, format, err := Detect(data)
	if err != nil {
		t.Fatal(err)
	}
	if format != "grype" {
		t.Errorf("expected format grype, got %s", format)
	}
	if _, ok := parser.(*GrypeParser); !ok {
		t.Errorf("expected GrypeParser, got %T", parser)
	}
}

func TestDetect_SARIF(t *testing.T) {
	data, err := os.ReadFile("../../testdata/scanner-sample.sarif")
	if err != nil {
		t.Fatal(err)
	}

	parser, format, err := Detect(data)
	if err != nil {
		t.Fatal(err)
	}
	if format != "sarif" {
		t.Errorf("expected format sarif, got %s", format)
	}
	if _, ok := parser.(*SARIFParser); !ok {
		t.Errorf("expected SARIFParser, got %T", parser)
	}
}

func TestDetect_Invalid(t *testing.T) {
	_, _, err := Detect([]byte(`{"unknown": true}`))
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestTrivyParser(t *testing.T) {
	data, err := os.ReadFile("../../testdata/trivy-sample.json")
	if err != nil {
		t.Fatal(err)
	}

	parser := &TrivyParser{}
	findings, err := parser.Parse(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(findings))
	}

	// Check first finding
	f := findings[0]
	if f.CVE != "CVE-2023-44487" {
		t.Errorf("expected CVE-2023-44487, got %s", f.CVE)
	}
	if f.Package != "golang.org/x/net" {
		t.Errorf("expected golang.org/x/net, got %s", f.Package)
	}
	if f.Version != "0.7.0" {
		t.Errorf("expected 0.7.0, got %s", f.Version)
	}
	if f.Severity != "HIGH" {
		t.Errorf("expected HIGH, got %s", f.Severity)
	}
	if f.Ecosystem != "Go" {
		t.Errorf("expected Go, got %s", f.Ecosystem)
	}
	if f.Source != "trivy" {
		t.Errorf("expected trivy, got %s", f.Source)
	}
	if f.Target != "go.sum" {
		t.Errorf("expected go.sum, got %s", f.Target)
	}

	// Check npm finding
	f = findings[3]
	if f.Ecosystem != "npm" {
		t.Errorf("expected npm, got %s", f.Ecosystem)
	}
	if f.Package != "braces" {
		t.Errorf("expected braces, got %s", f.Package)
	}
}

func TestGrypeParser(t *testing.T) {
	data, err := os.ReadFile("../../testdata/grype-sample.json")
	if err != nil {
		t.Fatal(err)
	}

	parser := &GrypeParser{}
	findings, err := parser.Parse(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	// Check Go finding
	f := findings[0]
	if f.CVE != "CVE-2023-44487" {
		t.Errorf("expected CVE-2023-44487, got %s", f.CVE)
	}
	if f.Ecosystem != "Go" {
		t.Errorf("expected Go, got %s", f.Ecosystem)
	}
	if f.Fixed != "0.17.0" {
		t.Errorf("expected 0.17.0, got %s", f.Fixed)
	}

	// Check Java finding
	f = findings[2]
	if f.Ecosystem != "Maven" {
		t.Errorf("expected Maven, got %s", f.Ecosystem)
	}
	if f.Package != "log4j-core" {
		t.Errorf("expected log4j-core, got %s", f.Package)
	}
	if f.Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %s", f.Severity)
	}
}

func TestSARIFParser(t *testing.T) {
	data, err := os.ReadFile("../../testdata/scanner-sample.sarif")
	if err != nil {
		t.Fatal(err)
	}

	parser := &SARIFParser{}
	findings, err := parser.Parse(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// Check first finding
	f := findings[0]
	if f.CVE != "CVE-2023-44487" {
		t.Errorf("expected CVE-2023-44487, got %s", f.CVE)
	}
	if f.Severity != "HIGH" {
		t.Errorf("expected HIGH (from error level), got %s", f.Severity)
	}
	if f.Package != "golang.org/x/net" {
		t.Errorf("expected golang.org/x/net, got %s", f.Package)
	}
	if f.Target != "go.sum" {
		t.Errorf("expected go.sum, got %s", f.Target)
	}
	if f.Title != "HTTP/2 rapid reset attack" {
		t.Errorf("expected rule title, got %s", f.Title)
	}

	// Check second finding
	f = findings[1]
	if f.Severity != "MEDIUM" {
		t.Errorf("expected MEDIUM (from warning level), got %s", f.Severity)
	}
}

func TestTrivyEcosystemMapping(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"gomod", "Go"},
		{"gobinary", "Go"},
		{"npm", "npm"},
		{"pip", "PyPI"},
		{"cargo", "crates.io"},
		{"bundler", "RubyGems"},
		{"composer", "Packagist"},
		{"nuget", "NuGet"},
		{"jar", "Maven"},
		{"unknown-type", "unknown-type"},
	}

	for _, tt := range tests {
		got := mapTrivyEcosystem(tt.input)
		if got != tt.expected {
			t.Errorf("mapTrivyEcosystem(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestGrypeEcosystemMapping(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"go-module", "Go"},
		{"npm", "npm"},
		{"python", "PyPI"},
		{"rust-crate", "crates.io"},
		{"gem", "RubyGems"},
		{"java-archive", "Maven"},
		{"dotnet", "NuGet"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		got := mapGrypeEcosystem(tt.input)
		if got != tt.expected {
			t.Errorf("mapGrypeEcosystem(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
