package sbom

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestDetectLockfileFormat(t *testing.T) {
	tests := []struct {
		path string
		want lockfileFormat
	}{
		{"go.sum", lockfileGoSum},
		{"/some/path/go.sum", lockfileGoSum},
		{"package-lock.json", lockfilePackageLock},
		{"yarn.lock", lockfileYarnLock},
		{"pnpm-lock.yaml", lockfilePnpmLock},
		{"Cargo.lock", lockfileCargoLock},
		{"Gemfile.lock", lockfileGemfileLock},
		{"requirements.txt", lockfileRequirementsTxt},
		{"poetry.lock", lockfilePoetryLock},
		{"composer.lock", lockfileComposerLock},
		{"unknown.json", lockfileUnknown},
		{"bom.json", lockfileUnknown},
		{"Makefile", lockfileUnknown},
	}

	for _, tt := range tests {
		t.Run(filepath.Base(tt.path), func(t *testing.T) {
			got := detectLockfileFormat(tt.path)
			if got != tt.want {
				t.Errorf("detectLockfileFormat(%q) = %d, want %d", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsLockfile(t *testing.T) {
	if !IsLockfile("go.sum") {
		t.Error("expected go.sum to be recognized as lockfile")
	}
	if IsLockfile("bom.json") {
		t.Error("expected bom.json to not be recognized as lockfile")
	}
}

func TestParseGoSum(t *testing.T) {
	data := []byte(`golang.org/x/text v0.3.7 h1:abc123=
golang.org/x/text v0.3.7/go.mod h1:def456=
golang.org/x/net v0.0.0-20220225 h1:ghi789=
golang.org/x/net v0.0.0-20220225/go.mod h1:jkl012=
golang.org/x/text v0.3.7 h1:duplicate=
`)

	comps, err := parseGoSum(data)
	if err != nil {
		t.Fatalf("parseGoSum: %v", err)
	}

	// Should have 2 unique components (text and net), no /go.mod entries, deduped
	if len(comps) != 2 {
		t.Fatalf("expected 2 components, got %d", len(comps))
	}

	sort.Slice(comps, func(i, j int) bool { return comps[i].Name < comps[j].Name })

	if comps[0].Name != "golang.org/x/net" || comps[0].Version != "0.0.0-20220225" {
		t.Errorf("unexpected component: %+v", comps[0])
	}
	if comps[1].Name != "golang.org/x/text" || comps[1].Version != "0.3.7" {
		t.Errorf("unexpected component: %+v", comps[1])
	}

	for _, c := range comps {
		if c.Ecosystem != "go" {
			t.Errorf("expected ecosystem 'go', got %q", c.Ecosystem)
		}
	}
}

func TestParsePackageLockV2(t *testing.T) {
	data := []byte(`{
  "lockfileVersion": 2,
  "dependencies": {
    "lodash": { "version": "4.17.21" },
    "express": { "version": "4.18.2" }
  }
}`)

	comps, err := parsePackageLock(data)
	if err != nil {
		t.Fatalf("parsePackageLock: %v", err)
	}

	if len(comps) != 2 {
		t.Fatalf("expected 2 components, got %d", len(comps))
	}

	for _, c := range comps {
		if c.Ecosystem != "npm" {
			t.Errorf("expected ecosystem 'npm', got %q", c.Ecosystem)
		}
	}
}

func TestParsePackageLockV3(t *testing.T) {
	data := []byte(`{
  "lockfileVersion": 3,
  "packages": {
    "": { "version": "1.0.0" },
    "node_modules/lodash": { "version": "4.17.21" },
    "node_modules/@scope/pkg": { "version": "1.0.0" }
  }
}`)

	comps, err := parsePackageLock(data)
	if err != nil {
		t.Fatalf("parsePackageLock: %v", err)
	}

	// Should have 2 components (skipping root "")
	if len(comps) != 2 {
		t.Fatalf("expected 2 components, got %d", len(comps))
	}

	sort.Slice(comps, func(i, j int) bool { return comps[i].Name < comps[j].Name })

	if comps[0].Name != "@scope/pkg" || comps[0].Version != "1.0.0" {
		t.Errorf("unexpected component: %+v", comps[0])
	}
	if comps[1].Name != "lodash" || comps[1].Version != "4.17.21" {
		t.Errorf("unexpected component: %+v", comps[1])
	}
}

func TestParseYarnLock(t *testing.T) {
	data := []byte(`# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

"@scope/pkg@^1.0.0":
  version "1.2.3"
  resolved "https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.2.3.tgz"
`)

	comps, err := parseYarnLock(data)
	if err != nil {
		t.Fatalf("parseYarnLock: %v", err)
	}

	if len(comps) != 2 {
		t.Fatalf("expected 2 components, got %d", len(comps))
	}

	sort.Slice(comps, func(i, j int) bool { return comps[i].Name < comps[j].Name })

	if comps[0].Name != "@scope/pkg" || comps[0].Version != "1.2.3" {
		t.Errorf("unexpected component: %+v", comps[0])
	}
	if comps[1].Name != "lodash" || comps[1].Version != "4.17.21" {
		t.Errorf("unexpected component: %+v", comps[1])
	}
}

func TestParsePnpmLock(t *testing.T) {
	data := []byte(`lockfileVersion: '6.0'
packages:
  /lodash@4.17.21:
    version: 4.17.21
  /@scope/pkg@1.0.0:
    version: 1.0.0
`)

	comps, err := parsePnpmLock(data)
	if err != nil {
		t.Fatalf("parsePnpmLock: %v", err)
	}

	if len(comps) != 2 {
		t.Fatalf("expected 2 components, got %d", len(comps))
	}

	sort.Slice(comps, func(i, j int) bool { return comps[i].Name < comps[j].Name })

	if comps[0].Name != "@scope/pkg" || comps[0].Version != "1.0.0" {
		t.Errorf("unexpected component: %+v", comps[0])
	}
	if comps[1].Name != "lodash" || comps[1].Version != "4.17.21" {
		t.Errorf("unexpected component: %+v", comps[1])
	}
}

func TestParseCargoLock(t *testing.T) {
	data := []byte(`[[package]]
name = "serde"
version = "1.0.193"

[[package]]
name = "tokio"
version = "1.35.0"
`)

	comps, err := parseCargoLock(data)
	if err != nil {
		t.Fatalf("parseCargoLock: %v", err)
	}

	if len(comps) != 2 {
		t.Fatalf("expected 2 components, got %d", len(comps))
	}

	for _, c := range comps {
		if c.Ecosystem != "cargo" {
			t.Errorf("expected ecosystem 'cargo', got %q", c.Ecosystem)
		}
	}
}

func TestParseGemfileLock(t *testing.T) {
	data := []byte(`GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.8)
    rails (7.0.8)
      actionpack (= 7.0.8)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 7.0)
`)

	comps, err := parseGemfileLock(data)
	if err != nil {
		t.Fatalf("parseGemfileLock: %v", err)
	}

	if len(comps) != 2 {
		t.Fatalf("expected 2 components, got %d", len(comps))
	}

	sort.Slice(comps, func(i, j int) bool { return comps[i].Name < comps[j].Name })

	if comps[0].Name != "rack" || comps[0].Version != "2.2.8" {
		t.Errorf("unexpected component: %+v", comps[0])
	}
	if comps[1].Name != "rails" || comps[1].Version != "7.0.8" {
		t.Errorf("unexpected component: %+v", comps[1])
	}

	for _, c := range comps {
		if c.Ecosystem != "gem" {
			t.Errorf("expected ecosystem 'gem', got %q", c.Ecosystem)
		}
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	data := []byte(`# This is a comment
requests==2.31.0
flask==3.0.0 ; python_version >= "3.8"
-r other-requirements.txt
https://example.com/pkg.tar.gz
numpy==1.24.0 # inline comment
`)

	comps, err := parseRequirementsTxt(data)
	if err != nil {
		t.Fatalf("parseRequirementsTxt: %v", err)
	}

	if len(comps) != 3 {
		t.Fatalf("expected 3 components, got %d", len(comps))
	}

	sort.Slice(comps, func(i, j int) bool { return comps[i].Name < comps[j].Name })

	if comps[0].Name != "flask" || comps[0].Version != "3.0.0" {
		t.Errorf("unexpected component: %+v", comps[0])
	}
	if comps[1].Name != "numpy" || comps[1].Version != "1.24.0" {
		t.Errorf("unexpected component: %+v", comps[1])
	}
	if comps[2].Name != "requests" || comps[2].Version != "2.31.0" {
		t.Errorf("unexpected component: %+v", comps[2])
	}

	for _, c := range comps {
		if c.Ecosystem != "pip" {
			t.Errorf("expected ecosystem 'pip', got %q", c.Ecosystem)
		}
	}
}

func TestParsePoetryLock(t *testing.T) {
	data := []byte(`[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "flask"
version = "3.0.0"
`)

	comps, err := parsePoetryLock(data)
	if err != nil {
		t.Fatalf("parsePoetryLock: %v", err)
	}

	if len(comps) != 2 {
		t.Fatalf("expected 2 components, got %d", len(comps))
	}

	for _, c := range comps {
		if c.Ecosystem != "pip" {
			t.Errorf("expected ecosystem 'pip', got %q", c.Ecosystem)
		}
	}
}

func TestParseComposerLock(t *testing.T) {
	data := []byte(`{
  "packages": [
    { "name": "monolog/monolog", "version": "v3.5.0" },
    { "name": "symfony/console", "version": "v6.4.0" }
  ],
  "packages-dev": [
    { "name": "phpunit/phpunit", "version": "v10.5.0" }
  ]
}`)

	comps, err := parseComposerLock(data)
	if err != nil {
		t.Fatalf("parseComposerLock: %v", err)
	}

	if len(comps) != 3 {
		t.Fatalf("expected 3 components, got %d", len(comps))
	}

	// Check "v" prefix stripping
	sort.Slice(comps, func(i, j int) bool { return comps[i].Name < comps[j].Name })

	if comps[0].Name != "monolog/monolog" || comps[0].Version != "3.5.0" {
		t.Errorf("unexpected component: %+v", comps[0])
	}

	for _, c := range comps {
		if c.Ecosystem != "composer" {
			t.Errorf("expected ecosystem 'composer', got %q", c.Ecosystem)
		}
	}
}

func TestParseFileWithLockfile(t *testing.T) {
	// Write a temporary go.sum file and parse it via ParseFile
	dir := t.TempDir()
	path := filepath.Join(dir, "go.sum")
	data := []byte("golang.org/x/text v0.3.7 h1:abc=\n")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	comps, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	if comps[0].Name != "golang.org/x/text" {
		t.Errorf("unexpected name: %s", comps[0].Name)
	}
}
