package sbom

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// lockfileFormat describes a recognized lockfile type.
type lockfileFormat int

const (
	lockfileUnknown lockfileFormat = iota
	lockfileGoSum
	lockfilePackageLock
	lockfileYarnLock
	lockfilePnpmLock
	lockfileCargoLock
	lockfileGemfileLock
	lockfileRequirementsTxt
	lockfilePoetryLock
	lockfileComposerLock
)

// detectLockfileFormat returns the lockfile format based on the filename.
func detectLockfileFormat(path string) lockfileFormat {
	switch filepath.Base(path) {
	case "go.sum":
		return lockfileGoSum
	case "package-lock.json":
		return lockfilePackageLock
	case "yarn.lock":
		return lockfileYarnLock
	case "pnpm-lock.yaml":
		return lockfilePnpmLock
	case "Cargo.lock":
		return lockfileCargoLock
	case "Gemfile.lock":
		return lockfileGemfileLock
	case "requirements.txt":
		return lockfileRequirementsTxt
	case "poetry.lock":
		return lockfilePoetryLock
	case "composer.lock":
		return lockfileComposerLock
	default:
		return lockfileUnknown
	}
}

// parseLockfile dispatches to the appropriate parser based on format.
func parseLockfile(path string, format lockfileFormat) ([]Component, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}

	switch format {
	case lockfileGoSum:
		return parseGoSum(data)
	case lockfilePackageLock:
		return parsePackageLock(data)
	case lockfileYarnLock:
		return parseYarnLock(data)
	case lockfilePnpmLock:
		return parsePnpmLock(data)
	case lockfileCargoLock:
		return parseCargoLock(data)
	case lockfileGemfileLock:
		return parseGemfileLock(data)
	case lockfileRequirementsTxt:
		return parseRequirementsTxt(data)
	case lockfilePoetryLock:
		return parsePoetryLock(data)
	case lockfileComposerLock:
		return parseComposerLock(data)
	default:
		return nil, fmt.Errorf("unsupported lockfile format")
	}
}

// parseGoSum parses a go.sum file and returns deduplicated components.
func parseGoSum(data []byte) ([]Component, error) {
	seen := make(map[string]bool)
	var components []Component

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		mod := fields[0]
		ver := fields[1]

		// Skip /go.mod entries
		if strings.HasSuffix(ver, "/go.mod") {
			continue
		}

		// Strip /go.mod or hash suffixes from version
		ver = strings.TrimSuffix(ver, "/go.mod")

		// Strip leading "v" from version
		ver = strings.TrimPrefix(ver, "v")

		key := mod + "@" + ver
		if seen[key] {
			continue
		}
		seen[key] = true

		components = append(components, Component{
			Name:      mod,
			Version:   ver,
			Ecosystem: "go",
		})
	}

	return components, scanner.Err()
}

// parsePackageLock parses a package-lock.json file (v2 and v3).
func parsePackageLock(data []byte) ([]Component, error) {
	var doc struct {
		LockfileVersion int `json:"lockfileVersion"`
		// v2 format
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
		// v3 format
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}

	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decoding package-lock.json: %w", err)
	}

	var components []Component

	// v3: use packages map
	if doc.LockfileVersion >= 3 && len(doc.Packages) > 0 {
		for path, pkg := range doc.Packages {
			if path == "" || pkg.Version == "" {
				continue
			}
			// path is like "node_modules/lodash"
			name := path
			if idx := strings.LastIndex(path, "node_modules/"); idx >= 0 {
				name = path[idx+len("node_modules/"):]
			}
			components = append(components, Component{
				Name:      name,
				Version:   pkg.Version,
				Ecosystem: "npm",
			})
		}
		return components, nil
	}

	// v2 and earlier: use dependencies map
	for name, dep := range doc.Dependencies {
		if dep.Version == "" {
			continue
		}
		components = append(components, Component{
			Name:      name,
			Version:   dep.Version,
			Ecosystem: "npm",
		})
	}

	return components, nil
}

// parseYarnLock parses a yarn.lock file.
func parseYarnLock(data []byte) ([]Component, error) {
	var components []Component

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var currentName string

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		// Package header lines: "pkg@version:" or "\"pkg@version\":"
		if !strings.HasPrefix(line, " ") && strings.Contains(line, "@") {
			// Extract package name from the header
			header := strings.TrimSuffix(strings.TrimSpace(line), ":")
			header = strings.Trim(header, "\"")

			// Handle scoped packages like @scope/pkg@version
			atIdx := strings.LastIndex(header, "@")
			if atIdx > 0 {
				currentName = header[:atIdx]
			}
			continue
		}

		// Version line inside a block: "  version "x.y.z""
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "version ") && currentName != "" {
			ver := strings.TrimPrefix(trimmed, "version ")
			ver = strings.Trim(ver, "\"")
			components = append(components, Component{
				Name:      currentName,
				Version:   ver,
				Ecosystem: "npm",
			})
			currentName = ""
		}
	}

	return components, scanner.Err()
}

// parsePnpmLock parses a pnpm-lock.yaml file.
func parsePnpmLock(data []byte) ([]Component, error) {
	var doc struct {
		Packages map[string]struct {
			Version string `yaml:"version"`
		} `yaml:"packages"`
	}

	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decoding pnpm-lock.yaml: %w", err)
	}

	var components []Component
	for key, pkg := range doc.Packages {
		// key format: "/pkg@version" or "/@scope/pkg@version"
		name, version := parsePnpmPackageKey(key, pkg.Version)
		if name == "" || version == "" {
			continue
		}
		components = append(components, Component{
			Name:      name,
			Version:   version,
			Ecosystem: "npm",
		})
	}

	return components, nil
}

// parsePnpmPackageKey extracts name and version from a pnpm packages map key.
func parsePnpmPackageKey(key, fallbackVersion string) (string, string) {
	// Strip leading "/"
	key = strings.TrimPrefix(key, "/")

	// Find the last "@" that separates name from version
	atIdx := strings.LastIndex(key, "@")
	if atIdx <= 0 {
		return key, fallbackVersion
	}

	name := key[:atIdx]
	version := key[atIdx+1:]

	// Version might have suffixes like "(react@18.0.0)" - strip them
	if idx := strings.Index(version, "("); idx > 0 {
		version = version[:idx]
	}

	if version == "" {
		version = fallbackVersion
	}

	return name, version
}

// parseCargoLock parses a Cargo.lock file.
func parseCargoLock(data []byte) ([]Component, error) {
	var doc struct {
		Package []struct {
			Name    string `toml:"name"`
			Version string `toml:"version"`
		} `toml:"package"`
	}

	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decoding Cargo.lock: %w", err)
	}

	components := make([]Component, 0, len(doc.Package))
	for _, pkg := range doc.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		components = append(components, Component{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: "cargo",
		})
	}

	return components, nil
}

// parseGemfileLock parses a Gemfile.lock file.
func parseGemfileLock(data []byte) ([]Component, error) {
	var components []Component

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	inGEM := false
	inSpecs := false

	for scanner.Scan() {
		line := scanner.Text()

		if strings.TrimSpace(line) == "GEM" {
			inGEM = true
			inSpecs = false
			continue
		}

		// A new top-level section resets
		if inGEM && len(line) > 0 && line[0] != ' ' {
			inGEM = false
			inSpecs = false
			continue
		}

		if inGEM && strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}

		if inSpecs {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}

			// Spec entries are indented 4 spaces: "    name (version)"
			// Sub-dependencies are indented 6+ spaces
			indent := len(line) - len(strings.TrimLeft(line, " "))
			if indent == 4 {
				// Parse "name (version)"
				parenIdx := strings.Index(trimmed, " (")
				if parenIdx > 0 && strings.HasSuffix(trimmed, ")") {
					name := trimmed[:parenIdx]
					version := trimmed[parenIdx+2 : len(trimmed)-1]
					components = append(components, Component{
						Name:      name,
						Version:   version,
						Ecosystem: "gem",
					})
				}
			}
		}
	}

	return components, scanner.Err()
}

// parseRequirementsTxt parses a requirements.txt file.
func parseRequirementsTxt(data []byte) ([]Component, error) {
	var components []Component

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines, comments, and includes
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Skip URL-based requirements
		if strings.Contains(line, "://") {
			continue
		}

		// Strip inline comments
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Strip environment markers (e.g., "; python_version >= '3.6'")
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Look for == pinned version
		if idx := strings.Index(line, "=="); idx > 0 {
			name := strings.TrimSpace(line[:idx])
			version := strings.TrimSpace(line[idx+2:])
			if name != "" && version != "" {
				components = append(components, Component{
					Name:      name,
					Version:   version,
					Ecosystem: "pip",
				})
			}
		}
	}

	return components, scanner.Err()
}

// parsePoetryLock parses a poetry.lock file.
func parsePoetryLock(data []byte) ([]Component, error) {
	var doc struct {
		Package []struct {
			Name    string `toml:"name"`
			Version string `toml:"version"`
		} `toml:"package"`
	}

	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decoding poetry.lock: %w", err)
	}

	components := make([]Component, 0, len(doc.Package))
	for _, pkg := range doc.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		components = append(components, Component{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: "pip",
		})
	}

	return components, nil
}

// parseComposerLock parses a composer.lock file.
func parseComposerLock(data []byte) ([]Component, error) {
	var doc struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
		PackagesDev []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages-dev"`
	}

	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decoding composer.lock: %w", err)
	}

	var components []Component

	for _, pkg := range doc.Packages {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		// Strip leading "v" from version
		version := strings.TrimPrefix(pkg.Version, "v")
		components = append(components, Component{
			Name:      pkg.Name,
			Version:   version,
			Ecosystem: "composer",
		})
	}

	for _, pkg := range doc.PackagesDev {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		version := strings.TrimPrefix(pkg.Version, "v")
		components = append(components, Component{
			Name:      pkg.Name,
			Version:   version,
			Ecosystem: "composer",
		})
	}

	return components, nil
}
