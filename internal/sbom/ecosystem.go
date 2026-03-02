package sbom

import "strings"

// MapEcosystemToOSV converts PURL ecosystem type strings to OSV ecosystem names.
func MapEcosystemToOSV(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "npm"
	case "pypi", "pip":
		return "PyPI"
	case "maven":
		return "Maven"
	case "go", "golang":
		return "Go"
	case "cargo":
		return "crates.io"
	case "nuget":
		return "NuGet"
	case "gem", "rubygems":
		return "RubyGems"
	case "composer":
		return "Packagist"
	case "hex":
		return "Hex"
	case "pub":
		return "Pub"
	case "swift":
		return "SwiftURL"
	default:
		return ecosystem
	}
}
