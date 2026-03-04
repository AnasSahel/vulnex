package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// IsLockfile returns true if the given path is a recognized lockfile.
func IsLockfile(path string) bool {
	return detectLockfileFormat(path) != lockfileUnknown
}

// Component represents a software component extracted from an SBOM.
type Component struct {
	Name      string
	Version   string
	Ecosystem string // npm, pip, maven, go, etc.
	PURL      string // Package URL
	CPE       string // CPE 2.3 URI if available
}

// sbomFormat describes the detected SBOM document type.
type sbomFormat int

const (
	formatUnknown sbomFormat = iota
	formatCycloneDX
	formatSPDX
)

// ParseFile detects the file format (lockfile or SBOM) and parses components.
// Lockfiles are detected by filename before reading; SBOMs are detected by content.
func ParseFile(path string) ([]Component, error) {
	// Check for lockfile format first (by filename, before reading)
	if lf := detectLockfileFormat(path); lf != lockfileUnknown {
		return parseLockfile(path, lf)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading SBOM file: %w", err)
	}

	format, err := detectFormat(data)
	if err != nil {
		return nil, err
	}

	switch format {
	case formatCycloneDX:
		return parseCycloneDX(data)
	case formatSPDX:
		return parseSPDX(data)
	default:
		return nil, fmt.Errorf("unsupported or unrecognized SBOM format")
	}
}

// detectFormat inspects raw JSON bytes and determines whether the document is
// CycloneDX or SPDX. It returns formatUnknown if neither format is recognized.
func detectFormat(data []byte) (sbomFormat, error) {
	var probe map[string]interface{}
	if err := json.Unmarshal(data, &probe); err != nil {
		return formatUnknown, fmt.Errorf("SBOM file is not valid JSON: %w", err)
	}

	// CycloneDX: look for "bomFormat": "CycloneDX"
	if bf, ok := probe["bomFormat"]; ok {
		if s, ok := bf.(string); ok && strings.EqualFold(s, "CycloneDX") {
			return formatCycloneDX, nil
		}
	}

	// SPDX: look for "spdxVersion"
	if _, ok := probe["spdxVersion"]; ok {
		return formatSPDX, nil
	}

	return formatUnknown, nil
}

// parseCycloneDX parses a CycloneDX JSON SBOM and extracts components.
func parseCycloneDX(data []byte) ([]Component, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decoding CycloneDX JSON: %w", err)
	}

	rawComponents, ok := doc["components"]
	if !ok {
		return nil, nil // no components section
	}

	compList, ok := rawComponents.([]interface{})
	if !ok {
		return nil, fmt.Errorf("CycloneDX components field is not an array")
	}

	components := make([]Component, 0, len(compList))
	for _, raw := range compList {
		obj, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}

		comp := Component{
			Name:    jsonStr(obj, "name"),
			Version: jsonStr(obj, "version"),
			PURL:    jsonStr(obj, "purl"),
		}

		// Extract ecosystem from purl (e.g., "pkg:npm/lodash@4.17.21" -> "npm")
		if comp.PURL != "" {
			comp.Ecosystem = ecosystemFromPURL(comp.PURL)
		}

		// Extract CPE from the cpe field if present
		if cpe := jsonStr(obj, "cpe"); cpe != "" {
			comp.CPE = cpe
		}

		components = append(components, comp)
	}

	return components, nil
}

// parseSPDX parses an SPDX JSON SBOM and extracts components from the packages array.
func parseSPDX(data []byte) ([]Component, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decoding SPDX JSON: %w", err)
	}

	rawPackages, ok := doc["packages"]
	if !ok {
		return nil, nil // no packages section
	}

	pkgList, ok := rawPackages.([]interface{})
	if !ok {
		return nil, fmt.Errorf("SPDX packages field is not an array")
	}

	components := make([]Component, 0, len(pkgList))
	for _, raw := range pkgList {
		obj, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}

		comp := Component{
			Name:    jsonStr(obj, "name"),
			Version: jsonStr(obj, "versionInfo"),
		}

		// Extract PURL and CPE from externalRefs
		if refs, ok := obj["externalRefs"].([]interface{}); ok {
			for _, ref := range refs {
				refObj, ok := ref.(map[string]interface{})
				if !ok {
					continue
				}
				refType := jsonStr(refObj, "referenceType")
				refLocator := jsonStr(refObj, "referenceLocator")
				if refLocator == "" {
					continue
				}
				switch refType {
				case "purl":
					comp.PURL = refLocator
				case "cpe23Type", "cpe22Type":
					comp.CPE = refLocator
				}
			}
		}

		// Derive ecosystem from PURL if available
		if comp.PURL != "" && comp.Ecosystem == "" {
			comp.Ecosystem = ecosystemFromPURL(comp.PURL)
		}

		components = append(components, comp)
	}

	return components, nil
}

// ecosystemFromPURL extracts the ecosystem type from a Package URL.
// Format: pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>
// Example: "pkg:npm/lodash@4.17.21" -> "npm"
func ecosystemFromPURL(purl string) string {
	// Strip the "pkg:" prefix
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := purl[4:]

	// The ecosystem type is everything before the first "/"
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return ""
	}

	return rest[:slashIdx]
}

// jsonStr safely extracts a string value from a JSON object map.
func jsonStr(obj map[string]interface{}, key string) string {
	v, ok := obj[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}
