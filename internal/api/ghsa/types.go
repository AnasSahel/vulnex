package ghsa

// GitHub Advisory Database REST API response types.
// See: https://docs.github.com/en/rest/security-advisories/global-advisories

// GHSAdvisory represents a single advisory from the GitHub Advisory Database REST API.
type GHSAdvisory struct {
	GHSAID          string              `json:"ghsa_id"`
	CVEID           string              `json:"cve_id"`
	URL             string              `json:"html_url"`
	Summary         string              `json:"summary"`
	Description     string              `json:"description"`
	Severity        string              `json:"severity"`
	Identifiers     []Identifier        `json:"identifiers"`
	References      []string            `json:"references"`
	PublishedAt     string              `json:"published_at"`
	UpdatedAt       string              `json:"updated_at"`
	WithdrawnAt     *string             `json:"withdrawn_at"`
	Vulnerabilities []GHSAVulnerability `json:"vulnerabilities"`
	CVSS            *GHSACVSS           `json:"cvss"`
	CWEs            []GHSACWE           `json:"cwes"`
	EPSS            *GHSAEpss           `json:"epss"`
}

// GHSAVulnerability represents a vulnerable package entry within an advisory.
type GHSAVulnerability struct {
	Package                GHSAPackage `json:"package"`
	VulnerableVersionRange string      `json:"vulnerable_version_range"`
	PatchedVersions        string      `json:"patched_versions"`
	FirstPatchedVersion    *string     `json:"first_patched_version"`
	VulnerableFunctions    []string    `json:"vulnerable_functions"`
}

// GHSAPackage identifies the affected package ecosystem and name.
type GHSAPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// GHSACVSS holds the CVSS vector and score for an advisory.
type GHSACVSS struct {
	VectorString string  `json:"vector_string"`
	Score        float64 `json:"score"`
}

// GHSACWE represents a CWE weakness classification associated with an advisory.
type GHSACWE struct {
	CWEID string `json:"cwe_id"`
	Name  string `json:"name"`
}

// GHSAEpss holds the EPSS probability and percentile for an advisory.
type GHSAEpss struct {
	Percentage float64 `json:"percentage"`
	Percentile float64 `json:"percentile"`
}

// Identifier represents an advisory identifier such as a CVE or GHSA ID.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
