package model

// Reference represents a URL reference associated with a CVE.
type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags,omitempty"` // "Exploit", "Patch", "Vendor Advisory", etc.
}

// Advisory represents a security advisory from a source like GHSA or OSV.
type Advisory struct {
	ID       string `json:"id"`       // GHSA-xxxx-xxxx-xxxx or OSV ID
	Source   string `json:"source"`   // "ghsa", "osv"
	URL      string `json:"url"`
	Severity string `json:"severity"` // "critical", "high", "medium", "low"
	Summary  string `json:"summary"`
}

// CPEMatch represents a CPE (Common Platform Enumeration) match configuration.
type CPEMatch struct {
	CPE23URI           string `json:"cpe23_uri"`
	Vulnerable         bool   `json:"vulnerable"`
	VersionStartIncl   string `json:"version_start_including,omitempty"`
	VersionStartExcl   string `json:"version_start_excluding,omitempty"`
	VersionEndIncl     string `json:"version_end_including,omitempty"`
	VersionEndExcl     string `json:"version_end_excluding,omitempty"`
}

// AffectedPkg represents an affected open-source package from OSV or GHSA.
type AffectedPkg struct {
	Ecosystem string  `json:"ecosystem"` // npm, pip, maven, go, rubygems, rust, etc.
	Name      string  `json:"name"`
	Versions  []string `json:"versions,omitempty"` // specific affected versions
	Ranges    []Range `json:"ranges,omitempty"`    // version ranges
	Fixed     string  `json:"fixed,omitempty"`     // first fixed version
}

// Range represents a version range for an affected package.
type Range struct {
	Type       string `json:"type"` // SEMVER, ECOSYSTEM, GIT
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}
