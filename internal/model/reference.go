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

// EnrichedAdvisory represents a fully detailed security advisory with all available data.
type EnrichedAdvisory struct {
	ID          string        `json:"id"`
	CVEID       string        `json:"cve_id,omitempty"`
	Source      string        `json:"source"`
	URL         string        `json:"url"`
	Severity    string        `json:"severity"`
	Summary     string        `json:"summary"`
	Description string        `json:"description,omitempty"`
	CVSSScore   float64       `json:"cvss_score,omitempty"`
	CVSSVector  string        `json:"cvss_vector,omitempty"`
	EPSSScore   float64       `json:"epss_score,omitempty"`
	EPSSPctile  float64       `json:"epss_percentile,omitempty"`
	CWEs        []CWEEntry    `json:"cwes,omitempty"`
	Packages    []AffectedPkg `json:"affected_packages,omitempty"`
	References  []string      `json:"references,omitempty"`
	PublishedAt string        `json:"published_at,omitempty"`
	UpdatedAt   string        `json:"updated_at,omitempty"`
	WithdrawnAt string        `json:"withdrawn_at,omitempty"`
}

// SBOMFinding represents a single vulnerability finding for a component in an SBOM.
type SBOMFinding struct {
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Fixed     string   `json:"fixed,omitempty"`
	Advisory  Advisory `json:"advisory"`
	// Enrichment fields (populated when --enrich is used)
	CVEIDs     []string   `json:"cve_ids,omitempty"`
	EPSS       *EPSSScore `json:"epss,omitempty"`
	KEV        *KEVEntry  `json:"kev,omitempty"`
	CVSSScore  float64    `json:"cvss_score,omitempty"`
	Risk       *RiskScore `json:"risk,omitempty"`
	HasExploit bool       `json:"has_exploit,omitempty"`
	EPSSTrend  *EPSSTrend `json:"epss_trend,omitempty"`
}

// SBOMResult holds the complete results of an SBOM vulnerability check.
type SBOMResult struct {
	File            string        `json:"file"`
	TotalComponents int           `json:"total_components"`
	Findings        []SBOMFinding `json:"findings"`
	Suppressed      []SBOMFinding `json:"suppressed,omitempty"`
}

// SBOMDiffResult holds the diff between two SBOM vulnerability checks.
type SBOMDiffResult struct {
	OldFile       string        `json:"old_file"`
	NewFile       string        `json:"new_file"`
	OldComponents int           `json:"old_components"`
	NewComponents int           `json:"new_components"`
	Added         []SBOMFinding `json:"added"`
	Removed       []SBOMFinding `json:"removed"`
	Unchanged     []SBOMFinding `json:"unchanged"`
	Suppressed    []SBOMFinding `json:"suppressed,omitempty"`
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
