package cra

// Report is the root data structure for a CRA evidence pack.
type Report struct {
	Meta        ReportMeta
	Product     ProductSection
	SBOM        SBOMSection
	Vulns       VulnSection
	Handling    HandlingSection
	SDL         SDLSection
	AnnexI      AnnexISection
	CLIVersion  string
	GeneratedAt string // RFC3339 timestamp
}

// ReportMeta holds metadata about report generation.
type ReportMeta struct {
	Repo    string
	Release string
	Branch  string
}

// ProductSection holds product identity and release metadata.
type ProductSection struct {
	Name               string
	Version            string
	TagName            string
	CommitSHA          string
	PublishedAt        string
	ReleaseURL         string
	ReleaseNotes       string
	CommitAuthor       string
	CommitDate         string
	CommitVerification string // "verified" | "unverified" | "unknown"
}

// SBOMSection holds SBOM component inventory.
type SBOMSection struct {
	Provided   bool
	FilePath   string
	Format     string
	Components []SBOMComponent
}

// SBOMComponent is a single component from the SBOM.
type SBOMComponent struct {
	Name      string
	Version   string
	Ecosystem string
	PURL      string
}

// VulnSection holds known vulnerabilities and VEX statements.
type VulnSection struct {
	Provided bool
	Findings []VulnFinding
}

// VulnFinding is a single vulnerability finding with optional VEX status.
type VulnFinding struct {
	ID               string
	Summary          string
	Severity         string
	Package          string
	Version          string
	Ecosystem        string
	VEXStatus        string
	VEXJustification string
}

// HandlingSection holds the vulnerability handling record.
type HandlingSection struct {
	Provided  bool
	Decisions []VulnDecision
}

// VulnDecision records a handling decision for a specific vulnerability.
type VulnDecision struct {
	VulnID    string `json:"vuln_id"`
	Status    string `json:"status"`    // "remediated" | "accepted" | "deferred"
	Rationale string `json:"rationale"`
	Date      string `json:"date"`
}

// SDLSection holds secure development lifecycle attestation.
type SDLSection struct {
	Available           bool // false when auth-gated and no valid token
	Skipped             bool
	SkipReason          string
	BranchProtected     bool
	RequiredReviews     int
	DismissStaleReviews bool
	EnforceAdmins       bool
	CommitSigned        bool
}

// AnnexIItem maps a CRA Annex I obligation to evidence and coverage status.
type AnnexIItem struct {
	Obligation string
	Evidence   string
	Status     string // "covered" | "partial" | "not_covered" | "manual_input"
}

// AnnexISection holds the Annex I obligation mapping table.
type AnnexISection struct {
	Items []AnnexIItem
}
