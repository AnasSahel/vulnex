package model

import "time"

// EnrichedCVE is the universal data contract that aggregates data from all sources.
// Every API client converts to this model, and every formatter renders it.
type EnrichedCVE struct {
	// Core identity
	ID       string `json:"id"`        // CVE-YYYY-NNNNN
	SourceID string `json:"source_id"` // CNA source identifier
	Status   string `json:"status"`    // Analyzed, Modified, Rejected, Awaiting Analysis, etc.

	// Dates
	Published    time.Time `json:"published"`
	LastModified time.Time `json:"last_modified"`

	// Description
	Descriptions []LangString `json:"descriptions"`

	// Scoring
	CVSS []CVSSScore `json:"cvss"`
	EPSS *EPSSScore  `json:"epss,omitempty"`

	// Classification
	CWEs []CWEEntry `json:"cwes"`
	Tags []string   `json:"tags,omitempty"` // disputed, unsupported, etc.

	// Affected products
	CPEs         []CPEMatch    `json:"cpes,omitempty"`
	AffectedPkgs []AffectedPkg `json:"affected_packages,omitempty"`

	// Exploitation status
	KEV *KEVEntry `json:"kev,omitempty"`

	// References
	References []Reference `json:"references"`
	Advisories []Advisory  `json:"advisories,omitempty"`

	// Metadata
	DataSources []string  `json:"data_sources"` // which APIs contributed data
	FetchedAt   time.Time `json:"fetched_at"`
}

// Description returns the English description, falling back to the first available.
func (e *EnrichedCVE) Description() string {
	return English(e.Descriptions)
}

// HighestScore returns the highest CVSS score, or nil if none.
func (e *EnrichedCVE) HighestScore() *CVSSScore {
	return HighestCVSS(e.CVSS)
}

// IsInKEV returns true if this CVE is in the CISA KEV catalog.
func (e *EnrichedCVE) IsInKEV() bool {
	return e.KEV != nil
}

// Severity returns the severity string from the highest CVSS score,
// or "UNKNOWN" if no CVSS scores are available.
func (e *EnrichedCVE) Severity() string {
	if s := e.HighestScore(); s != nil {
		return s.Severity
	}
	return "UNKNOWN"
}
