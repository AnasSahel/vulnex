package osv

// OSV.dev API request and response types.
// See: https://osv.dev/docs/

// QueryRequest is the request body for the OSV query endpoint.
type QueryRequest struct {
	Commit  string        `json:"commit,omitempty"`
	Version string        `json:"version,omitempty"`
	Package *QueryPackage `json:"package,omitempty"`
}

// QueryPackage identifies a package in a query request.
type QueryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl,omitempty"`
}

// BatchQueryRequest is the request body for the OSV batch query endpoint.
type BatchQueryRequest struct {
	Queries []QueryRequest `json:"queries"`
}

// BatchQueryResponse is the response from the OSV batch query endpoint.
type BatchQueryResponse struct {
	Results []BatchResult `json:"results"`
}

// BatchResult holds the vulnerabilities returned for a single query in a batch.
type BatchResult struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

// OSVVulnerability represents a single vulnerability record from OSV.dev.
type OSVVulnerability struct {
	ID               string                 `json:"id"`
	Summary          string                 `json:"summary"`
	Details          string                 `json:"details"`
	Modified         string                 `json:"modified"`
	Published        string                 `json:"published"`
	Aliases          []string               `json:"aliases"`
	Related          []string               `json:"related"`
	Severity         []OSVSeverity          `json:"severity"`
	Affected         []OSVAffected          `json:"affected"`
	References       []OSVReference         `json:"references"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
}

// OSVSeverity represents a severity score entry in an OSV record.
type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// OSVAffected represents an affected package entry in an OSV record.
type OSVAffected struct {
	Package           OSVPackage             `json:"package"`
	Ranges            []OSVRange             `json:"ranges"`
	Versions          []string               `json:"versions"`
	EcosystemSpecific map[string]interface{} `json:"ecosystem_specific"`
	DatabaseSpecific  map[string]interface{} `json:"database_specific"`
}

// OSVPackage identifies a package within an affected entry.
type OSVPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl"`
}

// OSVRange describes a version range in which a package is affected.
type OSVRange struct {
	Type   string     `json:"type"`
	Events []OSVEvent `json:"events"`
}

// OSVEvent represents a single version event within a range.
type OSVEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// OSVReference represents a reference URL in an OSV record.
type OSVReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}
