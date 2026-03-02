package vulncheck

// VulnCheckResponse represents the top-level JSON response from the VulnCheck API.
type VulnCheckResponse struct {
	Data []VulnCheckVuln `json:"data"`
}

// VulnCheckVuln represents a single vulnerability record from VulnCheck.
type VulnCheckVuln struct {
	CVEID         string             `json:"cve_id"`
	Description   string             `json:"description"`
	CVSS          VulnCheckCVSS      `json:"cvss"`
	ExploitStatus string             `json:"exploit_status"` // "known", "likely", "none"
	References    []VulnCheckRef     `json:"references"`
}

// VulnCheckCVSS contains CVSS scoring information from VulnCheck.
type VulnCheckCVSS struct {
	Version      string  `json:"version"`       // "3.1", "4.0"
	VectorString string  `json:"vector_string"`
	BaseScore    float64 `json:"base_score"`
	Severity     string  `json:"severity"`
}

// VulnCheckRef represents a reference URL from a VulnCheck vulnerability record.
type VulnCheckRef struct {
	URL    string `json:"url"`
	Source string `json:"source"`
	Type   string `json:"type"` // "advisory", "exploit", "patch"
}
