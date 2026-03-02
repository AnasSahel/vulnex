package nvd

// NVD API 2.0 response types.
// See: https://nvd.nist.gov/developers/vulnerabilities

// CVEResponse is the top-level response from the NVD CVE API 2.0.
type CVEResponse struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability wraps a single CVE entry in the NVD response.
type Vulnerability struct {
	CVE CVE `json:"cve"`
}

// CVE represents the core CVE record from the NVD API.
type CVE struct {
	ID               string         `json:"id"`
	SourceIdentifier string         `json:"sourceIdentifier"`
	Published        string         `json:"published"`
	LastModified     string         `json:"lastModified"`
	VulnStatus       string         `json:"vulnStatus"`
	Descriptions     []LangString   `json:"descriptions"`
	Metrics          Metrics        `json:"metrics"`
	Weaknesses       []Weakness     `json:"weaknesses"`
	Configurations   []Configuration `json:"configurations"`
	References       []NVDReference `json:"references"`
}

// LangString is a language-tagged string as returned by the NVD API.
type LangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// Metrics holds all CVSS metric versions returned by NVD.
type Metrics struct {
	CvssMetricV40 []CvssMetricV40 `json:"cvssMetricV40,omitempty"`
	CvssMetricV31 []CvssMetricV31 `json:"cvssMetricV31,omitempty"`
	CvssMetricV2  []CvssMetricV2  `json:"cvssMetricV2,omitempty"`
}

// CvssMetricV31 represents a CVSS v3.1 score entry from NVD.
type CvssMetricV31 struct {
	Source   string       `json:"source"`
	Type     string       `json:"type"`
	CvssData CvssDataV31 `json:"cvssData"`
}

// CvssDataV31 holds the actual CVSS v3.1 scoring data.
type CvssDataV31 struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// CvssMetricV2 represents a CVSS v2.0 score entry from NVD.
type CvssMetricV2 struct {
	Source   string      `json:"source"`
	Type     string      `json:"type"`
	CvssData CvssDataV2 `json:"cvssData"`
}

// CvssDataV2 holds the actual CVSS v2.0 scoring data.
type CvssDataV2 struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
}

// CvssMetricV40 represents a CVSS v4.0 score entry from NVD.
type CvssMetricV40 struct {
	Source   string       `json:"source"`
	Type     string       `json:"type"`
	CvssData CvssDataV40 `json:"cvssData"`
}

// CvssDataV40 holds the actual CVSS v4.0 scoring data.
type CvssDataV40 struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// Weakness represents a CWE weakness classification from NVD.
type Weakness struct {
	Source      string       `json:"source"`
	Type        string       `json:"type"`
	Description []LangString `json:"description"`
}

// Configuration represents a CPE applicability configuration.
type Configuration struct {
	Nodes []Node `json:"nodes"`
}

// Node represents a single node in a CPE match configuration tree.
type Node struct {
	Operator string        `json:"operator"`
	Negate   bool          `json:"negate"`
	CpeMatch []NVDCPEMatch `json:"cpeMatch"`
}

// NVDCPEMatch represents a single CPE match entry within a configuration node.
type NVDCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
}

// NVDReference represents a reference URL from the NVD API.
type NVDReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags,omitempty"`
}
