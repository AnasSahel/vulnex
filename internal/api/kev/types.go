package kev

// Catalog represents the full CISA KEV JSON feed response.
type Catalog struct {
	Title           string          `json:"title"`
	CatalogVersion  string          `json:"catalogVersion"`
	DateReleased    string          `json:"dateReleased"`
	Count           int             `json:"count"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability represents a single entry in the CISA KEV catalog JSON feed.
type Vulnerability struct {
	CveID                        string `json:"cveID"`
	VendorProject                string `json:"vendorProject"`
	Product                      string `json:"product"`
	VulnerabilityName            string `json:"vulnerabilityName"`
	DateAdded                    string `json:"dateAdded"`
	ShortDescription             string `json:"shortDescription"`
	RequiredAction               string `json:"requiredAction"`
	DueDate                      string `json:"dueDate"`
	KnownRansomwareCampaignUse   string `json:"knownRansomwareCampaignUse"`
	Notes                        string `json:"notes"`
}
