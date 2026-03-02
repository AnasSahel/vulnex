package model

// KEVEntry represents an entry in the CISA Known Exploited Vulnerabilities catalog.
type KEVEntry struct {
	CVEID                   string `json:"cve_id"`
	VendorProject           string `json:"vendor_project"`
	Product                 string `json:"product"`
	VulnerabilityName       string `json:"vulnerability_name"`
	DateAdded               string `json:"date_added"`
	ShortDescription        string `json:"short_description"`
	RequiredAction          string `json:"required_action"`
	DueDate                 string `json:"due_date"`
	KnownRansomwareCampaign string `json:"known_ransomware_campaign"` // "Known", "Unknown"
	Notes                   string `json:"notes,omitempty"`
}
