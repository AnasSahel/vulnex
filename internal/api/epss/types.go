package epss

// Response represents the top-level JSON response from the FIRST.org EPSS API.
type Response struct {
	Status     string     `json:"status"`
	StatusCode int        `json:"status-code"`
	Version    string     `json:"version"`
	Total      int        `json:"total"`
	Offset     int        `json:"offset"`
	Limit      int        `json:"limit"`
	Data       []EPSSData `json:"data"`
}

// EPSSData represents a single EPSS record returned by the API.
// EPSS and Percentile are returned as strings by the API and must be
// parsed to float64 before use.
type EPSSData struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
}
