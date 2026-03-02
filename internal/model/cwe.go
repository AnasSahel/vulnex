package model

// CWEEntry represents a Common Weakness Enumeration classification.
type CWEEntry struct {
	ID          string `json:"id"`          // e.g., "CWE-79"
	Description string `json:"description"` // e.g., "Improper Neutralization of Input During Web Page Generation"
	Source      string `json:"source"`      // "nvd@nist.gov", CNA identifier
}
