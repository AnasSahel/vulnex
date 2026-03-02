package model

// CVSSScore represents a CVSS score from any version (2.0, 3.0, 3.1, 4.0).
type CVSSScore struct {
	Version      string  `json:"version"`       // "2.0", "3.0", "3.1", "4.0"
	VectorString string  `json:"vector_string"`
	BaseScore    float64 `json:"base_score"`
	Severity     string  `json:"severity"` // NONE, LOW, MEDIUM, HIGH, CRITICAL
	Source       string  `json:"source"`   // "nvd@nist.gov", CNA identifier, etc.
	Type         string  `json:"type"`     // "Primary", "Secondary"
}

// HighestCVSS returns the CVSSScore with the highest base score from a slice.
// Returns nil if the slice is empty.
func HighestCVSS(scores []CVSSScore) *CVSSScore {
	if len(scores) == 0 {
		return nil
	}
	highest := &scores[0]
	for i := 1; i < len(scores); i++ {
		if scores[i].BaseScore > highest.BaseScore {
			highest = &scores[i]
		}
	}
	return highest
}

// SeverityFromScore returns the CVSS v3.x severity string for a given base score.
func SeverityFromScore(score float64) string {
	switch {
	case score == 0.0:
		return "NONE"
	case score <= 3.9:
		return "LOW"
	case score <= 6.9:
		return "MEDIUM"
	case score <= 8.9:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}
