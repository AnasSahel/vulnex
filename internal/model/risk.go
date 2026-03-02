package model

// RiskPriority represents a composite risk priority level.
type RiskPriority string

const (
	PriorityCritical RiskPriority = "P0-CRITICAL"
	PriorityHigh     RiskPriority = "P1-HIGH"
	PriorityMedium   RiskPriority = "P2-MEDIUM"
	PriorityLow      RiskPriority = "P3-LOW"
	PriorityMinimal  RiskPriority = "P4-MINIMAL"
)

// RiskScore represents a composite risk assessment combining multiple signals.
type RiskScore struct {
	Priority     RiskPriority `json:"priority"`
	Score        float64      `json:"score"`        // 0-100 composite score
	CVSSScore    float64      `json:"cvss_score"`
	EPSSScore    float64      `json:"epss_score"`
	InKEV        bool         `json:"in_kev"`
	Disagreement string       `json:"disagreement,omitempty"` // description of signal disagreement
	Rationale    string       `json:"rationale"`
}

// ComputeRisk calculates a composite risk score from an EnrichedCVE.
//
// Priority matrix:
//   P0 - CRITICAL: In CISA KEV (regardless of other scores)
//   P1 - HIGH:     EPSS >= 0.7 OR (CVSS >= 9.0)
//   P2 - MEDIUM:   EPSS >= 0.3 OR (CVSS >= 7.0 AND EPSS >= 0.1)
//   P3 - LOW:      CVSS >= 7.0 but EPSS < 0.1
//   P4 - MINIMAL:  CVSS < 7.0 AND EPSS < 0.1
func ComputeRisk(cve *EnrichedCVE) RiskScore {
	rs := RiskScore{}

	// Extract CVSS score
	if highest := cve.HighestScore(); highest != nil {
		rs.CVSSScore = highest.BaseScore
	}

	// Extract EPSS score
	if cve.EPSS != nil {
		rs.EPSSScore = cve.EPSS.Score
	}

	rs.InKEV = cve.IsInKEV()

	// Determine priority
	switch {
	case rs.InKEV:
		rs.Priority = PriorityCritical
		rs.Score = 100
		rs.Rationale = "In CISA KEV — confirmed active exploitation"

	case rs.EPSSScore >= 0.7:
		rs.Priority = PriorityHigh
		rs.Score = 85
		rs.Rationale = "High exploitation probability (EPSS >= 0.7)"

	case rs.CVSSScore >= 9.0:
		rs.Priority = PriorityHigh
		rs.Score = 80
		rs.Rationale = "Critical CVSS severity (>= 9.0)"

	case rs.EPSSScore >= 0.3:
		rs.Priority = PriorityMedium
		rs.Score = 60
		rs.Rationale = "Moderate exploitation probability (EPSS >= 0.3)"

	case rs.CVSSScore >= 7.0 && rs.EPSSScore >= 0.1:
		rs.Priority = PriorityMedium
		rs.Score = 55
		rs.Rationale = "High CVSS with some exploitation probability"

	case rs.CVSSScore >= 7.0:
		rs.Priority = PriorityLow
		rs.Score = 35
		rs.Rationale = "High CVSS but low exploitation probability"

	default:
		rs.Priority = PriorityMinimal
		rs.Score = 15
		rs.Rationale = "Low severity and low exploitation probability"
	}

	// Detect disagreements between signals
	rs.Disagreement = detectDisagreement(rs.CVSSScore, rs.EPSSScore, rs.InKEV)

	return rs
}

// detectDisagreement identifies cases where vulnerability signals disagree.
func detectDisagreement(cvss, epss float64, inKEV bool) string {
	switch {
	case cvss >= 9.0 && epss < 0.1 && !inKEV:
		return "HIGH CVSS / LOW EPSS: Theoretically severe but practically low exploitation risk"
	case cvss < 7.0 && epss >= 0.5:
		return "LOW CVSS / HIGH EPSS: Underrated by CVSS but attackers are interested"
	case epss >= 0.7 && !inKEV:
		return "HIGH EPSS / NOT IN KEV: Exploitation likely imminent but not yet confirmed"
	case cvss < 4.0 && inKEV:
		return "LOW CVSS / IN KEV: Low severity score but confirmed active exploitation"
	default:
		return ""
	}
}
