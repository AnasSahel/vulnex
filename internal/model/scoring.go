package model

import "math"

// ScoringProfile defines the weights for computing a weighted composite
// vulnerability score from multiple signals.
type ScoringProfile struct {
	Name       string  `json:"name"`
	CVSSWeight float64 `json:"cvss_weight"` // Weight for CVSS base score (0.0-1.0)
	EPSSWeight float64 `json:"epss_weight"` // Weight for EPSS score (0.0-1.0)
	KEVWeight  float64 `json:"kev_weight"`  // Weight for KEV membership (0.0-1.0)
}

// DefaultProfile returns the default scoring profile with balanced weights:
//   - CVSS: 0.3 — severity matters but is often inflated
//   - EPSS: 0.5 — exploitation probability is the strongest signal
//   - KEV:  0.2 — confirmed exploitation is a binary but important signal
func DefaultProfile() ScoringProfile {
	return ScoringProfile{
		Name:       "default",
		CVSSWeight: 0.3,
		EPSSWeight: 0.5,
		KEVWeight:  0.2,
	}
}

// ExploitFocusedProfile returns a profile that heavily weights exploitation evidence.
func ExploitFocusedProfile() ScoringProfile {
	return ScoringProfile{
		Name:       "exploit-focused",
		CVSSWeight: 0.1,
		EPSSWeight: 0.6,
		KEVWeight:  0.3,
	}
}

// SeverityFocusedProfile returns a profile that weights CVSS severity highest.
func SeverityFocusedProfile() ScoringProfile {
	return ScoringProfile{
		Name:       "severity-focused",
		CVSSWeight: 0.6,
		EPSSWeight: 0.3,
		KEVWeight:  0.1,
	}
}

// ComputeWeightedScore calculates a weighted composite score (0-100) from an
// EnrichedCVE using the provided ScoringProfile.
//
// The score is computed as:
//
//	score = (cvssNormalized * CVSSWeight + epssNormalized * EPSSWeight + kevNormalized * KEVWeight) * 100
//
// Where:
//   - cvssNormalized = baseScore / 10.0 (CVSS is 0-10, normalized to 0-1)
//   - epssNormalized = epssScore (EPSS is already 0-1)
//   - kevNormalized  = 1.0 if in KEV, 0.0 otherwise
func ComputeWeightedScore(profile ScoringProfile, cve *EnrichedCVE) float64 {
	if cve == nil {
		return 0
	}

	var cvssNorm float64
	if highest := cve.HighestScore(); highest != nil {
		cvssNorm = highest.BaseScore / 10.0
	}

	var epssNorm float64
	if cve.EPSS != nil {
		epssNorm = cve.EPSS.Score
	}

	var kevNorm float64
	if cve.IsInKEV() {
		kevNorm = 1.0
	}

	raw := cvssNorm*profile.CVSSWeight + epssNorm*profile.EPSSWeight + kevNorm*profile.KEVWeight
	score := raw * 100.0

	// Clamp to [0, 100] and round to two decimal places.
	score = math.Max(0, math.Min(100, score))
	return math.Round(score*100) / 100
}
