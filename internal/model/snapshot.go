package model

import "time"

// Snapshot captures the key risk signals of a CVE at a point in time.
// One snapshot is stored per CVE per day (upserted).
type Snapshot struct {
	CVEID    string       `json:"cve_id"`
	Date     string       `json:"date"` // YYYY-MM-DD
	CVSS     float64      `json:"cvss"`
	EPSS     float64      `json:"epss"`
	EPSSPctl float64      `json:"epss_percentile"`
	InKEV    bool         `json:"in_kev"`
	Exploits int          `json:"exploits"` // count of known exploits
	Priority RiskPriority `json:"priority"`
	Score    float64      `json:"score"` // weighted composite score (0-100)
	Data     []byte       `json:"data"`  // full EnrichedCVE JSON blob
}

// SnapshotFromEnriched creates a Snapshot from an EnrichedCVE and its computed risk.
func SnapshotFromEnriched(cve *EnrichedCVE, risk RiskScore) Snapshot {
	s := Snapshot{
		CVEID:    cve.ID,
		Date:     time.Now().Format("2006-01-02"),
		CVSS:     risk.CVSSScore,
		EPSS:     risk.EPSSScore,
		InKEV:    risk.InKEV,
		Priority: risk.Priority,
		Score:    risk.Score,
	}

	if cve.EPSS != nil {
		s.EPSSPctl = cve.EPSS.Percentile
	}

	return s
}
