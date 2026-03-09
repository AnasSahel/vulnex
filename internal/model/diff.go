package model

import "fmt"

// ChangeType classifies what changed for a CVE between snapshots.
type ChangeType string

const (
	ChangeEscalated   ChangeType = "escalated"
	ChangeDeescalated ChangeType = "de-escalated"
	ChangeNewExploits ChangeType = "new_exploits"
	ChangeEPSSMovement ChangeType = "epss_movement"
	ChangeStable      ChangeType = "stable"
	ChangeNew         ChangeType = "new" // no previous snapshot
)

// CVEChange represents a change in a single CVE between two snapshots.
type CVEChange struct {
	CVEID       string       `json:"cve_id"`
	Type        ChangeType   `json:"type"`
	OldPriority RiskPriority `json:"old_priority,omitempty"`
	NewPriority RiskPriority `json:"new_priority"`
	OldEPSS     float64      `json:"old_epss,omitempty"`
	NewEPSS     float64      `json:"new_epss"`
	EPSSDelta   float64      `json:"epss_delta,omitempty"`
	EPSSPctChg  float64      `json:"epss_pct_change,omitempty"` // percentage change
	OldCVSS     float64      `json:"old_cvss,omitempty"`
	NewCVSS     float64      `json:"new_cvss"`
	OldScore    float64      `json:"old_score,omitempty"`
	NewScore    float64      `json:"new_score"`
	KEVAdded    bool         `json:"kev_added,omitempty"`
	OldInKEV    bool         `json:"old_in_kev,omitempty"`
	NewInKEV    bool         `json:"new_in_kev"`
	OldExploits int          `json:"old_exploits,omitempty"`
	NewExploits int          `json:"new_exploits"`
	Details     []string     `json:"details,omitempty"` // human-readable change descriptions
}

// WatchDiff represents the complete diff result for a watch list.
type WatchDiff struct {
	Since       string      `json:"since"`       // comparison date or duration
	TotalCVEs   int         `json:"total_cves"`
	ChangedCVEs int         `json:"changed_cves"`
	Escalated   []CVEChange `json:"escalated,omitempty"`
	Deescalated []CVEChange `json:"de_escalated,omitempty"`
	NewExploits []CVEChange `json:"new_exploits,omitempty"`
	EPSSMoved   []CVEChange `json:"epss_moved,omitempty"`
	NewEntries  []CVEChange `json:"new_entries,omitempty"`
	Stable      []CVEChange `json:"stable,omitempty"`
	HasEscalation bool     `json:"has_escalation"`
}

// ComputeChange compares a current snapshot against a previous one and classifies the change.
func ComputeChange(current, previous *Snapshot) CVEChange {
	c := CVEChange{
		CVEID:       current.CVEID,
		NewPriority: current.Priority,
		NewEPSS:     current.EPSS,
		NewCVSS:     current.CVSS,
		NewScore:    current.Score,
		NewInKEV:    current.InKEV,
		NewExploits: current.Exploits,
	}

	if previous == nil {
		c.Type = ChangeNew
		c.Details = append(c.Details, "New to watch list")
		return c
	}

	c.OldPriority = previous.Priority
	c.OldEPSS = previous.EPSS
	c.OldCVSS = previous.CVSS
	c.OldScore = previous.Score
	c.OldInKEV = previous.InKEV
	c.OldExploits = previous.Exploits

	// KEV addition
	if current.InKEV && !previous.InKEV {
		c.KEVAdded = true
		c.Details = append(c.Details, "Added to CISA KEV")
	}

	// EPSS delta
	c.EPSSDelta = current.EPSS - previous.EPSS
	if previous.EPSS > 0 {
		c.EPSSPctChg = (c.EPSSDelta / previous.EPSS) * 100
	} else if current.EPSS > 0 {
		c.EPSSPctChg = 100 // from zero to something
	}

	// Classify change type by priority
	oldRank := priorityRank(previous.Priority)
	newRank := priorityRank(current.Priority)

	switch {
	case newRank < oldRank: // lower rank = higher priority (P0 < P4)
		c.Type = ChangeEscalated
		c.Details = append(c.Details, fmt.Sprintf("%s → %s", previous.Priority, current.Priority))

	case newRank > oldRank:
		c.Type = ChangeDeescalated
		c.Details = append(c.Details, fmt.Sprintf("%s → %s", previous.Priority, current.Priority))

	case current.Exploits > previous.Exploits:
		c.Type = ChangeNewExploits
		c.Details = append(c.Details, fmt.Sprintf("+%d new exploits", current.Exploits-previous.Exploits))

	case isSignificantEPSSChange(previous.EPSS, current.EPSS):
		c.Type = ChangeEPSSMovement
		direction := "rising"
		if c.EPSSDelta < 0 {
			direction = "falling"
		}
		c.Details = append(c.Details, fmt.Sprintf("EPSS %s (%.3f → %.3f)", direction, previous.EPSS, current.EPSS))

	default:
		c.Type = ChangeStable
	}

	// Add EPSS detail for non-stable, non-EPSS-movement changes
	if c.Type != ChangeStable && c.Type != ChangeEPSSMovement && isSignificantEPSSChange(previous.EPSS, current.EPSS) {
		c.Details = append(c.Details, fmt.Sprintf("EPSS %.3f → %.3f", previous.EPSS, current.EPSS))
	}

	return c
}

// isSignificantEPSSChange returns true if the EPSS change is worth reporting.
// Threshold: absolute change > 0.02 OR relative change > 20%.
func isSignificantEPSSChange(old, new float64) bool {
	delta := new - old
	if delta < 0 {
		delta = -delta
	}
	if delta > 0.02 {
		return true
	}
	if old > 0 {
		pct := delta / old
		return pct > 0.20
	}
	return false
}

// priorityRank converts priority to a numeric rank (P0=0, P4=4) for comparison.
func priorityRank(p RiskPriority) int {
	switch p {
	case PriorityCritical:
		return 0
	case PriorityHigh:
		return 1
	case PriorityMedium:
		return 2
	case PriorityLow:
		return 3
	case PriorityMinimal:
		return 4
	default:
		return 5
	}
}
