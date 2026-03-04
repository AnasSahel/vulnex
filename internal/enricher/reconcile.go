package enricher

import (
	"fmt"
	"math"

	"github.com/trustin-tech/vulnex/internal/model"
)

// significanceThresholdMedium is the delta above which a conflict is considered medium.
const significanceThresholdMedium = 1.0

// significanceThresholdHigh is the delta above which a conflict is considered high.
const significanceThresholdHigh = 2.0

// ReconcileScores compares CVSS scores from different sources (Primary vs Secondary)
// within the same CVSS version. It returns a list of conflicts where the delta
// exceeds the significance threshold (>1.0 points).
func ReconcileScores(cve *model.EnrichedCVE) []model.ScoreConflict {
	if cve == nil || len(cve.CVSS) < 2 {
		return nil
	}

	// Group scores by version and type.
	type key struct {
		version string
		typ     string
	}
	grouped := make(map[key][]model.CVSSScore)
	for _, s := range cve.CVSS {
		k := key{version: s.Version, typ: s.Type}
		grouped[k] = append(grouped[k], s)
	}

	// For each version, compare Primary vs Secondary scores.
	var conflicts []model.ScoreConflict

	versions := []string{"4.0", "3.1", "3.0", "2.0"}
	for _, ver := range versions {
		primaries := grouped[key{version: ver, typ: "Primary"}]
		secondaries := grouped[key{version: ver, typ: "Secondary"}]

		if len(primaries) == 0 || len(secondaries) == 0 {
			continue
		}

		primary := highestScore(primaries)
		secondary := highestScore(secondaries)
		delta := math.Abs(primary.BaseScore - secondary.BaseScore)

		if delta <= significanceThresholdMedium {
			continue
		}

		significance := classifySignificance(delta)

		conflicts = append(conflicts, model.ScoreConflict{
			Version:      ver,
			NVDScore:     primary.BaseScore,
			CNAScore:     secondary.BaseScore,
			Delta:        math.Round(delta*100) / 100,
			Significance: significance,
		})
	}

	return conflicts
}

// classifySignificance returns a human-readable significance label for a score delta.
func classifySignificance(delta float64) string {
	switch {
	case delta > significanceThresholdHigh:
		return "high"
	case delta > significanceThresholdMedium:
		return "medium"
	default:
		return "low"
	}
}

// highestScore returns the CVSSScore with the highest BaseScore from a slice.
func highestScore(scores []model.CVSSScore) model.CVSSScore {
	best := scores[0]
	for _, s := range scores[1:] {
		if s.BaseScore > best.BaseScore {
			best = s
		}
	}
	return best
}

// FormatConflicts returns a human-readable summary of score conflicts.
func FormatConflicts(conflicts []model.ScoreConflict) string {
	if len(conflicts) == 0 {
		return "No CVSS score conflicts detected"
	}

	result := fmt.Sprintf("%d CVSS score conflict(s) detected:\n", len(conflicts))
	for _, c := range conflicts {
		result += fmt.Sprintf(
			"  CVSS v%s: NVD=%.1f vs CNA=%.1f (delta=%.1f, significance=%s)\n",
			c.Version, c.NVDScore, c.CNAScore, c.Delta, c.Significance,
		)
	}
	return result
}
