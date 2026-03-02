package enricher

import "github.com/trustin-tech/vulnex/internal/model"

// ComputeRiskScore computes a composite risk score for an enriched CVE.
func ComputeRiskScore(cve *model.EnrichedCVE) model.RiskScore {
	return model.ComputeRisk(cve)
}

// ComputeRiskScores computes risk scores for a batch of enriched CVEs.
func ComputeRiskScores(cves []*model.EnrichedCVE) []model.RiskScore {
	scores := make([]model.RiskScore, len(cves))
	for i, cve := range cves {
		if cve != nil {
			scores[i] = model.ComputeRisk(cve)
		}
	}
	return scores
}
