package model

// EPSSScore represents an Exploit Prediction Scoring System score
// from the FIRST.org EPSS API.
type EPSSScore struct {
	Score      float64 `json:"score"`      // 0.0 - 1.0 probability of exploitation in next 30 days
	Percentile float64 `json:"percentile"` // 0.0 - 1.0 relative ranking
	Date       string  `json:"date"`       // model date (YYYY-MM-DD)
}

// EPSSTrend represents the EPSS score trend over time.
type EPSSTrend struct {
	Current    float64 `json:"current"`
	Previous30 float64 `json:"previous_30d"`
	Delta      float64 `json:"delta"`
	Direction  string  `json:"direction"` // "rising", "falling", "stable"
}
