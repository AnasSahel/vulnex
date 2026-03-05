package policy

import "github.com/trustin-tech/vulnex/internal/model"

// Result holds the outcome of evaluating a policy against findings.
type Result struct {
	Failures []Violation `json:"failures"`
	Warnings []Violation `json:"warnings"`
	Passed   bool        `json:"passed"`
}

// Violation represents a single policy rule violation.
type Violation struct {
	Finding  model.SBOMFinding `json:"finding"`
	RuleName string            `json:"rule_name"`
}
