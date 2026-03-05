package policy

import (
	"fmt"
	"os"
	"strings"

	"github.com/trustin-tech/vulnex/internal/model"
	"gopkg.in/yaml.v3"
)

// Policy represents a set of rules for evaluating vulnerability findings.
type Policy struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// Rule defines a single policy rule with a match condition and action.
type Rule struct {
	Name   string    `yaml:"name"`
	Match  Condition `yaml:"match"`
	Action string    `yaml:"action"` // "fail", "warn", "allow"
}

// Condition defines the criteria for matching a finding. All non-nil fields must match (AND).
type Condition struct {
	KEV        *bool    `yaml:"kev,omitempty"`
	Severity   []string `yaml:"severity,omitempty"`
	EPSSGte    *float64 `yaml:"epss_gte,omitempty"`
	CVSSGte    *float64 `yaml:"cvss_gte,omitempty"`
	HasExploit *bool    `yaml:"has_exploit,omitempty"`
	Priority   []string `yaml:"priority,omitempty"`
	Ecosystem  []string `yaml:"ecosystem,omitempty"`
}

// Load reads and parses a policy YAML file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy file: %w", err)
	}

	if p.Version == 0 {
		return nil, fmt.Errorf("policy file missing version field")
	}

	return &p, nil
}

// Evaluate returns the action and rule name for the first matching rule.
// Returns ("", "") if no rule matches.
func (p *Policy) Evaluate(f model.SBOMFinding) (action, ruleName string) {
	for _, rule := range p.Rules {
		if matchesCondition(rule.Match, f) {
			return rule.Action, rule.Name
		}
	}
	return "", ""
}

// EvaluateAll evaluates all findings against the policy and returns the result.
func (p *Policy) EvaluateAll(findings []model.SBOMFinding) *Result {
	result := &Result{Passed: true}

	for _, f := range findings {
		action, ruleName := p.Evaluate(f)
		switch action {
		case "fail":
			result.Failures = append(result.Failures, Violation{
				Finding:  f,
				RuleName: ruleName,
			})
			result.Passed = false
		case "warn":
			result.Warnings = append(result.Warnings, Violation{
				Finding:  f,
				RuleName: ruleName,
			})
		}
	}

	return result
}

func matchesCondition(c Condition, f model.SBOMFinding) bool {
	if c.KEV != nil {
		hasKEV := f.KEV != nil
		if *c.KEV != hasKEV {
			return false
		}
	}

	if len(c.Severity) > 0 {
		if !containsFold(c.Severity, f.Advisory.Severity) {
			return false
		}
	}

	if c.EPSSGte != nil {
		if f.EPSS == nil || f.EPSS.Score < *c.EPSSGte {
			return false
		}
	}

	if c.CVSSGte != nil {
		if f.CVSSScore < *c.CVSSGte {
			return false
		}
	}

	if c.HasExploit != nil {
		if *c.HasExploit != f.HasExploit {
			return false
		}
	}

	if len(c.Priority) > 0 {
		if f.Risk == nil || !containsFold(c.Priority, string(f.Risk.Priority)) {
			return false
		}
	}

	if len(c.Ecosystem) > 0 {
		if !containsFold(c.Ecosystem, f.Ecosystem) {
			return false
		}
	}

	return true
}

func containsFold(slice []string, val string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, val) {
			return true
		}
	}
	return false
}
