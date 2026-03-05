---
status: active
type: feature
date: 2026-03-03
title: Competitive Roadmap — Positioning Against Trivy
---

# Competitive Roadmap: Positioning vulnex Against Trivy and Similar Tools

Date: 2026-03-03
Project: `vulnex`

## Executive Summary

`vulnex` should not try to beat Trivy by becoming a broad scanner first.
The winning strategy is to become the **risk-prioritization intelligence layer** that consumes scanner outputs and helps teams decide what to fix first.

- Trivy excels at broad detection and ecosystem maturity.
- vulnex can win on multi-source intelligence, prioritization quality, and low-noise triage workflows.

## Strategic Position

Position vulnex as:
- **Detection input**: from Trivy/Grype/osv-scanner/SBOMs
- **Decision engine**: enrich with KEV + EPSS + NVD + GHSA + OSV
- **Action output**: explainable priority, policy gate, and routing to team workflows

Primary value proposition:
- fewer false-priority alerts
- faster triage
- better signal-to-noise in CI and security operations

## 3-Release Plan

## Release 1 (v1.3): Reliability and Trust
Target: 4-6 weeks

### Objective
Remove confidence-killing issues and establish dependable baseline behavior in local and CI environments.

### Scope
1. Correctness and stability
- fix `--no-cache` nil panic in KEV flows
- implement OSV CVE alias fallback path
- align docs/help/config path semantics

2. Core test coverage uplift
- add tests for `internal/api/{kev,osv,nvd,ghsa}`
- add tests for `internal/enricher`, `internal/cache`, `internal/config`
- golden tests for formatter outputs where practical

3. Source reliability visibility
- include per-source status in structured output
- mark partial enrichment explicitly when a source fails

### Success Metrics
- zero known panics in standard command paths
- >70% coverage in critical core packages
- deterministic behavior for cache/no-cache/offline combinations

### Exit Criteria
- all high-severity runtime bugs fixed
- CI remains green with race checks
- docs and CLI help no longer contradict runtime behavior

## Release 2 (v1.4): Scanner Interop and Policy Engine
Target: 6-8 weeks

### Objective
Integrate into existing pipelines immediately without requiring teams to replace scanners.

### Scope
1. Scanner import adapters
- add `vulnex import --from trivy|grype|osv-scanner <file>`
- normalize findings into a shared internal model

2. Policy-based gating
- add `vulnex policy check`
- policy rules combine CVSS + EPSS + KEV + exploitability signals
- support policy examples such as:
  - fail if `KEV == true`
  - fail if `EPSS > 0.70` and `severity >= high`

3. Baseline and diff workflows
- first-class support for "new since baseline"
- allowlist with expiry and reason metadata

### Success Metrics
- teams can keep Trivy and add vulnex as post-processor with minimal changes
- measurable reduction in low-value CI failures
- reduced median time from finding to priority decision

### Exit Criteria
- import works for at least Trivy JSON and one additional scanner format
- policy engine supports deterministic pass/fail output for CI
- baseline/diff behavior documented and tested

## Release 3 (v1.5): Team Workflow and Explainability
Target: 8-10 weeks

### Objective
Move from a strong CLI utility to a team-level operational product.

### Scope
1. Explainable prioritization
- add `vulnex explain <id>` output explaining score/priority composition
- include machine-readable rationale in JSON mode

2. Workflow integrations
- emit actionable output for GitHub Issues/Jira/Slack/Discord
- dedupe and alert only on meaningful deltas (e.g., new P0/P1)

3. Historical intelligence
- EPSS trend-aware alerts
- watched CVE/component change notifications

### Success Metrics
- increased recurring team usage (weekly active repos)
- lower alert fatigue in security channels
- improved MTTR for critical vulnerabilities

### Exit Criteria
- explain output is stable and test-covered
- at least one ticketing and one chat integration stable for production use
- trend and watch workflows validated in CI and real projects

## Why This Beats Feature-Parity Strategy

Trying to replicate Trivy’s full scanner breadth quickly is high effort and low differentiation.
A decision-intelligence strategy is both faster and more defensible:

- Trivy keeps doing detection.
- vulnex becomes the layer that determines urgency, ownership, and next action.

This creates complementary adoption rather than direct displacement risk.

## Packaging and Platform Priorities

Short-term priorities:
- add Windows CI smoke runs (`windows-latest`) to validate runtime behavior continuously
- maintain zero-CGO, multi-arch binaries via GoReleaser
- document platform-specific config/cache paths clearly

## Suggested KPIs Across Releases

Product quality:
- panic count
- error-rate per source
- enrichment completeness rate

Decision quality:
- percentage of findings auto-prioritized
- precision of "high-priority" recommendations (as assessed by triage teams)

Adoption:
- number of repos using `vulnex` in CI
- number of pipelines using policy mode
- retention of weekly active users

## Immediate Next Steps

1. Execute Release 1 critical fixes already identified.
2. Define a normalized import schema for Trivy first (JSON).
3. Implement minimal `policy check` with 3-5 high-value built-in rules.
4. Add Windows CI smoke workflow to de-risk cross-platform usability.
