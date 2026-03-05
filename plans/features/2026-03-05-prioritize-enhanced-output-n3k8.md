---
name: Prioritize Enhanced Output
description: Redesign prioritize table output with EPSS percentages, rationale lines for urgent findings, prioritization summary block, and inline policy failure markers.
date: 2026-03-05
status: completed
---

# Prioritize Enhanced Output

## Description

The current `prioritize` command output shows raw data (EPSS as decimals, no explanation of priority tiers, no summary of what to do) that requires users to already understand the scoring system to interpret. This feature makes the output self-explanatory and actionable.

Key changes:
1. Show EPSS as percentages (e.g., `94.4%` instead of `0.9440`) with trend arrow.
2. Add a rationale line under P0 and P1 findings explaining WHY they got that priority (using the existing `RiskScore.Rationale` field).
3. Add a "Prioritization" summary block at the bottom with action-required count, can-wait count, and top-priority finding with fix advice.
4. Mark policy-failed findings inline in the table output with a `[FAIL]` marker.

## User Stories

- As a user, I want to understand why a finding is P0-CRITICAL so I can explain it to my team.
- As a user, I want a summary telling me what to do first so I don't have to interpret the table manually.
- As a user, I want EPSS as a percentage so I can understand it at a glance.
- As a user, I want policy failures visible in the table, not just in stderr.

## Acceptance Criteria

- [ ] EPSS column shows percentages (e.g., `94.4%↑`) instead of raw decimals.
- [ ] P0 and P1 findings have a rationale line below them (e.g., `→ Actively exploited, 94% exploitation probability. Patch immediately.`).
- [ ] A "Prioritization" summary block appears after the severity summary with: action-required count (P0+P1), can-wait count (P2-P4), and top priority finding with package name and fix version.
- [ ] Policy-failed findings show `[FAIL]` marker inline next to the priority column.
- [ ] `go build ./...` passes.
- [ ] Website updated: new prioritize docs page, demos.ts updated.

## Implementation Details

### Files modified

#### `internal/output/table.go` — `FormatSBOMResult`
1. Change EPSS formatting from `%.4f` to percentage: `fmt.Sprintf("%.1f%%", f.EPSS.Score*100)` + trend arrow.
2. After printing each P0/P1 finding row, print an indented rationale line using `f.Risk.Rationale`.
3. Accept optional `policyResult` or mark findings with a `PolicyFailed` field. Since `FormatSBOMResult` takes `*model.SBOMResult`, add a `PolicyFailures` map to `SBOMResult` keyed by advisory ID.
4. After the severity summary, print a "Prioritization" block:
   - Count P0+P1 as "action required", P2-P4 as "can wait"
   - Find the top-priority finding and show its CVE, package, and fix version

#### `internal/model/reference.go` — `SBOMResult`
Add `PolicyFailures map[string]string` field to carry policy failure rule names into the formatter.

#### `cmd/prioritize.go`
After policy evaluation, populate `result.PolicyFailures` map before calling `FormatSBOMResult`.

#### `website/src/pages/docs/prioritize.astro` (new)
New docs page with: overview, usage, examples showing the enhanced output, flags table, policy section, comparison with raw scanner output, tips & recipes.

#### `website/src/content/docs-nav.ts`
Add prioritize entry under Commands.

#### `website/src/content/demos.ts`
Update or add a prioritize demo tab.

### Target output format
```
golang.org/x/net 0.7.0 (Go)
  ID                Severity  CVSS  EPSS      KEV  Priority      Fixed
  CVE-2023-44487    HIGH      7.5   94.4%↑    YES  P0-CRITICAL   0.17.0
    → Actively exploited (KEV), 94% exploitation probability. Patch immediately.
  CVE-2023-39325    HIGH      7.5   0.2%      —    P3-LOW        0.17.0
  CVE-2022-27664    HIGH      7.5   0.1%      —    P3-LOW        0.0.0-2~

braces 3.0.2 (npm)
  CVE-2024-4068     MEDIUM    7.5   0.2%      —    P3-LOW        3.0.3

Summary: 4 components scanned, 2 vulnerable, 4 findings
  HIGH: 3  MEDIUM: 1

Prioritization
  Action required    1 finding — patch immediately (P0)
  Can wait           3 findings — low exploitation risk (P3)
  Top priority       CVE-2023-44487 in golang.org/x/net — upgrade to 0.17.0
```

## Priority

**High** — Core UX improvement for the flagship triage command.

## Dependencies

- `internal/output/table.go` — Existing FormatSBOMResult
- `internal/model/risk.go` — Existing RiskScore.Rationale field
- `cmd/prioritize.go` — Existing command

## Testing Commands

```bash
go build ./...
go run . prioritize testdata/trivy-sample.json
go run . prioritize testdata/grype-sample.json
go run . prioritize testdata/scanner-sample.sarif --policy testdata/policy-sample.yaml
```

## Documentation

- New `website/src/pages/docs/prioritize.astro` page.
- `docs-nav.ts` updated with prioritize entry.
- `demos.ts` updated with prioritize demo.
- No README changes needed (already documented).
