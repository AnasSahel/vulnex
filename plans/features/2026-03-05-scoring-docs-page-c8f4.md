---
name: Scoring and Prioritization Documentation Page
description: Add a dedicated docs page to the website explaining how vulnex scoring works - the formula, signals, weights, profiles, priority tiers, and signal disagreements.
date: 2026-03-05
status: completed
---

# Scoring and Prioritization Documentation Page

## Description

Users who encounter `--cvss-weight`, `--scoring-profile`, or see priority labels like "P0-CRITICAL" in output have no documentation explaining how the scoring system actually works. The formula, what each signal measures, how weights affect the outcome, and how priority tiers are assigned are all buried in Go source code comments.

This feature adds a dedicated documentation page at `website/src/pages/docs/scoring.astro` that explains:

1. **The three signals** - What CVSS, EPSS, and KEV are and what they measure
2. **The weighted score formula** - `score = (CVSS/10 x cvss-weight + EPSS x epss-weight + KEV x kev-weight) x 100`
3. **Built-in scoring profiles** - default, exploit-focused, severity-focused with their weight values and rationale
4. **Custom weights** - How `--cvss-weight`, `--epss-weight`, `--kev-weight` override profiles, with worked examples
5. **Priority tiers (P0-P4)** - The threshold matrix from `ComputeRisk()` that assigns P0-CRITICAL through P4-MINIMAL
6. **Signal disagreements** - When CVSS and EPSS tell different stories (e.g., high severity but low exploit probability)
7. **Practical guidance** - When to raise or lower each weight based on team priorities (compliance-driven vs risk-driven)

## User Stories

- As a security engineer, I want a single page that explains the scoring formula so I can justify prioritization decisions to my team.
- As a new user, I want to understand what P0-P4 labels mean and how they're assigned so I can triage vulnerabilities effectively.
- As a DevSecOps engineer, I want worked examples showing how different weights change scores so I can configure vulnex for my CI pipeline.
- As a manager reviewing a vulnerability report, I want to understand what "signal disagreement" means when vulnex flags a conflict between CVSS and EPSS.

## Acceptance Criteria

- [x] New page at `website/src/pages/docs/scoring.astro` using `DocsLayout` with sidebar navigation.
- [x] Page explains the three signals (CVSS, EPSS, KEV) in plain language with what each measures.
- [x] Page shows the weighted score formula with a step-by-step breakdown.
- [x] Page documents all three built-in profiles with their weight values in a table.
- [x] Page includes at least two worked examples with concrete numbers showing how weights change the final score.
- [x] Page documents the P0-P4 priority matrix with thresholds.
- [x] Page documents signal disagreement patterns (high CVSS/low EPSS, low CVSS/in KEV, etc.).
- [x] Page includes CLI examples using `--scoring-profile` and `--cvss-weight`/`--epss-weight`/`--kev-weight`.
- [x] Navigation from existing pages (navbar, cve.astro) links to the new scoring page.
- [x] Website builds successfully with `npx astro build`.

## Priority

**High**

## Implementation Details

### Files created

- `website/src/pages/docs/scoring.astro` — Full scoring documentation page with 10 sections:
  - Overview, The three signals (CVSS/EPSS/KEV cards), The formula (with two worked examples), Scoring profiles (table + terminal example), Custom weights (two examples + comparison table showing same CVE with different weights), Priority tiers P0-P4 (threshold matrix), Signal disagreements (4 patterns with actions), Practical guidance (when to raise/lower each weight + team-type recommendations), CLI examples (5 terminal windows), Related commands

### Files modified

- `website/src/components/Navbar.astro` — Added "Scoring" link to navigation bar
- `website/src/pages/docs/cve.astro` — Added cross-link to scoring guide from the scoring profiles section
- `README.md` — Added link to scoring guide in the `vulnex scoring` section

## Testing Commands

```bash
# Build the website
cd website && npx astro build

# Dev server to preview the page
cd website && npm run dev
# Then visit http://localhost:4321/docs/scoring/

# Verify Go code still builds/tests
go build ./...
go test ./...
```
