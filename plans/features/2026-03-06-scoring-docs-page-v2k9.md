---
name: Scoring Documentation Page
description: Website documentation page for the scoring command explaining CVSS+EPSS+KEV composite scoring, profiles, priority tiers, and signal disagreements.
date: 2026-03-06
status: completed
---

# Scoring Documentation Page

## Description

Already implemented. The scoring docs page exists at `website/src/pages/docs/scoring.astro` with full coverage of:
- Problem with CVSS-only prioritization
- Three signals (CVSS, EPSS, KEV) with limitations
- Weighted scoring formula with worked examples
- Three built-in profiles (default, exploit-focused, severity-focused)
- Custom weights with CLI examples
- P0-P4 priority tier matrix
- Signal disagreement detection
- Practical guidance by team type

Also already present in `docs-nav.ts` (Reference section) and `demos.ts` (Scoring tab).

## Status

No changes needed — feature was already implemented in a previous session.
