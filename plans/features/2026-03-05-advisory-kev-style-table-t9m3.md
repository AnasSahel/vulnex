---
name: Advisory KEV-Style Table Output
description: Replace the box-drawn lipgloss table in advisory search/affected with a plain space-aligned table matching the KEV list style, with colored severity and a count footer.
date: 2026-03-05
status: completed
---

# Advisory KEV-Style Table Output

## Description

The `advisory search` and `advisory affected` commands currently render results using a lipgloss box-drawn table (`table.New()`), which looks inconsistent with the `kev list`/`kev recent` output that uses a clean, plain space-aligned table with `styledPad`.

This feature replaces `FormatAdvisories` in the table formatter to use the same plain-text column style as `FormatKEVList` — with severity-colored text, truncated summaries, and a count footer showing total results with severity breakdown.

## User Stories

- As a user, I want `advisory search` output to look consistent with `kev list` so the CLI feels unified.
- As a user, I want severity in advisory results to be color-coded so I can quickly spot critical/high items.
- As a user, I want a count footer so I know how many results were returned.

## Acceptance Criteria

- [x] `FormatAdvisories` in `table.go` uses plain space-aligned columns (no box-drawn borders).
- [x] Columns: `GHSA ID | Severity | CVE | Summary` with fixed widths.
- [x] Severity is color-coded using the existing `severityStyle`.
- [x] Summary is truncated (respects `--long` flag).
- [x] Footer shows total count and severity breakdown (e.g. `CRITICAL: 1  HIGH: 2  MEDIUM: 1`).
- [x] `advisory search`, `advisory affected` both use the updated format.
- [x] `go build ./...` passes.
- [x] No changes to JSON/CSV/YAML/SARIF/Markdown formatters.

## Implementation Details

### File modified

- `internal/output/table.go` — Rewrite `FormatAdvisories` method

### Changes

Replace the current `FormatAdvisories` implementation (which uses `table.New()`) with a `styledPad`-based approach matching `FormatKEVList`:

1. Define column widths for GHSA ID (22), Severity (10), CVE (18), Summary (rest).
2. Print header row using `styledPad` + `headerStyle`.
3. Print each advisory row with severity coloring.
4. Print footer: `\n%d advisories` + severity breakdown.

## Priority

**Medium** — Visual consistency improvement.

## Dependencies

- `internal/output/table.go` — Existing table formatter
- `model.Advisory` — Existing advisory model

## Documentation

- Update website docs for advisory commands to show new table output style.
- No README changes needed.
