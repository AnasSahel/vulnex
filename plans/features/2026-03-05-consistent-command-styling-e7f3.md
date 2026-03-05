---
name: Consistent Command Output Styling
description: Apply lipgloss styling to all remaining unstyled commands (scoring, kev stats, stats, config show) so every command has coherent visual presentation.
date: 2026-03-05
status: completed
---

# Consistent Command Output Styling

## Description

Several commands still use raw `fmt.Fprintf` with ASCII-art headers (`====`, `----`) and no colors, while the majority of commands use lipgloss styles with colored severity labels, bold section headers, and structured key-value layouts. This creates an inconsistent experience when switching between commands.

### Commands that needed styling

1. **`vulnex scoring`** — Plain text with `====` underlines, P0-P4 labels have no color, profile weights not highlighted
2. **`vulnex kev stats`** — Plain text with `====` underlines, vendor counts have no structure
3. **`vulnex stats`** — Plain text with `----` underlines, severity counts not colored
4. **`vulnex config show`** — Plain key-value pairs with no bold labels or section structure

### Commands that are fine as-is

- `version` — Simple info display, plain text is appropriate
- `cache clear` / `cache update` — Simple one-liner confirmations
- `config set` / `config get` / `config init` — Simple one-liner confirmations

## User Stories

- As a user, I want all commands to look visually consistent so the tool feels polished and professional.
- As a user running `vulnex scoring`, I want P0-CRITICAL in red and P4-MINIMAL in gray so I can instantly scan priority tiers.
- As a user running `vulnex kev stats`, I want vendor counts structured with bold headers like other commands.
- As a user running `vulnex stats`, I want severity groups colored to match the severity styling in `cve search`.

## Acceptance Criteria

- [x] `scoring` uses lipgloss: bold blue section headers, colored P0-P4 labels matching severity palette, profile weights in a structured layout.
- [x] `kev stats` uses lipgloss: bold section header, bold labels for stat lines, structured vendor table.
- [x] `stats` uses lipgloss: bold headers, colored severity labels in the breakdown table.
- [x] `config show` uses lipgloss: bold labels (same `labelStyle`/`valueStyle` pattern as `FormatCVE`).
- [x] All four commands respect `--no-color` flag (fall back to plain text).
- [x] `cve watch` refactored to use shared styles instead of duplicated definitions.
- [x] `go build ./...` and `go test ./...` pass.

## Priority

**Medium**

## Dependencies

- Existing lipgloss styles in `internal/output/table.go` (severityStyle, headerStyle, labelStyle, valueStyle)
- `--no-color` global flag on root command

## Implementation Details

### Files created

- `cmd/styles.go` — Shared `cmdStyles` struct with `newCmdStyles(noColor)` constructor, `severity()` and `priority()` methods, and `styledPadCmd()` helper. Used by all commands that render output directly instead of through the Formatter interface.

### Files modified

- `cmd/scoring.go` — Replaced `====` headers and plain text with lipgloss: bold blue section headers, structured profile table with column headers, colored P0-P4 priority labels, muted hint text.
- `cmd/kev_stats.go` — Replaced `====` headers with bold blue headers, bold labels for stat lines, structured vendor list.
- `cmd/stats.go` — Replaced `----` headers with bold headers, colored severity labels in default breakdown, bold total line. Refactored `printTable` → `printStyledTable` accepting `cmdStyles`.
- `cmd/config_cmd.go` — `config show` now uses bold labels and muted style for paths and "(not set)" values.
- `cmd/epss_trend.go` — Replaced `----` dashes with bold blue column headers, styled CVE ID and section header.
- `cmd/cve_watch.go` — Refactored to use shared `cmdStyles` instead of duplicated `watchSuccessStyle`, `watchCVEIDStyle`, and `watchSeverityStyle`. Now respects `--no-color`.

## Documentation

- No README or website doc changes needed — these are internal presentation fixes, not new features.

## Testing Commands

```bash
go build ./...
go test ./...
go run . scoring
go run . scoring --no-color
go run . config show
go run . cve watch --list
go run . cve watch --refresh
# kev stats and stats require API calls:
# go run . kev stats
# go run . stats --year 2024
```
