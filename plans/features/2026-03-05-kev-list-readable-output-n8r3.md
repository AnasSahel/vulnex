---
name: Readable KEV List Output
description: Replace bordered table in kev list/recent with a plain space-aligned layout and add --limit/--offset pagination to avoid overwhelming output.
date: 2026-03-05
status: completed
---

# Readable KEV List Output

## Description

The `kev list` and `kev recent` commands render all entries in a bordered lipgloss table. With 1,200+ entries in the KEV catalog, rows wrap across multiple lines because the bordered table exceeds terminal width. This makes the output unreadable.

Two changes:
1. **Drop borders** — Switch to a plain space-aligned layout (like `epss trend` or `stats`) that fits within standard terminal widths.
2. **Add pagination** — Default to 20 rows with `--limit` and `--offset` flags so users aren't flooded with 1,200+ entries.

## User Stories

- As a user running `kev list`, I want output that fits my terminal without wrapping.
- As a user, I want to page through KEV entries instead of seeing all 1,200+ at once.
- As a user running `kev recent`, I want the same readable format.

## Acceptance Criteria

- [x] `kev list` uses plain space-aligned columns (no borders).
- [x] `kev list` defaults to 20 rows.
- [x] `--limit N` controls how many rows to display (0 = all).
- [x] `--offset N` skips the first N entries for pagination.
- [x] `kev recent` uses the same plain layout.
- [x] Header row is styled (bold blue) matching other commands.
- [x] Vendor and Product columns truncated to fit terminal width.
- [x] `go build ./...` passes.

## Implementation Details

### Files modified

- `internal/output/table.go` — Replaced bordered `table.New()` in `FormatKEVList` with plain `fmt.Fprintf` using `styledPad` for headers and fixed-width `%-*s` for data. Columns: CVE ID (18), Vendor (16), Product (24), Added (12), Ransomware. Due Date column removed from list view to save horizontal space (still available in `kev check` detail view and structured output formats). Vendor/Product truncated to column width.
- `cmd/kev_list.go` — Added `--limit` (default 20) and `--offset` (default 0) flags. Pagination applied only to table output; structured formats (json, csv) get all data. Shows "Showing N of M entries" on stderr.

## Testing Commands

```bash
go build ./...
go run . kev list                    # 20 entries, plain layout
go run . kev list --limit 50         # 50 entries
go run . kev list --limit 0          # all entries
go run . kev list --offset 20        # skip first 20
go run . kev recent                  # plain layout, last 7 days
```

## Priority

**Medium**

## Dependencies

- `internal/output/table.go` — `FormatKEVList` method
- `cmd/kev_list.go` — kev list command
- `cmd/kev_check.go` — already uses row layout (not affected)

## Documentation

- No README changes needed — pagination flags are self-documenting via `--help`.
- No website changes needed.
