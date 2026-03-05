---
name: Display Missing KEV Fields
description: Show the vulnerability_name, short_description, and notes fields from the CISA KEV catalog that are currently parsed but never displayed.
date: 2026-03-05
status: completed
---

# Display Missing KEV Fields

## Description

The CISA KEV catalog provides three fields that vulnex parses into `model.KEVEntry` but never renders:

- **`vulnerability_name`** — CISA's own name for the vulnerability (e.g., "Apache Log4j2 Remote Code Execution Vulnerability")
- **`short_description`** — A one-line description of the vulnerability from CISA's perspective
- **`notes`** — Additional notes (often empty, but present on some entries)

These fields provide valuable context that complements the NVD description. They should be surfaced in both the enriched CVE detail view and the KEV list/check outputs.

## User Stories

- As a security analyst, I want to see CISA's vulnerability name so I can quickly identify what the KEV entry refers to without reading the full NVD description.
- As a user running `vulnex kev list`, I want to see the short description so I can triage entries without looking each one up individually.
- As a user running `vulnex enrich`, I want to see all available KEV context in the KEV Details section.

## Acceptance Criteria

- [x] `vulnex enrich` KEV Details section shows `vulnerability_name` as "Name" when non-empty.
- [x] `vulnex enrich` KEV Details section shows `short_description` as "Description" when non-empty.
- [x] `vulnex enrich` KEV Details section shows `notes` when non-empty.
- [x] `vulnex kev list` table includes "Name" column (truncated to 40 chars).
- [x] `go build ./...` passes.
- [x] All existing formatters (JSON, CSV, etc.) continue to work since they serialize the full model.

## Priority

**Low**

## Dependencies

- `internal/model/kev.go` — Already has all three fields defined
- `internal/output/table.go` — Renders KEV Details section and KEV list/check tables

## Documentation

- No README changes needed — the fields are already part of the KEV data model.
- No website changes needed — this is a display improvement, not a new feature.

## Implementation Details

### Files modified

- `internal/output/table.go` — Two changes:
  1. `FormatCVE` KEV Details section: added `Name:` (vulnerability_name), `Description:` (short_description), and `Notes:` fields, all conditionally shown when non-empty.
  2. `FormatKEVList`: added "Name" column to the table header and rows, truncated to 40 characters for readability.

### Design decisions

- Fields shown conditionally (only when non-empty) to avoid cluttering output.
- VulnerabilityName truncated to 40 chars in list view since it can be very long.
- JSON/CSV/YAML/Markdown formatters unchanged — they already serialize the full `KEVEntry` struct.

## Testing Commands

```bash
go build ./...
go run . enrich CVE-2021-44228          # Should show Name, Description in KEV Details
go run . kev list                       # Should show Name column
go run . kev recent                     # Should show Name column
```
