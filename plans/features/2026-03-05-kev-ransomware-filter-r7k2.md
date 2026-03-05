---
name: KEV Ransomware Filter
description: Add a --ransomware flag to kev list and kev recent to filter entries where ransomware campaign is "Known".
date: 2026-03-05
status: completed
---

# KEV Ransomware Filter

## Description

The `kev list` and `kev recent` commands show all KEV entries. Users interested in ransomware-associated vulnerabilities need a quick way to filter the list to only entries where `KnownRansomwareCampaign` is "Known". A `--ransomware` boolean flag will filter entries before pagination and display.

## User Stories

- As a security analyst, I want to run `kev list --ransomware` to see only KEV entries linked to known ransomware campaigns.
- As a user running `kev recent --ransomware`, I want to see only recently added entries with known ransomware associations.

## Acceptance Criteria

- [x] `kev list --ransomware` filters to entries where `KnownRansomwareCampaign` is "Known".
- [x] `kev recent --ransomware` applies the same filter.
- [x] The filter is applied before `--limit`/`--offset` pagination.
- [x] The "Showing N of M entries" message reflects filtered totals.
- [x] Structured output formats (json, csv) also respect the filter.
- [x] `go build ./...` passes.

## Implementation Details

### Files modified

- `cmd/kev_list.go` — Added `--ransomware` flag to both `kevListCmd` and `kevRecentCmd`. Added `filterRansomware()` helper that filters entries where `KnownRansomwareCampaign` is "Known" (case-insensitive). Filter is applied before pagination in `kev list` and before output in `kev recent`.

## Testing Commands

```bash
go build ./...
go run . kev list --ransomware              # only ransomware-linked entries
go run . kev list --ransomware --limit 10   # with pagination
go run . kev recent --ransomware            # recent + ransomware filter
```

## Priority

**Low**

## Dependencies

- `cmd/kev_list.go` — kev list and kev recent commands
- `internal/model/kev.go` — `KEVEntry.KnownRansomwareCampaign` field

## Documentation

- No README changes needed — flag is self-documenting via `--help`.
- No website changes needed.
