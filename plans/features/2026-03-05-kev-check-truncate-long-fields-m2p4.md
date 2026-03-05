---
name: Truncate Long Fields in KEV Check Output
description: Truncate Description, Required Action, and Notes fields in `kev check` table output unless --long flag is specified.
date: 2026-03-05
status: completed
---

# Truncate Long Fields in KEV Check Output

## Description

The `kev check` command now displays KEV entries in a label-value row format. However, the Description, Required Action, and Notes fields can be very long, causing awkward line wrapping in the terminal. These fields should be truncated by default and only shown in full when `--long` is specified.

## User Stories

- As a user, I want `kev check` output to be compact by default so I can scan entries quickly.
- As a user, I want `kev check --long` to show full field content when I need the complete details.

## Acceptance Criteria

- [x] Description truncated to ~80 characters by default in `kev check` table output.
- [x] Required Action truncated to ~80 characters by default.
- [x] Notes truncated to ~80 characters by default.
- [x] `--long` / `-l` flag shows full content for all three fields.
- [x] `go build ./...` passes.

## Testing Commands

```bash
go build ./...
go run . kev check CVE-2021-44228        # truncated output
go run . kev check CVE-2021-44228 -l     # full output
```

## Priority

**Low**

## Dependencies

- `cmd/kev_check.go` — Row-based KEV check output
- Global `--long` flag already exists on root command

## Documentation

- No README or website changes needed.
