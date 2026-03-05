---
name: Deprecate Enrich Command
description: Make enrichment the default behavior on cve get, add --fast flag, move all enrich flags to cve get, and remove the standalone enrich command.
date: 2026-03-05
status: completed
---

# Deprecate Enrich Command

## Description

The standalone `enrich` command duplicates `cve get` with the only difference being that `enrich` calls the multi-source enricher while `cve get` only hits NVD. Since enrichment is the core value proposition of vulnex, it should be the default behavior of `cve get`, not a separate command.

This feature:
1. Makes `cve get` call the enricher by default (NVD + EPSS + KEV + GHSA + OSV).
2. Adds a `--fast` flag to `cve get` to skip enrichment and only hit NVD (the current behavior).
3. Moves `--stdin`, `--scoring-profile`, and custom weight flags from `enrich` to `cve get` (they already exist on `cve get`).
4. Removes the standalone `enrich` command entirely.

## User Stories

- As a user, I want `cve get` to return enriched data by default so I don't need to remember a separate command.
- As a user, I want a `--fast` flag when I only need basic NVD data without waiting for all sources.
- As a user, I want `cat cves.txt | vulnex cve get --stdin` to replace the old `vulnex enrich --stdin` pipeline.

## Acceptance Criteria

- [ ] `vulnex cve get CVE-2024-3094` calls the enricher (all 5 sources) and shows full enriched output.
- [ ] `vulnex cve get CVE-2024-3094 --fast` calls only NVD (current behavior).
- [ ] `vulnex cve get --stdin` reads CVE IDs from stdin, enriches them, and outputs the batch.
- [ ] `vulnex cve get --fast --stdin` reads CVE IDs from stdin and fetches only NVD data.
- [ ] `--scoring-profile`, `--cvss-weight`, `--epss-weight`, `--kev-weight` continue to work on `cve get`.
- [ ] The standalone `enrich` command is removed (file deleted).
- [ ] `go build ./...` passes.
- [ ] Long description and examples on `cve get` are updated.

## Implementation Details

### Files modified

- `cmd/cve_get.go` — Change `RunE` to call `app.Enricher.Enrich` / `EnrichBatch` by default; when `--fast` is set, fall back to `app.NVD.GetCVE`. Update `Long` description and `Example` strings. Add `--fast` flag in `init()`.
- `cmd/enrich.go` — Delete this file.

### cve get RunE logic

```
fast := cmd.Flags().GetBool("fast")

if fast {
    // Current NVD-only path
} else {
    // Enricher path (current enrich command logic)
}
```

For batch (multiple IDs or --stdin), use `app.Enricher.EnrichBatch` when not fast, or loop `app.NVD.GetCVE` when fast.

## Priority

**High** — Simplifies the CLI surface and makes enrichment discoverable by default.

## Dependencies

- `internal/enricher/enricher.go` — Enricher with `Enrich` and `EnrichBatch` methods.
- `cmd/root.go` — AppContext with `Enricher` and `NVD` fields.

## Testing Commands

```bash
go build ./...
go run . cve get CVE-2024-3094
go run . cve get CVE-2024-3094 --fast
echo "CVE-2024-3094" | go run . cve get --stdin
go run . cve get CVE-2024-3094 --scoring-profile exploit-focused
```

## Documentation

- Website `cve.astro` docs page should be updated to reflect that `cve get` now enriches by default and document the `--fast` flag.
- Remove any references to the `enrich` command from docs.
