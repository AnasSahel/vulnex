---
name: Temporal Snapshots
description: Store daily enrichment snapshots in SQLite so vulnex can track how vulnerability intelligence changes over time.
date: 2026-03-09
status: completed
---

# Temporal Snapshots

## Description

Today, vulnex's cache is a short-lived lookup cache — entries expire and get replaced. There's no persistent record of what a CVE's risk profile looked like yesterday, last week, or last month. This means vulnex can't answer temporal questions like "which of my watched CVEs got worse?" or "when did this CVE get added to KEV?"

This feature adds a `snapshots` table to the SQLite cache that stores timestamped enrichment snapshots. Each snapshot captures the key risk signals (CVSS, EPSS, KEV status, exploit availability) at a point in time for a given CVE. This is the foundation for watch diff (feature 2) and correlation (feature 3).

### Current problems

1. Cache entries are overwritten on refresh — no history preserved
2. `cve watch --refresh` shows current state but can't compare to previous state
3. `epss trend` fetches history from the FIRST.org API — not available for other signals (KEV, exploits, GHSA)
4. No way to detect meaningful changes (EPSS spike, KEV addition) without manual tracking

### Target design

A new `snapshots` SQLite table stores one row per CVE per day:

```sql
CREATE TABLE IF NOT EXISTS snapshots (
    cve_id     TEXT    NOT NULL,
    date       TEXT    NOT NULL,  -- YYYY-MM-DD
    cvss       REAL,
    epss       REAL,
    epss_pctl  REAL,
    in_kev     INTEGER NOT NULL DEFAULT 0,
    exploits   INTEGER NOT NULL DEFAULT 0,  -- count of known exploits
    priority   TEXT,    -- P0-P4
    score      REAL,    -- weighted composite score
    data       TEXT,    -- full JSON blob for detailed diff
    PRIMARY KEY (cve_id, date)
);
CREATE INDEX idx_snapshots_date ON snapshots(date);
```

Snapshots are recorded automatically during:
- `cve watch --refresh` (all watched CVEs)
- `cve get` (individual CVE lookups)
- `sbom check` / `prioritize` (all CVEs in the scan)

One snapshot per CVE per day (upsert on `cve_id + date`). This keeps storage bounded — even 1000 CVEs tracked for a year is ~365K rows, well within SQLite's comfort zone.

## User Stories

1. As a security engineer, I want vulnex to remember what my CVEs looked like last week so I can see what changed.
2. As a developer running `sbom check` in CI, I want each run to build up a history so I can review trends.
3. As a vulnex user, I want snapshots to happen automatically without extra commands.

## Acceptance Criteria

- [x] New `snapshots` table created via auto-migration on cache open
- [x] `Cache` interface extended with `SaveSnapshot`, `SaveSnapshots`, `GetSnapshots`, `GetLatestSnapshot`
- [x] Snapshot model type in `internal/model/snapshot.go` with CVSS, EPSS, KEV, exploit count, priority, score, and raw JSON
- [x] `cve get` saves a snapshot after enrichment
- [x] `cve watch --refresh` saves snapshots for all refreshed CVEs
- [x] `sbom check` saves snapshots for all found CVEs (via `enrichFindings`)
- [x] `prioritize` saves snapshots for all processed CVEs (via `enrichFindings`)
- [x] Snapshots are upserted (one per CVE per day, latest wins)
- [x] `make test` passes with 5 snapshot tests (save/retrieve, batch, upsert, migration v2, v1→v2 migration)
- [x] Snapshot storage doesn't slow down normal operations (failures logged, never returned)

## Test Commands

```bash
# Verify snapshot is saved after enriched lookup
vulnex cve get CVE-2021-44228
vulnex cache stats  # Should show Snapshots: 1

# Verify batch snapshots via watch
vulnex cve watch CVE-2021-44228 CVE-2024-3094
vulnex cve watch --refresh
vulnex cache stats  # Snapshots should increase

# Run tests
go test -race -count=1 ./internal/cache/
```

## Priority

**High** — This is the foundation for the entire Threat Intelligence Layer. Watch diff and correlation both depend on it.

## Dependencies

None — builds on existing SQLite cache infrastructure.

## Implementation Notes

- Extend `internal/cache/cache.go` interface with snapshot methods
- Implement in `internal/cache/sqlite.go` — add migration in the `migrate()` function
- Create `internal/model/snapshot.go` for the `Snapshot` struct
- Snapshot saving should be non-blocking — use a goroutine or batch at the end of the command. A failed snapshot write should never break the main command.
- The `data` JSON blob stores the full `EnrichedCVE` so future features can diff any field, not just the numeric signals.
- Consider a `--no-snapshot` flag on root for users who want to opt out.

## Documentation Updates

- **Website docs**: No new page needed yet — document in the existing command pages when watch diff ships (feature 2)
- **README.md**: No changes until user-facing commands use snapshots
