---
name: Dashboard Data Integration
description: Replace mock data imports with real database queries across all dashboard pages using server components and Drizzle.
date: 2026-03-13
status: completed
---

# Dashboard Data Integration

## Description

Replace all mock data imports (`@/lib/mock-data`) with real database queries. Dashboard pages become server components (where possible) that query the shared Drizzle schema.

### Current problems

1. All dashboard pages import from `@/lib/mock-data.ts` — hardcoded arrays.
2. Risk stats are static strings, not computed from real data.
3. EPSS chart shows fake trend data.
4. Alerts feed shows hardcoded events.

### Target design

**Data access pattern:**
- Server components query the DB directly via Drizzle
- Client components receive data as props (from server component parents)
- Pages that need client interactivity (search, sort) use a hybrid: server component fetches data, passes to client component

**Page-by-page changes:**

1. **Dashboard overview (`/dashboard`)**
   - Risk stats: computed from `cve` + `cve_score` + `kev_entry` tables (count, averages)
   - Alerts feed: generated from recent `sync_log` events + new entries across tables
   - CVE table: query `cve` JOIN `cve_score` JOIN `kev_entry`, ordered by last modified
   - EPSS chart: query `cve_score` history (or latest scores for top CVEs)

2. **Watchlist (`/dashboard/watchlist`)**
   - Query `watchlist` JOIN `cve` JOIN `cve_score` for the current user
   - "Add CVE" button → search NVD and add to watchlist

3. **Exploits (`/dashboard/exploits`)**
   - Query `exploit` table, joined with `cve` for severity data
   - Filter by severity level

4. **SBOM (`/dashboard/sbom`)**
   - Keep mock data for now — SBOM parsing is a separate feature
   - Mark as "coming soon" or keep the upload UI as a placeholder

5. **Settings (`/dashboard/settings`)**
   - No data changes needed — already uses auth session

**Delete `app/src/lib/mock-data.ts`** once all pages are migrated.

## User Stories

1. As a user, I want to see real vulnerability data in my dashboard.
2. As a user, I want my watchlist to persist across sessions.

## Acceptance Criteria

- [x] Dashboard overview shows real data from the database
- [x] Risk stats are computed from actual CVE/score/KEV data
- [x] CVE table displays real CVEs with real CVSS/EPSS scores
- [x] Watchlist page shows user-specific watched CVEs
- [x] Exploits page shows real exploit records
- [x] Empty states render correctly when the database has no data
- [x] `mock-data.ts` is deleted
- [x] `bun run build` succeeds

## Priority

**High** — This is the user-visible payoff of all sync work.

## Dependencies

- `2026-03-13-shared-db-package-a2k7` (shared schema)
- `2026-03-13-sync-nvd-c8p2` (CVE data in DB)
- `2026-03-13-sync-epss-d3n7` (EPSS scores in DB)
- At least one sync must have run to populate data

## Implementation Notes

- Convert dashboard page to a server component that fetches data, passes to client child for interactivity
- Use `db.select().from(cve).leftJoin(cveScore, ...).leftJoin(kevEntry, ...)` for rich queries
- Compute risk stats server-side: `SELECT COUNT(*), AVG(epss_score), ...`
- For the alerts feed, derive alerts from recent changes: new KEV entries, EPSS spikes, new exploits
- Keep loading skeletons for client-side transitions (already implemented)
- SBOM page remains as-is (placeholder) — separate feature for real SBOM parsing

### Performance fix: N+1 query elimination (2026-03-13)

The initial implementation of `getDashboardCVEs()` had an N+1 query problem: for each of 50 CVEs, it ran 3 separate queries (CVSS score, EPSS score, KEV status check) = 151 sequential round-trips to Neon. With ~50ms latency per query, the dashboard took ~7.5s to load.

**Queries rewritten:**
- `getDashboardCVEs`: 151 queries → 1 query using `LEFT JOIN LATERAL` subqueries for CVSS, EPSS, and an `EXISTS` subquery for KEV
- `getEpssTrends`: 3 queries in a loop → 1 query with `IN` clause
- `getUserWatchlist`: called `getDashboardCVEs(500)` + JS filter (1,501 queries) → 1 query joining `watchlist` → `cve` with lateral subqueries

**Indexes added to `packages/db/src/schema.ts`:**
- `cve_last_modified_idx` on `cve(last_modified)` — ORDER BY in main dashboard query
- `cve_score_lookup_idx` on `cve_score(cve_id, source, scored_at)` — composite index for lateral joins
- `kev_entry_cve_id_idx` on `kev_entry(cve_id)` — EXISTS subquery for KEV check

## Documentation Updates

No changes needed — internal refactor.
