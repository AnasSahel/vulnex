---
name: Sync Control UI
description: Add a "Sync Now" button and sync status display to the dashboard header, triggering Motia workers via HTTP.
date: 2026-03-13
status: completed
---

# Sync Control UI

## Description

Add UI controls to the dashboard that let users trigger data syncs on demand and see the last sync status per data source.

### Current problems

1. No way for users to trigger a data refresh.
2. No visibility into when data was last updated.
3. Users don't know if sync is running or has failed.

### Target design

**Dashboard header additions:**
- "Sync Now" button in the top-right area of the dashboard
- Clicking it sends POST to Motia's HTTP endpoint (`/api/sync`)
- Button shows a spinner while sync is in progress
- Toast notification on completion (success/error)

**Sync status panel:**
- Small status indicator next to the Sync button showing "Last synced: 2h ago"
- Expandable dropdown showing per-source sync status:
  ```
  NVD        ✓ 2h ago    (1,247 CVEs)
  EPSS       ✓ 2h ago    (1,247 scores)
  KEV        ✓ 6h ago    (1,134 entries)
  GHSA       ✓ 2h ago    (892 advisories)
  Exploits   ✗ Failed    (rate limited)
  ```
- Data comes from the `sync_log` table

**API route:**
- `app/src/app/api/sync/route.ts` — POST handler that proxies to Motia's HTTP API
- Returns sync status from `sync_log` table on GET

## User Stories

1. As a user, I want to manually refresh vulnerability data when I need the latest information.
2. As a user, I want to know when data was last updated and if any sync failed.

## Acceptance Criteria

- [x] "Sync Now" button exists in the dashboard header/layout
- [x] Clicking it triggers a POST to the sync API
- [x] Button shows loading state during sync
- [x] Toast notification on sync completion
- [x] Sync status displays last sync time per source
- [x] Failed syncs show error indication
- [x] GET `/api/sync` returns current sync status from `sync_log`
- [x] `bun run build` succeeds

## Priority

**Medium** — Important for user experience but not blocking data display.

## Dependencies

- `2026-03-13-motia-scaffold-b5m3` (Motia HTTP endpoint)
- `2026-03-13-shared-db-package-a2k7` (sync_log table)
- At least one sync worker implemented

## Implementation Notes

- The Next.js API route acts as a proxy — forwards the request to Motia's local HTTP endpoint
- Use `sonner` (already in Shadcn) for toast notifications
- Sync status component reads from `sync_log` table via a server component or API route
- Consider polling the sync status every 10s while a sync is in progress
- The Motia HTTP endpoint URL should be configurable via env var (`MOTIA_API_URL`)
- Add the sync button to the existing dashboard layout sidebar or header area

## Documentation Updates

No changes needed — internal UI feature.
