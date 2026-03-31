---
name: Dashboard Sub-Pages
description: Build the Watchlist, SBOM Scans, Exploits, and Settings pages linked from the sidebar.
date: 2026-03-13
status: completed
---

# Dashboard Sub-Pages

## Description

The sidebar has links to Watchlist, SBOM Scans, Exploits, and Settings, but they all 404. This feature creates those pages with appropriate layouts and mock data.

### Current problems

1. Sidebar links to `/dashboard/watchlist`, `/dashboard/sbom`, `/dashboard/exploits`, `/dashboard/settings` lead to 404s.
2. No page structure exists for these routes.

### Target design

**Watchlist** (`/dashboard/watchlist`):
- Full-page version of the CVE table from the overview
- Add/remove CVEs, search/filter, bulk actions (UI only for now)
- Uses existing `SectionHeader` component

**SBOM Scans** (`/dashboard/sbom`):
- Upload area (drag & drop zone)
- List of past scans with status, date, vulnerability count
- Click a scan to see its results (mock)

**Exploits** (`/dashboard/exploits`):
- Feed of exploit intelligence events
- Filterable by severity, source, date range
- Expanded version of the alerts feed

**Settings** (`/dashboard/settings`):
- Profile section (name, email — read from auth session)
- Notification preferences (toggles)
- API key management (placeholder)
- Danger zone (delete account — UI only)

## User Stories

1. As a user, I want dedicated pages for each feature so I can manage my vulnerability data in detail.

## Acceptance Criteria

- [x] All 4 routes render without 404
- [x] Each page uses the dashboard layout (sidebar + header)
- [x] Pages use Shadcn components and reusable dashboard primitives
- [x] Settings page shows authenticated user info from session
- [x] `bun run build` completes without errors

## Priority

**Medium** — Fleshes out the product but not blocking other work.

## Dependencies

- `2026-03-13-auth-integration-k8v3` (for settings page user info)

## Implementation Notes

- Create `src/app/dashboard/watchlist/page.tsx`
- Create `src/app/dashboard/sbom/page.tsx`
- Create `src/app/dashboard/exploits/page.tsx`
- Create `src/app/dashboard/settings/page.tsx`
- Add mock data as needed to `src/lib/mock-data.ts`
- Reuse `SectionHeader`, `SeverityBadge`, `IconBox` components

## Documentation Updates

No changes needed — internal feature.
