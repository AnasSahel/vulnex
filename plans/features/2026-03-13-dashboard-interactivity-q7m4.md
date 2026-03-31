---
name: Dashboard Interactivity
description: Add client-side interactivity to the dashboard — sorting, filtering, search, and loading states.
date: 2026-03-13
status: completed
---

# Dashboard Interactivity

## Description

The dashboard currently renders static mock data with no user interaction. This feature adds sorting, filtering, search, and proper loading/empty states.

### Current problems

1. CVE table columns are not sortable.
2. Quick actions search bar does nothing.
3. No loading states — pages render instantly with mock data but will need loading when connected to real APIs.
4. No empty states for when there's no data.

### Target design

**CVE table sorting:**
- Clickable column headers (CVSS, EPSS, Priority)
- Sort indicator (arrow) on active column
- Client-side sorting of current data

**Search & filtering:**
- Quick actions search bar filters the CVE table by CVE ID or description
- Alerts feed filterable by type and severity
- URL search params for shareable filter state

**Loading states:**
- Skeleton components matching each section's layout
- Used during data fetching (future API integration)

**Empty states:**
- Friendly messaging when no CVEs match a filter
- "Add your first CVE" CTA on empty watchlist

## User Stories

1. As a user, I want to sort my CVE table so I can prioritize by CVSS or EPSS score.
2. As a user, I want to search CVEs so I can quickly find specific vulnerabilities.

## Acceptance Criteria

- [x] CVE table is sortable by CVSS, EPSS, and Priority columns
- [x] Quick actions search filters the CVE table in real-time
- [x] Loading skeletons exist for all dashboard sections
- [x] Empty states render when no data matches filters
- [x] `bun run build` completes without errors

## Priority

**Medium** — Improves usability, prepares for real data integration.

## Dependencies

- `2026-03-13-shadcn-refactor-p4r7` (completed)

## Implementation Notes

- Install Shadcn `skeleton` component if not already installed
- Add `useState` for sort state in CVE table (client component)
- Wire quick-actions search input to filter logic
- Create `src/components/dashboard/empty-state.tsx`
- Create `src/components/dashboard/loading-skeletons.tsx`

## Documentation Updates

No changes needed — internal feature.
