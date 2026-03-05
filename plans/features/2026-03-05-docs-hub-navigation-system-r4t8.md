---
name: Docs Hub and Navigation System
description: Build a first-class docs home, persistent navigation patterns, and cross-linking rules to remove documentation dead-ends.
date: 2026-03-05
status: completed
---

# Docs Hub and Navigation System

## Description

Discoverability breaks when users can only reach docs via scattered links. This feature creates a docs hub and consistent navigation primitives so users can browse by task and command without guessing URLs.

## User Stories

- As a user, I want a docs homepage with clear entry cards so I can choose a path quickly.
- As a keyboard user, I want predictable navigation (sidebar, breadcrumbs, prev/next).
- As a returning user, I want related links on each page to continue my workflow.

## Acceptance Criteria

- [x] `/docs/` exists and is linked from top navbar.
- [x] All docs pages render sidebar + breadcrumbs.
- [x] Every docs page has prev/next or related links.
- [x] No docs page is more than 3 clicks from `/docs/`.
- [x] Mobile docs nav is usable and collapsible.

## Priority

**High**

## Dependencies

- `website/src/layouts/DocsLayout.astro`
- `website/src/components/Navbar.astro`
- `website/src/pages/docs/*.astro`

## Implementation Details

### Files created

- `website/src/content/docs-nav.ts` — Navigation data with `DocsSection`, `DocsPage`, `getPagerLinks()`.
- `website/src/pages/docs/index.astro` — Hub page with section cards and quick-start highlight.

### Files modified

- `website/src/layouts/DocsLayout.astro` — Added:
  - `slug` prop for page identification
  - Breadcrumbs nav (Docs > Section)
  - Prev/next pager at page bottom
  - "All docs" back link in sidebar
  - Mobile sidebar toggle button (floating FAB)
  - Responsive sidebar (fixed overlay on mobile)
- `website/src/components/Navbar.astro` — Single "Docs" link to `/docs/` hub.

### Components

- Breadcrumbs are inline in DocsLayout (no separate component needed for current scope).
- Prev/next pager is inline in DocsLayout, driven by `docs-nav.ts` page ordering.
- Mobile sidebar toggle is a fixed-position button that toggles `.open` class.

## Testing Checklist

```bash
cd website && npm run build
# Desktop: verify sidebar, breadcrumbs, and pager on all docs pages
# Mobile (resize to < 900px): verify sidebar toggle button works
# Verify /docs/ hub links to all section pages
# Verify prev/next links navigate in correct order
```
