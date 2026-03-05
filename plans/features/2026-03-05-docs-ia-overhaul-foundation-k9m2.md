---
name: Docs IA Overhaul Foundation (Landing Preserved)
description: Redesign documentation information architecture into a scalable docs hub and taxonomy while preserving the existing high-conversion landing page experience.
date: 2026-03-05
status: completed
---

# Docs IA Overhaul Foundation (Landing Preserved)

## Description

The current docs are useful but hard to discover because users hit deep pages directly (`/docs/cve/`, `/docs/scoring/`) without a clear docs home, content taxonomy, or progression path.

This feature defines a durable information architecture that improves findability while preserving the existing landing page style, messaging, and conversion flow.

### Non-negotiable constraint

- Keep the landing page engaging and visually distinctive.
- Do not replace the hero, feature storytelling, or terminal demo structure.
- Scope changes primarily to docs architecture and entry points.

## User Stories

- As a first-time visitor, I want a clear docs home so I know where to start in under 10 seconds.
- As a practitioner, I want command docs grouped logically so I can jump to relevant tasks quickly.
- As a maintainer, I want a stable IA so adding new docs does not degrade navigation quality.

## Proposed IA

1. `Getting Started`
- install
- first query
- output formats
- common workflows

2. `Commands`
- cve commands

3. `Scoring & Policy`
- scoring model
- profiles and custom weights
- risk priority tiers

## Acceptance Criteria

- [x] IA map documented and reflected in docs navigation.
- [x] Every docs page belongs to one IA section.
- [x] No orphan docs pages (each has at least one inbound docs-nav link).
- [x] Landing page visual identity and core section order remain intact.
- [x] Existing deep links continue to resolve.

## Priority

**High**

## Dependencies

- `website/src/layouts/DocsLayout.astro`
- `website/src/pages/docs/*`
- `website/src/components/Navbar.astro`

## Implementation Details

### Files created

- `website/src/content/docs-nav.ts` — Single source of truth for docs IA: sections, pages, slugs, and prev/next pager logic.
- `website/src/pages/docs/index.astro` — Docs hub page with section cards.
- `website/src/pages/docs/getting-started.astro` — Getting Started guide with install, first query, enrich, output formats, and lockfile scanning sections.

### Files modified

- `website/src/pages/docs/cve.astro` — Added `slug="cve"` prop for breadcrumbs and pager.
- `website/src/pages/docs/scoring.astro` — Added `slug="scoring"` prop for breadcrumbs and pager.
- `website/src/layouts/DocsLayout.astro` — Added breadcrumbs, prev/next pager, mobile sidebar toggle, and "All docs" back link.
- `website/src/components/Navbar.astro` — Consolidated "Docs" + "Scoring" links into single "Docs" link to `/docs/`.

### Guardrails

- Landing page sections remain: hero, features, demos, sources, install, CI/CD.
- Landing changes limited to docs discoverability entry points (CTA/link microcopy).

## Testing Checklist

```bash
cd website && npm run build
# Verify /docs/ renders and links to all IA sections
# Verify /docs/getting-started/ renders with install, first query, enriching, output formats, scanning
# Verify /docs/cve/ and /docs/scoring/ still work with breadcrumbs and pager
# Verify landing page still contains existing conversion CTAs
```
