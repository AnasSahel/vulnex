---
name: Landing-to-Docs Discoverability Enhancements
description: Improve documentation findability from the landing page with minimal UI disruption and preserved storytelling.
date: 2026-03-05
status: completed
---

# Landing-to-Docs Discoverability Enhancements

## Description

The landing page is engaging, but documentation entry is currently secondary and easy to miss. This feature adds high-signal docs entry points without diluting the visual narrative.

## User Stories

- As a new visitor, I want a clear "Read Docs" action near the hero so I can learn usage fast.
- As a technical evaluator, I want direct links to quickstart and command reference from key sections.
- As a maintainer, I want docs discoverability improvements that do not flatten landing-page design.

## Acceptance Criteria

- [x] Hero includes visible `Read the docs` CTA linking to `/docs/`.
- [x] Existing conversion CTA(s) remain unchanged in priority.
- [x] At least one contextual docs link exists in each of: Features, Install, CI/CD.
- [x] Navbar includes a single canonical docs entry (`/docs/`).
- [x] Landing section layout and visual tone remain consistent with current design.

## Priority

**Medium**

## Dependencies

- `website/src/components/Hero.astro`
- `website/src/components/FeaturesSection.astro`
- `website/src/components/InstallSection.astro`
- `website/src/components/CiCdSection.astro`
- `website/src/components/Navbar.astro`

## Implementation Details

### Files modified

- `website/src/components/Hero.astro` — Replaced "See it in action" secondary CTA with "Read the docs" linking to `/docs/`.
- `website/src/components/FeaturesSection.astro` — Added "Explore command reference" link below section description.
- `website/src/components/InstallSection.astro` — Added "Post-install quickstart" link below section description.
- `website/src/components/CiCdSection.astro` — Added "Full pipeline docs" link below section description.
- `website/src/components/Footer.astro` — Added "Docs" link as first footer link.
- `website/src/components/Navbar.astro` — Consolidated to single "Docs" entry linking to `/docs/`.

### Design approach

- Used `.section-link` class with accent color and arrow character for contextual links.
- Links are positioned below section descriptions, before the main section content.
- Minimal visual impact — no structural changes to existing sections.

## Testing Checklist

```bash
cd website && npm run build
# Verify Hero has "Read the docs" CTA
# Verify Features section has "Explore command reference" link
# Verify Install section has "Post-install quickstart" link
# Verify CI/CD section has "Full pipeline docs" link
# Verify Footer has "Docs" link
# Verify Navbar has single "Docs" link to /docs/
```
