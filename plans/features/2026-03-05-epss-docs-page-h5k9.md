---
name: EPSS Documentation Page
description: Add a comprehensive docs page for the EPSS commands (score, top, trend) to the website, matching the style and structure of the existing CVE and Scoring docs pages.
date: 2026-03-05
status: completed
---

# EPSS Documentation Page

## Description

The website currently has docs pages for CVE commands and Scoring, but no dedicated page for the EPSS commands (`epss score`, `epss top`, `epss trend`). Users looking to understand EPSS score lookups, top exploited CVEs, and historical trend analysis have no web documentation to reference.

## User Stories

- As a user, I want a dedicated EPSS docs page so I can learn how to query exploitation probability scores.
- As a user, I want terminal examples for each EPSS subcommand so I can copy working commands.
- As a user, I want to understand the `--days` flag on `epss trend` to filter historical data.

## Acceptance Criteria

- [x] `/docs/epss/` page exists with full documentation for all three EPSS subcommands.
- [x] Page uses DocsLayout with sidebar, breadcrumbs, and prev/next pager.
- [x] Terminal window examples for `epss score`, `epss top`, and `epss trend`.
- [x] Flag reference tables for each subcommand.
- [x] Page is linked from the docs hub and docs-nav.ts.
- [x] `astro build` succeeds.

## Priority

**Medium**

## Dependencies

- `website/src/layouts/DocsLayout.astro`
- `website/src/content/docs-nav.ts`
- `website/src/pages/docs/index.astro`

## Documentation

- New page: `website/src/pages/docs/epss.astro`
- Updated: `website/src/content/docs-nav.ts` to include EPSS page in Commands section
- No README changes needed (EPSS commands already documented in README)
