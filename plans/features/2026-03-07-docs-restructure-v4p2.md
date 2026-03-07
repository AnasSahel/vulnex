---
name: Docs Restructure
description: Revamp docs home page with introduction and architecture diagram, simplify left sidebar to commands only (no subcommands), and add right-side TOC sidebar for subcommands on each command page.
date: 2026-03-07
status: completed
---

# Docs Restructure

## Description

Three changes to the documentation layout and content:

1. **Docs home page overhaul** — Replace the current hub page with a proper introduction explaining what vulnex is, the pain points it solves, and an architecture diagram (Excalidraw export as PNG) showing the data flow from 5 sources through vulnex to various outputs.

2. **Left sidebar simplification** — In the Commands section, show only the top-level command names (cve, kev, epss, etc.) without expanding subcommands. The subcommands currently shown as a nested list under each active command will be removed from the left sidebar.

3. **Command page layout** — Each command page gets:
   - An intro paragraph explaining the command, its purpose, and pain points it solves
   - A horizontal separator (`<hr>`)
   - Subcommand sections below the separator
   - A new **right sidebar** (table of contents) listing the subcommands for quick navigation within the page

## User Stories

1. As a new user, I want the docs home page to quickly explain what vulnex does and how it works so I can decide if it's relevant to me.
2. As a user browsing docs, I want a clean left sidebar with just command names so I can quickly find the right page without visual noise.
3. As a user reading a command page, I want a right-side TOC showing subcommands so I can jump to the one I need without scrolling.

## Acceptance Criteria

### Docs Home Page
- [x] Add an introduction section explaining vulnex's purpose and the pain points it solves (fragmented vuln data, no unified CLI, manual triage, etc.)
- [x] Create an architecture diagram using Excalidraw showing: 5 data sources (NVD, KEV, EPSS, GHSA, OSV) flowing into vulnex, then outputting to table/JSON/CSV/SARIF/markdown/yaml
- [x] Export diagram as PNG and reference it in the docs home page
- [x] Keep the Quick Start card and section grid below the new introduction
- [x] Diagram should work in both light and dark themes (use transparent or themed background)

### Left Sidebar
- [x] Remove subcommand expansion from `DocsSidebar.astro`
- [x] Remove chevron icons from command links (no expand/collapse needed)
- [x] Keep the active highlight on the current page
- [x] Keep section labels (Getting Started, Commands)

### Command Page Layout (DocsLayout + individual pages)
- [x] Add a right sidebar (aside) to `DocsLayout.astro` that renders a "On this page" TOC
- [x] The right sidebar lists subcommand anchors for the current page (read from `docs-nav.ts` subcommands)
- [x] Right sidebar is sticky, scrolls with the page, hidden on mobile
- [x] Existing command pages already have intro + `<hr>` + subcommands structure (cve.astro, sbom.astro) — verify and ensure consistency across all command pages
- [x] Adjust `docs-content` max-width to accommodate the right sidebar

## Priority

**High** — Documentation structure directly affects onboarding and usability.

## Dependencies

- Excalidraw (for diagram creation and PNG export)
- No code dependencies; this is docs/layout work

## Implementation Notes

### Files to modify:
- `website/src/pages/docs/index.astro` — Rewrite with introduction, diagram, and pain points
- `website/src/components/DocsSidebar.astro` — Remove subcommand expansion and chevrons
- `website/src/layouts/DocsLayout.astro` — Add right sidebar for subcommand TOC
- `website/src/content/docs-nav.ts` — May need to expose subcommands to the layout for TOC rendering

### Files to create:
- `website/public/images/vulnex-architecture.png` — Excalidraw diagram export

### Pages to verify (intro + hr + subcommands pattern):
- `website/src/pages/docs/cve.astro` — already has this pattern
- `website/src/pages/docs/kev.astro`
- `website/src/pages/docs/epss.astro`
- `website/src/pages/docs/advisory.astro`
- `website/src/pages/docs/exploit.astro`
- `website/src/pages/docs/sbom.astro`
- `website/src/pages/docs/prioritize.astro` — no subcommands, no right TOC
- `website/src/pages/docs/scoring.astro` — no subcommands, no right TOC

## Testing

```bash
# Build the website
cd website && npx astro build

# Dev server
cd website && npx astro dev

# Verify:
# 1. Docs home: introduction text, architecture diagram visible
# 2. Docs home: diagram renders correctly in both light/dark themes
# 3. Left sidebar: only command names shown, no subcommands nested
# 4. Left sidebar: no chevron arrows on command links
# 5. Command page (e.g., /docs/cve/): right sidebar shows subcommand TOC
# 6. Right sidebar: clicking a subcommand scrolls to it
# 7. Right sidebar: sticky positioning works on scroll
# 8. Right sidebar: hidden on mobile (<900px)
# 9. Pages without subcommands (prioritize, scoring): no right sidebar
# 10. Getting started page: no right sidebar
```

## Documentation Updates

- The docs home page IS the documentation update — it's the primary deliverable
- README.md does not need updates — no functional changes
