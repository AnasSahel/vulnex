---
name: Docs Command Page Readability
description: Improve readability of command reference pages with tabbed terminals, stronger section headers, scroll-spy TOC, compact jump links, better table padding, and back-to-top button.
date: 2026-03-07
status: completed
---

# Docs Command Page Readability

## Description

The command reference pages (cve, kev, epss, advisory, exploit, sbom) are dense and hard to scan. This feature improves readability through six changes:

1. **Tabbed terminals** — Group multiple examples per subcommand into a single TabbedPanel instead of stacking 2-4 separate terminal windows
2. **Stronger subcommand headers** — Give each subcommand section a distinct visual anchor with a monospace badge-style header
3. **Scroll-spy on right TOC** — Highlight the active subcommand in the "On this page" sidebar as the user scrolls
4. **Compact jump links** — Replace the subcommand card grid at the top with inline pill-style jump links
5. **Better table padding** — Increase cell padding in flags tables for scannability
6. **Back to top link** — Add a "Top" link in the right TOC sidebar

## User Stories

1. As a developer reading the cve docs, I want to quickly find the example I need without scrolling through 9 terminal blocks.
2. As a user scanning the page, I want clear visual boundaries between subcommands so I know where one ends and the next begins.
3. As a user navigating a long page, I want the right sidebar to show me where I am and let me jump back to the top.

## Acceptance Criteria

### Tabbed Terminals
- [x] Group examples within each subcommand into a single TabbedPanel
- [x] Tab labels should be short descriptors (e.g., "enriched lookup", "NVD only", "JSON output")
- [x] Apply to all command pages that have multiple terminal examples per subcommand
- [x] Start with the cve.astro page as the reference implementation

### Stronger Subcommand Headers
- [x] Each subcommand h2 gets a monospace styled treatment with a tinted background strip
- [x] Add styling in the shared command page styles (cve.astro styles serve as the template)
- [x] Clear visual separation from the previous section

### Scroll-spy TOC
- [x] Add IntersectionObserver in DocsLayout.astro that watches subcommand section headings
- [x] Highlight the active link in the right TOC sidebar with accent color and left border
- [x] Smooth transition between active states

### Compact Jump Links
- [x] Replace `.subcommand-grid` card layout with inline pill/chip links
- [x] Horizontal flow, wrapping on mobile
- [x] Smaller footprint than the current card grid

### Better Table Padding
- [x] Increase td/th padding from 10px 14px to 12px 16px
- [x] Flag name (first column code) gets a subtle monospace background treatment

### Back to Top
- [x] Add a "Top" link at the top of the right TOC sidebar that scrolls to page top
- [x] Or add it as the first item in the TOC list (implemented as "Overview" link pointing to #overview)

## Priority

**Medium** — Improves existing page usability without adding new content.

## Dependencies

- Existing TabbedPanel component
- Existing DocsLayout right TOC sidebar

## Implementation Notes

### Files to modify:
- `website/src/pages/docs/cve.astro` — Tabbed terminals, compact jump links, subcommand header styles (reference implementation)
- `website/src/pages/docs/kev.astro` — Same pattern
- `website/src/pages/docs/epss.astro` — Same pattern
- `website/src/pages/docs/advisory.astro` — Same pattern
- `website/src/pages/docs/exploit.astro` — Same pattern
- `website/src/pages/docs/sbom.astro` — Same pattern
- `website/src/layouts/DocsLayout.astro` — Scroll-spy script, back-to-top link, TOC active styles

## Testing

```bash
# Build the website
cd website && npx astro build

# Dev server
cd website && npx astro dev

# Verify:
# 1. Command pages (cve, kev, epss, advisory, exploit, sbom): pill jump links at top instead of card grid
# 2. Subcommand h2 headers have monospace badge styling with tinted background
# 3. Multiple terminal examples per subcommand are grouped in TabbedPanel tabs
# 4. Tab switching works correctly on each command page
# 5. Table padding is visually larger (12px 16px) with tinted code cells
# 6. Right TOC scroll-spy highlights active section on scroll
# 7. "Overview" link in right TOC scrolls to page top
# 8. All pages render correctly on mobile (<900px) — TOC hidden, pills wrap
```

## Documentation Updates

- No separate docs updates needed — this IS the docs improvement
- README.md does not need updates
