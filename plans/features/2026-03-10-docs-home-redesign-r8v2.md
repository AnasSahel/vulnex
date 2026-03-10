---
name: Docs Home Redesign
description: Redesign the docs index page from a text-heavy essay into a clean, scannable navigation hub.
date: 2026-03-10
status: completed
---

# Docs Home Redesign

## Description

The current docs home page reads like documentation itself — a long "What is vulnex?" essay, pain points list, and full architecture diagram — before the user ever reaches navigation links. This content already lives in the getting-started page, making the index redundant and slow to scan.

### Current problems

1. Text-heavy intro ("What is vulnex?", pain points) duplicates getting-started content
2. Architecture diagram takes a full viewport of space before any navigation
3. Section grid is buried below the fold — users must scroll past ~800px of prose to find links
4. "Documentation" badge + "vulnex docs" heading wastes vertical space with no information density
5. Quick Start card blends in rather than standing out as the primary action

### Target design

**Direction: Terminal-inspired navigation hub — everything scannable in 2 seconds.**

**Hero (minimal):**
- Title: `vulnex docs` in mono weight, no badge
- One-line description underneath
- Tight vertical spacing — 40px total

**Quick Start card (prominent):**
- Full-width card with terminal icon + "Quick Start" title + one-liner description + arrow
- Subtle terminal preview showing `brew install vulnex` or similar
- Red accent left border to draw the eye
- Links to getting-started page

**Command grid (flat):**
- Section label ("Getting Started" / "Commands") as a subtle uppercase header above each group
- Each page gets its own card: command name as mono-styled title + description
- Cards are a flat grid (not nested inside section wrapper cards)
- 2-column grid on desktop, 1-column on mobile
- Hover: left border accent + slight background shift

**What's removed from index:**
- "What is vulnex?" section (lives in getting-started)
- Pain points list (lives in getting-started)
- Architecture diagram (lives in getting-started)
- "Documentation" pill badge
- `<hr>` divider

## User Stories

1. As a developer landing on /docs/, I want to immediately see all available pages so I can navigate to the one I need.
2. As a new user, I want the Quick Start to be the most visible element so I know where to begin.

## Acceptance Criteria

- [ ] Hero: just title + one-line description, no badge, tight spacing
- [ ] Quick Start: prominent full-width card with red left border accent
- [ ] Flat page grid with section labels as subtle headers
- [ ] 2-column card layout on desktop, 1-column on mobile
- [ ] No "What is vulnex?" intro, pain points, or architecture diagram on index
- [ ] All content above the fold on a 1080p screen
- [ ] Hover states with accent border + background shift
- [ ] `cd website && npm run build` succeeds
- [ ] Responsive at 768px and 600px breakpoints

## Priority

**Medium** — Improves docs UX and first impression, but existing content is functional.

## Dependencies

None — self-contained change to `website/src/pages/docs/index.astro`.

## Implementation Notes

- **Modified files:**
  - `website/src/pages/docs/index.astro` — complete rewrite of page content and scoped styles
- **No new files needed** — reuses existing `DocsLayout`, `getDocsSections()`, and CSS variables
- Keep the `DocsLayout` wrapper and sidebar intact — only the `<slot>` content changes
- Follow existing CSS variable conventions: `--accent`, `--surface`, `--border`, `--text`, `--text-secondary`, `--font-mono`

## Documentation Updates

- **Website**: This IS the website update
- **README.md**: No changes needed
