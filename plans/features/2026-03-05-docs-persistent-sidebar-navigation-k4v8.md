---
name: Docs Persistent Sidebar Navigation
description: Replace per-page in-page sidebars with a Clerk-style persistent global sidebar across all docs pages, with collapsible command sections showing subcommands.
date: 2026-03-05
status: completed
---

# Docs Persistent Sidebar Navigation + Command Palette

## Description

The current docs layout has a different sidebar per page (populated via a `<slot name="sidebar">` in each `.astro` file). Each page defines its own sidebar links, there's no global navigation tree, and the docs hub (`/docs/`) has no sidebar at all.

The goal is to replace this with a **persistent global sidebar** (inspired by Clerk's docs) that appears on every docs page — including the hub — with:

- **Home** link → `/docs/`
- **Getting Started** section → Quick Start page
- **Commands** section with collapsible parent entries:
  - `cve` → page at `/docs/cve/`, sublinks: get, search, list, history, watch
  - `kev` → page at `/docs/kev/`, sublinks: list, recent, check, stats
  - `epss` → page at `/docs/epss/`, sublinks: score, top, trend
- **Reference** section:
  - Scoring & Prioritization

Each command page link navigates to the page. Each subcommand link scrolls to the anchor `#<cmd>-<subcmd>` on that page (as they already exist today).

The sidebar auto-expands the section containing the current page and highlights the active page. On mobile, the sidebar collapses behind a toggle button (existing behavior preserved).

## User Stories

- As a user, I want a persistent sidebar on every docs page so I can navigate between sections without going back to the hub.
- As a user, I want to see all commands grouped with their subcommands so I can quickly find the reference I need.
- As a user viewing docs on mobile, I want the sidebar to toggle open/closed without losing my place.
- As a user on the docs hub, I still want the sidebar visible so I can jump directly to any page.

## Acceptance Criteria

- [x] A global sidebar component renders on ALL docs pages, including `/docs/`.
- [x] Sidebar has a "Home" link pointing to `/docs/`.
- [x] Sidebar has a "Getting Started" section with a "Quick Start" link.
- [x] Sidebar has a "Commands" section with collapsible entries for each command.
- [x] Each command entry shows subcommands as nested links (anchor links to `#<cmd>-<subcmd>`).
- [x] The current page is highlighted in the sidebar (active state).
- [x] The section containing the current page auto-expands on load.
- [x] On mobile (< 900px), sidebar hides behind a toggle button.
- [x] Sidebar has a "Reference" section with Scoring link.
- [x] Per-page `<Fragment slot="sidebar">` blocks are removed from individual pages.
- [x] Sidebar data is driven from `docs-nav.ts` (single source of truth), extended with subcommand info.
- [x] `npm run build` passes with no errors.
- [x] Visual style matches Clerk reference: clean, light-weight, proper hierarchy with section headings.
- [x] Cmd+K (or Ctrl+K) opens a search/command palette modal.
- [x] Palette searches through all pages and subcommands from `docs-nav.ts`.
- [x] Substring matching on page titles, subcommand labels, and descriptions.
- [x] Arrow keys + Enter to navigate; Escape to close.
- [x] Search trigger button visible in the navbar with keyboard shortcut hint.

## Implementation Details

### Data model changes (`website/src/content/docs-nav.ts`)

Extended `DocsPage` with optional `subcommands` array:

```ts
export interface DocsSubcommand {
  id: string;       // anchor id, e.g. "kev-list"
  label: string;    // display name, e.g. "kev list"
}

export interface DocsPage {
  slug: string;
  title: string;
  description: string;
  subcommands?: DocsSubcommand[];
}
```

Command pages (cve, kev, epss) now include subcommand data. Section key renamed from "Scoring & Policy" to "Reference".

### New component (`website/src/components/DocsSidebar.astro`)

Self-contained sidebar component that:
1. Reads `docsSections` from `docs-nav.ts`
2. Receives the current `slug` as a prop
3. Renders Home link, section headings, page links, and nested subcommand links
4. Uses `.active` class for the current page
5. Auto-expands subcommands only for the active page (chevron rotates)
6. Subcommand links use `border-left` visual indicator with accent hover

### Layout changes (`website/src/layouts/DocsLayout.astro`)

- Replaced `<slot name="sidebar" />` with `<DocsSidebar slug={slug} />`
- Sidebar padding adjusted for the global nav style

### Page changes

- `website/src/pages/docs/index.astro` — Switched from standalone BaseLayout to DocsLayout (gets sidebar)
- `website/src/pages/docs/getting-started.astro` — Removed sidebar slot, added `slug="getting-started"`
- `website/src/pages/docs/cve.astro` — Removed sidebar slot
- `website/src/pages/docs/kev.astro` — Removed sidebar slot
- `website/src/pages/docs/epss.astro` — Removed sidebar slot
- `website/src/pages/docs/scoring.astro` — Removed sidebar slot

### Command palette (`website/src/components/SearchDialog.astro`)

A client-side command palette component that:
1. Builds a flat search index from `docs-nav.ts` (pages + subcommands + descriptions)
2. Opens on Cmd+K (Mac) / Ctrl+K (Windows/Linux) or clicking the search trigger
3. Filters results as the user types (simple substring/fuzzy match)
4. Supports keyboard navigation (arrow keys, Enter, Escape)
5. Navigates to the selected page/anchor on selection

### Navbar search trigger

Add a search button to `Navbar.astro` that shows the keyboard shortcut hint and opens the palette on click.

### Files modified

- `website/src/content/docs-nav.ts`
- `website/src/components/DocsSidebar.astro` (new)
- `website/src/components/SearchDialog.astro` (new)
- `website/src/components/Navbar.astro` — Add search trigger button
- `website/src/layouts/DocsLayout.astro`
- `website/src/pages/docs/index.astro`
- `website/src/pages/docs/getting-started.astro`
- `website/src/pages/docs/cve.astro`
- `website/src/pages/docs/kev.astro`
- `website/src/pages/docs/epss.astro`
- `website/src/pages/docs/scoring.astro`

## Testing Commands

```bash
cd website && npm run build
cd website && npm run dev
# Visit: /docs/, /docs/cve/, /docs/kev/, /docs/epss/, /docs/scoring/, /docs/getting-started/
# Verify: sidebar persists on all pages, active state highlights, subcommands expand on active page, mobile toggle works
```

## Priority

**High** — This is the core navigation change for the docs.

## Dependencies

- `website/src/content/docs-nav.ts` — Existing nav data structure
- `website/src/layouts/DocsLayout.astro` — Existing docs layout
- All existing docs pages

## Documentation

- No README changes — this is a website-only change.
- The website itself IS the documentation being updated.
