---
name: Docs Persistent Sidebar Navigation
description: Replace per-page in-page sidebars with a Clerk-style persistent global sidebar across all docs pages, with collapsible command sections showing subcommands.
date: 2026-03-05
status: active
---

# Docs Persistent Sidebar Navigation

## Description

The current docs layout has a different sidebar per page (populated via a `<slot name="sidebar">` in each `.astro` file). Each page defines its own sidebar links, there's no global navigation tree, and the docs hub (`/docs/`) has no sidebar at all.

The goal is to replace this with a **persistent global sidebar** (inspired by Clerk's docs) that appears on every docs page — including the hub — with:

- **Home** link → `/docs/`
- **Getting Started** section → Quick Start page
- **Commands** section with collapsible parent entries:
  - `cve` → page at `/docs/cve/`, sublinks: get, search, list, history, watch
  - `kev` → page at `/docs/kev/`, sublinks: list, recent, check, stats
  - `epss` → page at `/docs/epss/`, sublinks: score, top, trend
  - `enrich` → standalone page (no subcommands)
  - `scan` → standalone page (no subcommands)
  - `sbom` → page with sublinks: check, diff
  - `advisory` → page with sublinks: search, get, affected
  - `exploit` → page with sublinks: check
- **Reference** section:
  - Scoring & Prioritization
  - Configuration
  - Output Formats

Each command page link navigates to the page. Each subcommand link scrolls to the anchor `#<cmd>-<subcmd>` on that page (as they already exist today).

The sidebar auto-expands the section containing the current page and highlights the active page. On mobile, the sidebar collapses behind a toggle button (existing behavior preserved).

## User Stories

- As a user, I want a persistent sidebar on every docs page so I can navigate between sections without going back to the hub.
- As a user, I want to see all commands grouped with their subcommands so I can quickly find the reference I need.
- As a user viewing docs on mobile, I want the sidebar to toggle open/closed without losing my place.
- As a user on the docs hub, I still want the sidebar visible so I can jump directly to any page.

## Acceptance Criteria

- [ ] A global sidebar component renders on ALL docs pages, including `/docs/`.
- [ ] Sidebar has a "Home" link pointing to `/docs/`.
- [ ] Sidebar has a "Getting Started" section with a "Quick Start" link.
- [ ] Sidebar has a "Commands" section with collapsible entries for each command.
- [ ] Each command entry shows subcommands as nested links (anchor links to `#<cmd>-<subcmd>`).
- [ ] The current page is highlighted in the sidebar (active state).
- [ ] The section containing the current page auto-expands on load.
- [ ] On mobile (< 900px), sidebar hides behind a toggle button.
- [ ] Sidebar has a "Reference" section with Scoring, Configuration links.
- [ ] Per-page `<Fragment slot="sidebar">` blocks are removed from individual pages.
- [ ] Sidebar data is driven from `docs-nav.ts` (single source of truth), extended with subcommand info.
- [ ] `npm run build` passes with no errors.
- [ ] Visual style matches Clerk reference: clean, light-weight, proper hierarchy with section headings.

## Implementation Details

### Data model changes (`website/src/content/docs-nav.ts`)

Extend `DocsPage` to include optional subcommands:

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

Add subcommand data for each command page. Add new sections/pages for missing commands (enrich, scan, sbom, advisory, exploit) — these can be placeholder pages initially.

### New component (`website/src/components/DocsSidebar.astro`)

A self-contained sidebar component that:
1. Reads `docsSections` from `docs-nav.ts`
2. Receives the current `slug` as a prop
3. Renders section headings, page links, and nested subcommand links
4. Uses CSS classes `.active` for the current page, `.expanded` for open sections
5. Auto-expands the section containing the current slug

### Layout changes (`website/src/layouts/DocsLayout.astro`)

- Remove the `<slot name="sidebar" />` pattern
- Import and render `<DocsSidebar slug={slug} />` instead
- Keep the mobile toggle behavior

### Page changes (all `website/src/pages/docs/*.astro`)

- Remove `<Fragment slot="sidebar">...</Fragment>` blocks from every page
- The hub page (`/docs/index.astro`) should also use `DocsLayout` (or include the sidebar directly)

### Files to modify

- `website/src/content/docs-nav.ts` — Extend data model with subcommands
- `website/src/components/DocsSidebar.astro` — New global sidebar component
- `website/src/layouts/DocsLayout.astro` — Replace slot-based sidebar with `DocsSidebar`
- `website/src/pages/docs/index.astro` — Switch to DocsLayout, remove standalone layout
- `website/src/pages/docs/cve.astro` — Remove sidebar slot
- `website/src/pages/docs/kev.astro` — Remove sidebar slot
- `website/src/pages/docs/epss.astro` — Remove sidebar slot
- `website/src/pages/docs/scoring.astro` — Remove sidebar slot
- `website/src/pages/docs/getting-started.astro` — Remove sidebar slot

## Testing Commands

```bash
cd website && npm run build
cd website && npm run dev
# Visit: /docs/, /docs/cve/, /docs/kev/, /docs/epss/, /docs/scoring/
# Verify: sidebar persists, active state highlights, subcommands expand, mobile toggle works
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
