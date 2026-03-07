---
name: Docs Content Layer Migration
description: Migrate docs navigation from hand-coded docs-nav.ts to Astro Content Layer with a YAML data collection and type-safe Zod schema.
date: 2026-03-07
status: completed
---

# Docs Content Layer Migration

## Description

Migrate the documentation navigation data from a hand-coded TypeScript file (`docs-nav.ts`) to Astro's Content Layer API using a YAML data file with Zod schema validation. This gives us:

- **Type-safe metadata** — Zod schema validates title, description, section, order, and subcommands at build time
- **Single source of truth** — Replace `docs-nav.ts` with a YAML file queried via `getCollection('docs')`
- **Better DX** — Add/reorder docs by editing YAML instead of modifying TypeScript
- **Content Layer API** — Navigation, sidebar, pager, and search all derive from the content collection

### Architecture decision: YAML over MDX

Initially planned as an MDX migration, but the doc pages are 100% HTML/JSX (Astro components like TabbedPanel, TerminalWindow, styled `<pre>` blocks with `<span>` elements). MDX v2 parses JSX children as MDX, causing failures with:
- Blank lines inside `<pre>` (triggers paragraph breaks)
- `- ` at start of lines inside `<pre>` (triggers list parsing)
- Indented content (triggers code blocks)

Since the pages have zero markdown content, MDX adds complexity without benefit. The YAML data collection approach provides all the content layer benefits (typed schema, collection queries, build-time validation) while keeping the battle-tested `.astro` page files for rendering.

### What changed
- `src/data/docs.yaml` — YAML data file with all doc page metadata
- `src/content.config.ts` — Collection schema with `file()` loader
- `src/content/docs-helpers.ts` — Async functions querying the collection for sidebar, pager, search
- `src/components/DocsSidebar.astro` — Uses `getDocsSections()` from collection
- `src/components/SearchDialog.astro` — Uses `getDocsSections()` from collection
- `src/layouts/DocsLayout.astro` — Uses collection queries for pager/breadcrumbs/TOC
- `src/pages/docs/index.astro` — Uses collection queries for section grid

### What was removed
- `src/content/docs-nav.ts` — Replaced by YAML + docs-helpers.ts
- `@astrojs/mdx` dependency — Not needed

## Acceptance Criteria

- [x] Create `src/content.config.ts` with a `docs` collection using `file()` loader for `src/data/docs.yaml`
- [x] Define Zod schema with fields: `title`, `description`, `section` (enum), `order`, `subcommands` (optional)
- [x] Schema validates at build time — invalid data causes build error
- [x] Create `src/content/docs-helpers.ts` with `getDocsSections()`, `getAllPages()`, `getPagerLinks()`
- [x] Update `DocsSidebar.astro` to use collection queries
- [x] Update `DocsLayout.astro` to use collection queries for pager and TOC
- [x] Update `SearchDialog.astro` to use collection queries
- [x] Update `src/pages/docs/index.astro` to use collection queries
- [x] Remove `src/content/docs-nav.ts`
- [x] Build passes with `npx astro build`
- [x] All 11 pages render correctly

## Testing

```bash
cd website && npx astro build

# Verify:
# 1. All 9 docs pages render at the same URLs
# 2. Sidebar navigation works correctly
# 3. Prev/next pager works on every page
# 4. Hub page section grid shows all pages
# 5. Search dialog indexes all pages
# 6. Build fails if YAML has invalid fields (test by removing a required field)
```

## Documentation Updates

- No user-facing docs updates needed — this is an internal architecture change
- README.md does not need updates
