---
name: Docs Content Layer Migration
description: Migrate docs to Astro Content Layer with MDX content collections, type-safe Zod schemas, and dynamic routing via [slug].astro.
date: 2026-03-07
status: completed
---

# Docs Content Layer Migration

## Description

Migrate the documentation pages from individual `.astro` page files to Astro's Content Layer API using MDX content collections. This gives us:

- **Type-safe frontmatter** — Zod schema validates title, description, section, order, and subcommands at build time
- **Single source of truth** — Navigation, sidebar, pager, and search all derive from `getCollection('docs')` queries
- **Dynamic routing** — One `[slug].astro` route renders all docs pages via `render()` and `<Content />`
- **Better DX** — Add/reorder docs by editing frontmatter instead of modifying a separate nav file

### Architecture: MDX + Astro content components

Each doc page is split into two files:
- **MDX file** (`src/content/docs/*.mdx`) — Slim file with YAML frontmatter and a single Astro component import. Provides the schema-validated metadata and renderable content for the collection.
- **Content component** (`src/components/docs/*-content.astro`) — Pure Astro component with the actual page HTML (terminal examples, tables, cards). Avoids MDX parsing issues with raw HTML inside `<pre>` tags.

This split gives us the full content collection API (`getCollection`, `render`, `<Content />`) while keeping the battle-tested Astro template engine for complex HTML rendering.

## Acceptance Criteria

- [x] `content.config.ts` with `docs` collection using `glob()` loader for `*.mdx`
- [x] Zod schema: `title`, `description`, `section` (enum), `order`, `subcommands` (optional)
- [x] 9 MDX files in `src/content/docs/` with validated frontmatter
- [x] 9 content components in `src/components/docs/` with page HTML
- [x] `[slug].astro` dynamic route using `getStaticPaths()` + `render()`
- [x] `docs-helpers.ts` with async `getDocsSections()` / `getPagerLinks()` from collection
- [x] DocsSidebar, DocsLayout, SearchDialog, index.astro all use collection queries
- [x] Old individual `.astro` page files deleted from `src/pages/docs/`
- [x] `docs-nav.ts` deleted (replaced by content collection)
- [x] Build passes cleanly — all 11 pages generated

## Testing

```bash
cd website && npx astro build

# Verify:
# 1. All 9 docs pages render at /docs/<slug>/
# 2. Sidebar navigation works correctly
# 3. Prev/next pager works on every page
# 4. Hub page section grid shows all pages
# 5. Right TOC scroll-spy works on command pages
# 6. Search dialog indexes all pages
# 7. Build fails if MDX frontmatter has invalid fields
```
