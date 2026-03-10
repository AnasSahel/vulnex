---
name: Blog Section
description: Add a /blog section to the vulnex website with content collection, listing page, and an inaugural post about Watch Diff.
date: 2026-03-10
status: completed
---

# Blog Section

## Description

The vulnex website currently has a landing page and docs — but no way to announce features, share threat intel insights, or publish content that isn't command reference. A blog section fills this gap: it gives the project a voice and a place to explain *why* features exist, not just *how* to use them.

The first post will cover the Watch Diff feature (`cve watch diff`), showcasing the Threat Intelligence Layer and demonstrating vulnex's unique value prop — no other CLI vuln tool surfaces "what changed since your last check."

### Current problems

1. No place to announce new features — users discover them only via `--help` or changelogs
2. No narrative content explaining the *why* behind features (docs cover the *how*)
3. No SEO surface for threat intelligence concepts that would bring new users to vulnex

### Target design

New content collection `blog` with its own layout, listing page, and individual post pages.

**URL structure:**
- `/blog/` — listing page with all posts, newest first
- `/blog/<slug>/` — individual post

**Listing page (`/blog/`):**
- Editorial-style design — no cards, horizontal rows separated by border lines
- Each row: date (left, 100px mono) + title & description (main) + arrow icon (hidden until hover)
- "New" tag in red on latest post
- Header: "Blog" at 3.5rem/800 weight with subtitle
- Posts sorted by date descending

**Post page (`/blog/<slug>/`):**
- Clean editorial reading layout using `BaseLayout` with PageBackground grain overlay
- 680px max-width, 0.95rem body text, 1.8 line-height
- Post header: title, date, reading time, tags displayed inline with `/` separators (no colored backgrounds)
- Blockquotes use `border-left: 2px solid var(--text)` (not accent)
- Back-to-blog link says "Blog" with chevron icon
- Full MDX content (supports TerminalWindow, TabbedPanel, and other existing components)
- No sidebar (blog posts should feel focused, not cluttered)

**Content schema:**
```typescript
const blog = defineCollection({
  loader: glob({ pattern: '**/*.mdx', base: './src/content/blog' }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    date: z.string(),           // YYYY-MM-DD
    tags: z.array(z.string()).optional(),
  }),
});
```

**Navigation:**
- Add "Blog" link to `Navbar.astro` between the existing nav links

## User Stories

1. As a vulnex user, I want to read about new features so I understand what they do and why they matter.
2. As a project maintainer, I want a place to publish release announcements and threat intel insights.
3. As a potential user, I want to find vulnex through blog posts about vulnerability management topics.

## Acceptance Criteria

- [x] New `blog` content collection in `content.config.ts` with title, description, date, tags schema
- [x] Blog listing page at `pages/blog/index.astro` — editorial row layout (no cards), sorted by date desc
- [x] Blog post page at `pages/blog/[slug].astro` — editorial reading layout, 680px max-width, with grain background
- [x] Blog styles scoped within page components (no separate blog.css) following existing CSS variable conventions
- [x] "Blog" link added to `Navbar.astro`
- [x] First blog post: "Watch Diff: Know When Your CVEs Get Worse" covering the `cve watch diff` feature
- [x] Blog post uses `TerminalWindow` component for command examples
- [x] `cd website && npm run build` succeeds
- [x] Reading time computed from word count (~200 wpm)

## Priority

**Medium** — Adds content marketing surface and feature announcement capability, but doesn't block core CLI functionality.

## Dependencies

- Watch Diff feature (completed) — the first blog post covers this feature

## Implementation Notes

- **New files:**
  - `website/src/content/blog/watch-diff.mdx` — first blog post
  - `website/src/pages/blog/index.astro` — editorial listing page with horizontal row layout
  - `website/src/pages/blog/[slug].astro` — editorial post page with scoped styles
- **Modified files:**
  - `website/src/content.config.ts` — add `blog` collection
  - `website/src/components/Navbar.astro` — add Blog nav link
  - `website/src/components/WhatsNew.astro` — pulls latest blog post for homepage strip
- No separate `blog.css` — styles are scoped within each `.astro` page component
- Blog posts use `BaseLayout` + `PageBackground` for grain texture consistency
- Listing page uses editorial horizontal rows (border-separated) instead of card grid
- Post page: tags shown inline with `/` separators, blockquotes with solid text-color border
- Reading time: `Math.ceil(wordCount / 200)` computed in the `[slug].astro` page

## Documentation Updates

- **Website**: The blog section *is* the documentation update
- **README.md**: No changes needed — blog is a website-only addition
