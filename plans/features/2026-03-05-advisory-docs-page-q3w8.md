---
name: Advisory Documentation Page
description: Add a docs page for the advisory command covering search, get, and affected subcommands with examples, flags, pain points, and tips.
date: 2026-03-05
status: completed
---

# Advisory Documentation Page

## Description

Add a `/docs/advisory/` page to the website documenting the `vulnex advisory` command and its three subcommands (`get`, `search`, `affected`). The page should follow the same format as existing command docs (kev, cve, epss) with overview, subcommand cards, terminal examples, flag tables, a "What is GHSA?" explainer section, pain points it solves, and tips/recipes.

## User Stories

- As a user, I want to find advisory command docs from the sidebar so I can learn how to search and retrieve advisories.
- As a user, I want terminal examples for each subcommand so I can copy-paste commands.
- As a user, I want to understand what pain points the advisory command solves so I know when to use it.

## Acceptance Criteria

- [ ] New page at `website/src/pages/docs/advisory.astro` following kev.astro format.
- [ ] Page sections: Overview, advisory search, advisory get, advisory affected, What is GHSA?, Tips & recipes, Related commands.
- [ ] Each subcommand has Usage, Examples (TerminalWindow), and Flags table.
- [ ] Overview explains the purpose and pain points solved.
- [ ] `docs-nav.ts` updated with advisory entry and subcommands.
- [ ] `npm run build` passes.

## Implementation Details

### Files modified
- `website/src/pages/docs/advisory.astro` (new)
- `website/src/content/docs-nav.ts` — Add advisory to Commands section

### docs-nav.ts entry
```ts
{
  slug: "advisory", title: "advisory", description: "Search, retrieve, and inspect security advisories from GitHub Advisory Database.",
  subcommands: [
    { id: "advisory-search", label: "advisory search" },
    { id: "advisory-get", label: "advisory get" },
    { id: "advisory-affected", label: "advisory affected" },
  ],
},
```

## Priority

**High** — Completes the command docs coverage.

## Dependencies

- Existing docs layout, sidebar, and nav structure.

## Documentation

- This IS the documentation change.
- No README changes needed.
