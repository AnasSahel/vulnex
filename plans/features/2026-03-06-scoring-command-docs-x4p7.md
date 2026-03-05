---
name: Scoring Command Documentation Page
description: Move the scoring page into the Commands section of the website navigation and update it to include command reference content alongside the existing conceptual material.
date: 2026-03-06
status: completed
---

# Scoring Command Documentation Page

## Description

The `vulnex scoring` CLI command exists (cmd/scoring.go) and displays built-in scoring profiles and priority thresholds. However, on the website it's only listed under the **Reference** section of docs-nav.ts, not in the **Commands** section where every other command lives. The page itself (scoring.astro) uses a "Concepts" badge instead of "Command Reference" and lacks standard command-page elements like usage syntax.

This feature moves `scoring` into the Commands nav section, adds command reference content (usage syntax, badge, no-flags note), enriches the related commands section with links to `prioritize` and `sbom check`, and keeps all existing conceptual content intact.

## User Stories

1. As a user browsing the Commands section of the docs, I want to see `scoring` listed alongside other commands so I can discover it without hunting through Reference.
2. As a user on the scoring page, I want to see standard command reference elements (usage syntax, badge) so I know this is a real CLI command I can run.
3. As a user reading the scoring docs, I want links to `prioritize` and `sbom check` so I can navigate to commands that use scoring profiles.

## Acceptance Criteria

- [x] `scoring` appears in the **Commands** section of `docs-nav.ts` (after `prioritize`, before `sbom`).
- [x] `scoring` is removed from the **Reference** section of `docs-nav.ts` (avoid duplication).
- [x] `scoring.astro` badge changes from `Concepts` to `Command Reference`.
- [x] `scoring.astro` heading changes from `Scoring & Prioritization` to `vulnex scoring`.
- [x] A usage section is added after the overview: `vulnex scoring` (no arguments, no flags beyond global `--no-color`).
- [x] The related commands section links to `prioritize`, `sbom check`, and `cve get` (with scoring profile).
- [x] All existing conceptual content (signals, formula, profiles, custom weights, priority tiers, disagreements, guidance, CLI examples) remains unchanged.
- [x] The website builds without errors (`npm run build` in website/).
- [x] Navigation sidebar renders scoring under Commands.

## Priority

Medium — the command already works and the content already exists; this is a navigation/discoverability improvement.

## Dependencies

- Existing `scoring.astro` page (already implemented).
- Existing `docs-nav.ts` structure.
- No code changes to the CLI itself.

## Implementation Details

### Files Changed

1. **`website/src/content/docs-nav.ts`**
   - Added `scoring` entry to Commands section (after `prioritize`, before `sbom`)
   - Removed the entire Reference section (it only contained scoring)

2. **`website/src/pages/docs/scoring.astro`**
   - Badge: `Concepts` → `Command Reference`
   - Heading: `Scoring & Prioritization` → `vulnex scoring`
   - Title: `Scoring & Prioritization — vulnex docs` → `scoring command — vulnex docs`
   - Added usage section with terminal window showing full command output
   - Removed duplicate "View built-in profiles" terminal example from CLI examples section
   - Updated related commands: added `prioritize` and `sbom check`, removed redundant `Scoring profiles` link
   - Added `.code-inline` CSS styles for the usage section

### README.md
- No changes needed — the scoring command is already documented.

## Testing

```bash
# Verify website builds
cd website && npm run build

# Preview locally and check:
# 1. Scoring appears in Commands section of sidebar
# 2. Scoring page shows "Command Reference" badge
# 3. Usage section displays terminal output
# 4. Related commands link to cve, prioritize, and sbom
cd website && npm run dev

# Verify CLI command still works
go run . scoring
```
