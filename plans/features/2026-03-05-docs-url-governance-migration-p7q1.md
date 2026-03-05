---
name: Docs URL Governance and Migration Plan
description: Define canonical docs URLs, preserve backward compatibility, and remove dead-end or broken docs entry points (including /docs/ 404).
date: 2026-03-05
status: completed
---

# Docs URL Governance and Migration Plan

## Description

Users currently encounter broken or non-obvious docs entry paths. This feature establishes canonical URL conventions and migration rules so docs remain stable and discoverable over time.

## User Stories

- As a user, I want obvious URLs (`/docs/`, `/docs/commands/...`) that I can remember.
- As a maintainer, I want URL rules to avoid future routing drift.
- As a returning user, I want old links to keep working after reorganization.

## Acceptance Criteria

- [x] `/docs/` resolves successfully (no 404).
- [x] Canonical URL patterns documented in repo.
- [x] Legacy docs URLs continue to work (no breaking changes — existing pages kept at same paths).
- [x] README and landing docs links point to canonical routes.

## Priority

**High**

## Dependencies

- Astro routing config
- GitHub Pages deployment behavior
- docs links in `README.md` and website components

## Implementation Details

### Canonical URL pattern

- `/docs/` — Hub page
- `/docs/getting-started/` — Quick start guide
- `/docs/cve/` — CVE command reference
- `/docs/scoring/` — Scoring & prioritization guide

### Backward compatibility

No URLs were changed — existing `/docs/cve/` and `/docs/scoring/` remain at the same paths. The `/docs/` path was previously a 404 and now resolves to the hub page.

### Files modified

- `README.md` — Added Documentation and Getting Started links at the top.
- `website/src/pages/docs/index.astro` — Created (was previously missing, causing 404).
- `website/src/components/Navbar.astro` — Consolidated to single `/docs/` link.
- `website/src/components/Footer.astro` — Added Docs link.

## Testing Checklist

```bash
cd website && npm run build
# Verify /docs/ renders (was previously 404)
# Verify /docs/cve/ still works
# Verify /docs/scoring/ still works
# Verify /docs/getting-started/ works
# Verify README links resolve
```
