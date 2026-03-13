---
name: Dashboard Shadcn Component Refactor
description: Replace hand-built UI patterns with Shadcn components and extract repeated patterns into reusable components.
date: 2026-03-13
status: completed
---

# Dashboard Shadcn Component Refactor

## Description

The dashboard has several hand-built UI patterns that either duplicate Shadcn components or are repeated across multiple files. This refactor consolidates them into reusable, Shadcn-aligned components for consistency and maintainability.

### Current problems

1. Severity/status pills are hand-built with inline `color-mix` styles in 3 places (CVE table KEV badge, priority badge, alerts feed type label) — Shadcn `Badge` is installed but unused.
2. Section header + gradient divider pattern is copy-pasted in 4 components (alerts feed, risk posture, CVE table, EPSS chart).
3. Colored icon background pattern uses inline `color-mix` in 2 places (risk posture, alerts feed).
4. Risk posture stat cards use raw divs instead of Shadcn `Card`.

### Target design

**1. Severity Badge** — extend Shadcn Badge with a `severity` variant prop:
```tsx
<SeverityBadge severity="critical">KEV</SeverityBadge>
<SeverityBadge severity="P0">P0</SeverityBadge>
<SeverityBadge severity="info" label>Exploit</SeverityBadge>
```
Maps severity levels to CSS variables. Replaces all inline `color-mix` badge patterns.

**2. Section Header** — reusable component replacing the repeated h2 + divider:
```tsx
<SectionHeader title="Watched CVEs" count={8} />
```
Renders the uppercase label, gradient line, and optional count badge.

**3. Icon Box** — small reusable wrapper for colored icon backgrounds:
```tsx
<IconBox color="var(--severity-critical)">
  <AlertTriangle className="h-3.5 w-3.5" />
</IconBox>
```

**4. Risk Posture** — use Shadcn `Card` + `CardContent` instead of raw divs.

## User Stories

1. As a developer, I want reusable dashboard primitives so that new sections are consistent without copy-pasting styles.

## Acceptance Criteria

- [x] `SeverityBadge` component exists and is used in CVE table (KEV + priority) and alerts feed (type label)
- [x] `SectionHeader` component exists and is used in all 4 dashboard sections
- [x] `IconBox` component exists and is used in risk posture and alerts feed
- [x] Risk posture stat cards use Shadcn `Card` + `CardContent`
- [x] No inline `color-mix` style attributes remain in dashboard components (except EPSS chart SVG gradients)
- [x] No duplicate section header markup across components
- [x] Visual output is identical before and after refactor
- [x] `bun run build` completes without errors

## Priority

**Medium** — Code quality and consistency improvement, no user-facing change.

## Dependencies

- `2026-03-13-theme-toggle-w5k8` (completed) — CSS variables must be stable

## Implementation Notes

- Create `src/components/dashboard/severity-badge.tsx` wrapping Shadcn Badge
- Create `src/components/dashboard/section-header.tsx`
- Create `src/components/dashboard/icon-box.tsx`
- Update `alerts-feed.tsx`, `cve-table.tsx`, `risk-posture.tsx`, `epss-chart.tsx`
- The EPSS chart SVG gradient hex fallbacks are intentional (CSS vars don't work in SVG `stop-color`) — leave those alone
- The `SeverityBadge` should accept either a severity string (`critical`, `high`, `medium`, `low`) or a priority string (`P0`–`P4`) and map both to the correct CSS variable

## Documentation Updates

No changes needed — internal refactor only.
