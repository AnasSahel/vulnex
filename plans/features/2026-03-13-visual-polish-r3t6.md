---
name: Visual Polish & Responsive Refinement
description: Refine responsive breakpoints, add micro-animations, and polish edge cases across dashboard and auth pages.
date: 2026-03-13
status: completed
---

# Visual Polish & Responsive Refinement

## Description

The app is functional but needs a polish pass — responsive behavior on small screens, micro-interactions, and visual consistency refinements.

### Current problems

1. CVE table overflows horizontally on mobile without proper scroll handling.
2. Dashboard sections lack entrance animations.
3. Sidebar behavior on mobile could be smoother.
4. Auth pages lack loading states on form submission.

### Target design

**Responsive refinements:**
- CVE table: horizontal scroll wrapper on mobile, priority column hidden on small screens
- Stat cards: stack to 1 column on very small screens (< 400px)
- EPSS chart: adequate sizing on mobile

**Micro-animations:**
- Dashboard sections fade in with staggered delays on page load
- Stat cards have subtle scale-up on mount
- Form buttons show spinner during submission

**Auth page polish:**
- Loading spinner in buttons during sign-in/sign-up
- Smooth transition between login and signup pages
- Password strength indicator on signup

## User Stories

1. As a mobile user, I want the dashboard to be usable on my phone.
2. As a user, I want the app to feel responsive and polished.

## Acceptance Criteria

- [x] CVE table scrolls horizontally on screens < 768px
- [x] Dashboard sections have staggered fade-in animations
- [x] Auth form buttons show loading state during submission
- [x] No horizontal overflow on any page at 375px width
- [x] `bun run build` completes without errors

## Priority

**Low** — Nice-to-have polish, no functionality change.

## Dependencies

- `2026-03-13-auth-integration-k8v3` (for auth form loading states)

## Implementation Notes

- Add `overflow-x-auto` wrapper around the CVE table on mobile
- Use CSS `animation-delay` for staggered section entrance
- Add Shadcn `sonner` or toast component for success/error notifications
- Consider `framer-motion` only if CSS animations prove insufficient

## Documentation Updates

No changes needed — internal refinement.
