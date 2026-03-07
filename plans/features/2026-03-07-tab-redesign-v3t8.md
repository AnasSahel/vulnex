---
name: Tab Component Redesign
description: Restyle the TabbedPanel component with a clean underline-indicator design inspired by Vercel/shadcn/ui.
date: 2026-03-07
status: completed
---

# Tab Component Redesign

## Description

The current TabbedPanel uses a solid accent-fill on the active tab, creating a heavy toolbar-button aesthetic that clashes with the refined terminal windows below. Restyle to a clean underline-indicator design inspired by Vercel and shadcn/ui tabs.

### Current problems

1. **Solid accent fill on active tab** — heavy, button-like, clashes with the dark terminal aesthetic
2. **`flex: 1` stretches all tabs equally** — looks unbalanced when labels vary in length ("Critical RCE" vs "Malware")
3. **No bottom indicator** — no visual connection between selected tab and content below
4. **Light tab bar above dark terminal** — jarring contrast jump from `var(--surface)` to `#161b22`
5. **No transition on tab switch** — content snaps in/out abruptly

### Target design (Vercel/shadcn/ui style)

- **Underline indicator**: 2px bottom border on active tab, using `--accent` color
- **No background fill** on active tab — text color change + underline only
- **Natural width tabs**: tabs size to their label, not stretched
- **Dark tab bar**: match the terminal chrome (`#161b22`) so tab bar and terminal feel unified
- **Smooth transitions**: color and underline animate on tab switch
- **Typography**: mono font for tab labels to match the terminal context
- **Subtle separator**: thin bottom border on the tab bar, active underline overlaps it

## User Stories

1. As a docs reader, I want tabs that feel integrated with the terminal examples so the UI doesn't feel fragmented.
2. As a developer browsing command docs, I want to quickly scan tab labels without visual clutter.

## Acceptance Criteria

- [x] Active tab uses underline indicator (2px bottom border in accent color), no background fill
- [x] Inactive tabs show muted text, darken on hover
- [x] Tab labels use natural width (no `flex: 1`), mono font
- [x] Tab bar background matches terminal header (`#161b22`), border integrates with terminal
- [x] Smooth CSS transitions on hover and active state changes
- [x] Works in both light and dark themes
- [x] Tab bar scrolls horizontally on mobile without breaking
- [x] Build passes, all 9 doc pages render correctly

## Priority

**Medium** — Visual polish, no functionality change.

## Dependencies

None — self-contained CSS change in TabbedPanel.astro.

## Documentation Updates

- No docs changes needed — purely visual refinement
- No README changes needed
