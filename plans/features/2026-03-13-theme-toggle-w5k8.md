---
name: Dark & Light Theme Support
description: Add class-based dark/light theme switching with next-themes, a toggle button, and a complete light palette.
date: 2026-03-13
status: completed
---

# Dark & Light Theme Support

## Description

The VulneX Cloud dashboard is currently dark-only. Users working in bright environments or with light-mode OS preferences need a light alternative. Adding theme support also signals product maturity.

### Current problems

1. Dark theme is hard-coded in `:root` — no `.dark` class separation.
2. No way for users to switch themes.
3. `color-scheme: dark` is set unconditionally on `<html>`.

### Target design

**Theme system using `next-themes`:**
- Class-based switching (`.dark` on `<html>`)
- Three modes: Light, Dark, System (follows OS preference)
- Persisted in localStorage, no flash of wrong theme (SSR-safe)
- Smooth 150ms CSS `transition` on `background-color` and `color`

**Light palette — "Fog":**
A cool, slightly blue-tinted off-white — not generic white. The severity/status accent colors get slightly deepened for contrast on light backgrounds.

| Variable | Dark | Light |
|---|---|---|
| `--background` | `#0d1117` | `#f6f8fa` |
| `--foreground` | `#e6edf3` | `#1f2328` |
| `--card` / `--surface-raised` | `#161b22` | `#ffffff` |
| `--surface-overlay` | `#1c2129` | `#f0f3f6` |
| `--primary` | `#58a6ff` | `#0969da` |
| `--primary-foreground` | `#0d1117` | `#ffffff` |
| `--secondary` | `#1c2129` | `#eaeef2` |
| `--muted` | `#1c2129` | `#eaeef2` |
| `--muted-foreground` / `--text-dim` | `#8b949e` | `#656d76` |
| `--text-dimmer` | `#484f58` | `#8b949e` |
| `--border` | `#30363d` | `#d1d9e0` |
| `--border-subtle` | `#30363d80` | `#d1d9e080` |
| `--destructive` / `--severity-critical` | `#f85149` | `#cf222e` |
| `--severity-high` | `#f0883e` | `#bc4c00` |
| `--severity-medium` | `#d29922` | `#9a6700` |
| `--severity-low` | `#8b949e` | `#656d76` |
| `--status-success` | `#3fb950` | `#1a7f37` |
| `--status-info` | `#58a6ff` | `#0969da` |
| `--status-purple` | `#bc8cff` | `#8250df` |
| `--sidebar` | `#161b22` | `#ffffff` |
| `--sidebar-border` | `#30363d` | `#d1d9e0` |

**Theme toggle button:**
- Sun/Moon icon in the dashboard top navbar, next to the bell icon
- Click cycles: System → Light → Dark → System
- Tooltip shows current mode name
- Smooth icon transition (crossfade)

**Login/signup pages:**
- Also respect theme — the background glow and card adapt accordingly

## User Stories

1. As a user, I want to switch between dark and light themes so I can use the app comfortably in any lighting.
2. As a user, I want the app to follow my OS theme by default so it matches my system.

## Acceptance Criteria

- [x] `next-themes` is installed and configured with `ThemeProvider` wrapping the app
- [x] `:root` contains light theme variables, `.dark` contains dark theme variables
- [x] Theme toggle button exists in the dashboard top navbar
- [x] Toggle cycles between System, Light, and Dark modes
- [x] Theme persists across page reloads (localStorage)
- [x] No flash of wrong theme on initial load
- [x] Light theme is visually polished — not just inverted colors
- [x] Severity/status colors are adjusted for contrast in light mode
- [x] Login and signup pages respect the active theme
- [x] Smooth CSS transition when switching themes
- [x] Noise texture overlay adapts (darker opacity in light mode)
- [x] Glow utilities work in both themes
- [x] `bun run build` completes without errors

## Priority

**Medium** — Important for UX polish and accessibility, but the app is functional without it.

## Dependencies

- `2026-03-13-dashboard-sidebar-n8q3` (completed) — the toggle lives in the navbar

## Implementation Notes

- Install: `bun add next-themes`
- Add `ThemeProvider` in `app/layout.tsx` wrapping children, with `attribute="class"` and `defaultTheme="system"`
- Move current `:root` values into `.dark` selector
- Write new `:root` values for the light palette
- Create `src/components/theme-toggle.tsx` — a client component using `useTheme()` from next-themes
- Add the toggle to `dashboard/layout.tsx` header, between the status indicator and the bell icon
- Update `html` element: remove hard-coded `color-scheme: dark`, let it be set dynamically via `suppressHydrationWarning` on `<html>`
- Add `transition: background-color 150ms ease, color 150ms ease` to `body` in the base layer
- The EPSS chart SVG gradient fallback hex values should remain as-is (they match the dark theme; SVG gradients don't support CSS vars reliably) — the chart will look fine in light mode since the lines use `color-mix` with vars
- Login/signup background glow: already uses `bg-primary/[0.03]` which will adapt automatically

## Documentation Updates

No changes needed — the SaaS app is not public-facing yet.
