# App Cleanup & Redesign

**Date:** 2026-03-13
**Status:** Draft
**Branch:** feat/monetization

## Problem

The vulnex cloud app has pages that are not usable or redundant. The UI feels washed-out and lacks the polish expected of a security intelligence platform. The app needs to be trimmed to its core workflow and visually elevated.

## Decisions

### 1. Page Cleanup — Remove Redundant Pages

The core workflow is **"manage products and their CVEs"**. Watching individual CVEs is handled by creating a product and adding CVEs to it — no dedicated watchlist needed.

**Remove:**

| Page | Reason |
|------|--------|
| Watchlist (`/dashboard/watchlist`) | Redundant — users create a product to track CVEs |
| Exploits (`/dashboard/exploits`) | Empty state with no data pipeline; exploit info already surfaces on CVE detail (KEV, sources) |
| SBOM Scans (`/dashboard/sbom`) | Orphaned page not in sidebar; SBOM upload remains as a product-level action |

**Remove from UI (not pages):**

| Element | Reason |
|---------|--------|
| Top bar chat icon | Placeholder, not functional |
| Top bar notifications bell | Placeholder, not functional |

**Keep:**

- Login / Signup
- Overview (dashboard) — priority strip, product list, activity feed
- Products + Product Detail — CVE table, search, Add CVEs, Upload SBOM
- CVE Detail — description, scores, EPSS trends, sources
- Settings — profile, notifications, API keys
- Help & Docs sidebar link

**Sidebar after cleanup:**

```
Platform
  Overview
  Products
Support
  Settings
  Help & Docs
```

### 2. Visual Redesign — Cleaner Aesthetic

Inspired by viteplus.dev's design language, applied to the existing vulnex app while keeping light/dark theme toggle and red accent color.

#### Typography

- **Headings:** Increase font weight and size. Use bold (700) for page titles, semibold (600) for section headers. Increase line-height for readability.
- **Body text:** Use muted foreground for secondary text (descriptions, subtitles). Increase base size slightly if needed.
- **Monospace:** Keep for CVE IDs, CVSS vectors, code — use a refined monospace font (Geist Mono or JetBrains Mono).

#### Spacing & Layout

- **More whitespace:** Increase padding inside cards, between sections, and around page content. Current layout feels cramped.
- **Consistent spacing scale:** Use a tighter set of spacing values (e.g., 4/8/12/16/24/32/48px).
- **Content max-width:** Constrain main content area width so it doesn't stretch too wide on large screens.

#### Cards & Borders

- **Softer cards:** Use subtle border (1px, muted color) instead of shadow-heavy cards. Slight border-radius (8-12px).
- **Reduce visual weight:** Remove heavy box-shadows. Use very subtle shadow or none — rely on borders and background contrast.
- **Section dividers:** Use thin horizontal rules or labeled dividers (like the current "PRODUCTS" / "ACTIVITY" labels, but refined).

#### Color & Contrast

- **Keep red accent** (`hsl(0, 84%, 50%)` or similar) for primary actions, severity badges, and brand elements.
- **Improve contrast:** The current light theme feels washed out. Increase contrast between background levels (page bg, card bg, elevated bg).
- **Dark theme:** Adopt deeper backgrounds (closer to `hsl(0, 0%, 8%)` for base, `hsl(0, 0%, 12%)` for cards) instead of gray. Subtle warm tint is acceptable.
- **Muted secondary text:** Use `hsl(0, 0%, 45%)` in light mode, `hsl(0, 0%, 55%)` in dark mode for descriptions and less important info.

#### Priority Badges

- Keep the P0-P4 color system but refine the badges:
  - Smaller, pill-shaped with subtle background fill
  - Colors: P0/P1 red tones, P2 amber/orange, P3 gray, P4 light gray

#### Tables

- **Cleaner table rows:** Reduce row height slightly, add subtle hover state, remove heavy borders between rows (use only bottom border or alternating background).
- **Column alignment:** Right-align numeric columns (CVSS, EPSS). Left-align text columns.
- **Sortable column headers:** More visible sort indicators.

#### Sidebar

- Refine sidebar styling: lighter border on the right edge, better active state (subtle background highlight + left accent bar instead of full background fill).
- Reduce sidebar width slightly if possible.

#### Top Bar

- Simplify: keep "All sources online" status badge, Sync button. Remove placeholder icons.
- Clean alignment and spacing.

#### Empty States

- For pages/sections with no data (new users), use centered illustration or icon + descriptive text + primary action button. Keep it minimal.

### 3. Specific Component Changes

| Component | Current | Target |
|-----------|---------|--------|
| Product card (overview) | Row with severity bar | Cleaner row with better spacing, refined severity mini-bar |
| Activity feed | Stacked cards with red "C" badges | Tighter list items, smaller badges, more readable timestamps |
| CVE table | Dense table | More breathing room, subtle row borders, hover highlight |
| CVE detail | Stacked cards for description/scores/sources | Better card spacing, refined EPSS chart, cleaner score display |
| Settings toggles | Red toggle switches | Keep red, but ensure consistent sizing and alignment |
| Severity badges | Colored dots + numbers | Pill badges with background fill |

## Out of Scope

- New features or pages
- Backend/API changes
- Authentication flow changes
- Mobile-specific responsive redesign (keep existing responsive behavior)

## Success Criteria

- App has only 4 main views: Overview, Products (list + detail), CVE Detail, Settings
- No dead/placeholder UI elements
- Visual consistency across all pages following the cleaner aesthetic
- Light and dark themes both look polished
- No functionality loss — SBOM upload still accessible from product detail
