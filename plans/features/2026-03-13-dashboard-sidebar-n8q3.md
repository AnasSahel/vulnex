---
name: Dashboard Sidebar Navigation
description: Add a collapsible sidebar to the VulneX Cloud dashboard using Shadcn's sidebar component.
date: 2026-03-13
status: completed
---

# Dashboard Sidebar Navigation

## Description

The dashboard currently has a top navbar but no sidebar navigation. As more pages are added (watchlists, SBOM scans, settings, team management), users need persistent navigation. A sidebar provides spatial orientation and quick access to all sections.

### Current problems

1. No way to navigate between future dashboard sections — only one page exists.
2. The top navbar alone won't scale as the app grows with more features.

### Target design

A left sidebar using Shadcn's `sidebar` component that:

- **Sits alongside the main content** — sidebar on the left, page content on the right
- **Collapsible** — can be collapsed to icons-only mode for more screen space
- **Mobile-friendly** — becomes a slide-over sheet on small screens, triggered by a hamburger button in the top navbar
- **Uses the existing dark theme** — CSS variables (`surface-raised`, `border-subtle`, `text-dim`, `primary`, etc.)
- **Simple and clean** — no overwhelming depth of nesting, just grouped nav items with icons

**Navigation structure:**

```
── Overview (Dashboard)        [LayoutDashboard]
── Watchlist                   [Eye]
── SBOM Scans                  [FileSearch]
── Exploits                    [Bug]
─────────────── separator ─────
── Settings                    [Settings]
── Help & Docs                 [HelpCircle]
```

**Visual details:**
- Active item: primary color text + subtle primary/10 background
- Hover: surface-overlay background
- Icons: text-dim by default, foreground on active/hover
- Footer area: user avatar + name + email (compact)
- Header: vulnex.cloud wordmark with shield icon (moved from top navbar to sidebar header)
- Top navbar retains: status indicator, bell, settings icon, avatar (compact version)

## User Stories

1. As a user, I want a sidebar so that I can navigate between dashboard sections without losing context.
2. As a mobile user, I want the sidebar to collapse into a slide-over so it doesn't take up screen space.

## Acceptance Criteria

- [x] Shadcn `sidebar` component is installed and configured
- [x] Sidebar renders on the left of the dashboard with all nav items listed above
- [x] Active page is visually highlighted in the sidebar
- [x] Sidebar collapses to icon-only mode via a toggle button
- [x] On mobile (<768px), sidebar becomes a sheet triggered from the top navbar
- [x] Sidebar uses existing CSS variables — no hard-coded colors
- [x] Top navbar is updated: branding moves to sidebar header, hamburger menu added for mobile
- [x] `bun run build` completes without errors
- [x] Dashboard page still renders correctly with sidebar present

## Priority

**High** — Foundation for multi-page navigation in the SaaS app.

## Dependencies

- `2026-03-12-cloud-auth-dashboard-r7k4` (completed) — dashboard must exist first

## Implementation Notes

- Install Shadcn sidebar: `bunx shadcn@latest add sidebar`
- This will also pull in `sheet`, `tooltip`, and other dependencies automatically
- Use `SidebarProvider` in the dashboard layout wrapping both sidebar and main content
- The existing `dashboard/layout.tsx` header should be refactored:
  - Move the vulnex.cloud branding + shield icon to the `SidebarHeader`
  - Keep the bell, settings, avatar in the top navbar
  - Add a `SidebarTrigger` (hamburger) button to the navbar for mobile
- Nav items should use `SidebarMenuButton` with `isActive` prop for the current route
- Sidebar footer: `SidebarFooter` with user info (mock: "Jane Doe", "jane@company.com")
- Use `"use client"` for the sidebar wrapper since it uses `useSidebar` hook for collapse state

## Documentation Updates

No changes needed — the SaaS app is not public-facing yet.
