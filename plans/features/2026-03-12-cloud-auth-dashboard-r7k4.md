---
name: Cloud Auth Shell & Dashboard
description: Login/signup UI pages and a vulnerability intelligence dashboard as the first VulneX Cloud pages.
date: 2026-03-12
status: completed
---

# Cloud Auth Shell & Dashboard

## Description

VulneX Cloud needs its first real pages. This feature adds a minimal auth shell (login/signup forms) and a vulnerability intelligence dashboard — the page users land on after signing in. No backend auth wiring yet; this is UI-only with mock data, establishing the product feel and page structure for future integration.

### Current problems

1. The `app/` directory has only the default Next.js placeholder page.
2. There is no page structure, routing, or layout to build on.
3. Without a dashboard, there's nothing to demonstrate the SaaS value proposition.

### Target design

**Auth pages** (`/login`, `/signup`):
- Clean, centered card forms using Shadcn UI components
- Login: email + password fields, "Sign in" button, link to signup
- Signup: name + email + password fields, "Create account" button, link to login
- VulneX branding (logo/wordmark, tagline)
- No backend wiring — forms submit to nowhere, but structure is ready for auth integration

**Dashboard** (`/dashboard`):
- Top bar with VulneX wordmark, user avatar placeholder, and settings icon
- Layout priority (top to bottom, above-the-fold first):

1. **Quick actions bar** — CVE search input, "Add to watchlist" button, "Upload SBOM" button
2. **Recent alerts** — Timeline/feed of mock vulnerability events (new exploit found, EPSS spike, added to KEV) with timestamps and severity indicators
3. **Risk posture summary** — Stats cards showing: total watched CVEs, critical count, % with known exploits, average EPSS score
4. **Watched CVEs table** — Sortable table with columns: CVE ID, description (truncated), CVSS, EPSS, KEV status, priority badge (P0–P4)
5. **EPSS trend chart** — Simple line chart showing score movement for top watched CVEs over time (mock data, placeholder chart)

**Routing structure:**
- `/login` — login page
- `/signup` — signup page
- `/dashboard` — main dashboard (default authenticated landing)
- `/` — redirects to `/dashboard` (or `/login` when auth is wired)

**Mock data:** All dashboard sections use hardcoded mock data that mirrors real vulnex CLI output (real CVE IDs, realistic EPSS scores, plausible alert events).

## User Stories

1. As a visitor, I want to see a login/signup page so that I know VulneX Cloud is a real product I can sign up for.
2. As a user, I want a dashboard that shows my vulnerability posture at a glance so that I can quickly assess risk.
3. As a user, I want quick actions on the dashboard so that I can immediately search CVEs, add to watchlists, or upload SBOMs.

## Acceptance Criteria

- [x] `/login` renders a login form with email and password fields
- [x] `/signup` renders a signup form with name, email, and password fields
- [x] `/dashboard` renders with all 5 sections using mock data
- [x] Quick actions bar has a functional search input and action buttons (UI only)
- [x] Recent alerts section shows at least 5 mock alert events with timestamps
- [x] Risk posture shows 4 stat cards with mock numbers
- [x] Watched CVEs table shows at least 8 mock CVEs with all columns
- [x] EPSS trend section has a placeholder chart area
- [x] Dashboard has a top navigation bar with VulneX branding
- [x] All pages use Shadcn UI components and Satoshi font
- [x] Pages are responsive (mobile-friendly)
- [x] `bun run build` completes without errors
- [x] `/` redirects to `/dashboard`

## Priority

**High** — First visible pages of the SaaS product. Everything else builds on this.

## Dependencies

- `2026-03-12-saas-app-scaffold-m4v2` (completed) — Next.js + Tailwind + Shadcn setup

## Implementation Notes

- **Shadcn components to install:** `card`, `input`, `table`, `badge`, `avatar`, `separator`, `label`, `dropdown-menu`
- **File structure:**
  - `src/app/login/page.tsx` — login form
  - `src/app/signup/page.tsx` — signup form
  - `src/app/dashboard/page.tsx` — dashboard page
  - `src/app/dashboard/layout.tsx` — dashboard layout with top nav
  - `src/lib/mock-data.ts` — centralized mock data (CVEs, alerts, stats)
  - `src/components/dashboard/` — dashboard section components (quick-actions, alerts-feed, risk-posture, cve-table, epss-chart)
- **For the EPSS chart:** Use a simple SVG sparkline or a lightweight chart library. If adding a dependency feels heavy, a styled placeholder div is acceptable for now.
- **Mock CVE IDs to use:** CVE-2024-3094 (xz), CVE-2024-4577 (PHP CGI), CVE-2023-44487 (HTTP/2 rapid reset), CVE-2024-21762 (FortiOS), CVE-2023-4966 (Citrix Bleed), CVE-2024-1709 (ScreenConnect), CVE-2024-27198 (TeamCity), CVE-2023-46805 (Ivanti)
- **Dark mode:** Not required for this iteration, but use Shadcn's theming so it's easy to add later

## Documentation Updates

No changes needed — the SaaS app is not public-facing yet.
