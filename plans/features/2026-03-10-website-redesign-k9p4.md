---
name: Website Redesign
description: Redesign the vulnex landing page as a product site with CLI + SaaS platform positioning, terminal-forward hero, and waitlist capture.
date: 2026-03-10
status: completed
---

# Website Redesign

## Description

The current website is a template-style landing page that undersells the product. With vulnex expanding from an open-source CLI into a SaaS platform (dashboard, team features, continuous monitoring, API), the site needs to serve two jobs: convert developers to install the free CLI, and capture demand for the paid platform via a waitlist.

### Current problems

1. Every section follows identical centered-label → h2 → paragraph → grid rhythm — reads as template output
2. Hero is flat — centered text wall with terminal pushed below the fold
3. Terminal demos (the most compelling content) are buried mid-page at 720px constrained width
4. Sources section wastes a full viewport for 5 icon cards with minimal info
5. No social proof (GitHub stars, version, download count)
6. No SaaS positioning — site only speaks to CLI users
7. Install section over-explains with a two-column layout for what's a one-liner
8. Light mode has jarring dark terminal blocks with no visual bridging

### Target design

**Section order:**
1. Hero (split: copy left, terminal right)
2. Showcase (tabbed terminal demos, full-width)
3. Platform Preview (SaaS pitch + waitlist email capture)
4. Features (compact grouped list: Free CLI vs Pro Platform)
5. Install (single centered tabbed code block)
6. What's New (latest blog post strip)
7. Footer (clean link bar)

**Hero:**
- Split layout: tagline + sub + two CTAs on left, terminal on right
- CTAs: "Install CLI" (primary), "Join Waitlist" (secondary/accent outline)
- Badge strip below: source logos + GitHub stars
- Terminal shows `cve get` output (current hero content, repositioned)

**Showcase:**
- Moves from position #4 to #2
- Tabbed demos at wider width (880px vs 720px)
- Same demo data, better visual prominence

**Platform Preview (NEW):**
- Grid of 4 preview cards: Dashboard, Team Alerts, Scheduled Scans, REST API
- Each card: icon, title, short description
- Waitlist email capture form below the cards
- Visually distinct from CLI sections (subtle gradient background)

**Features:**
- Two-column layout: Free (CLI) on left, Pro (Platform) on right
- Compact list items with checkmark icons, not card grid
- Replaces the current 9-card grid
- Implicitly communicates pricing tiers without a pricing page

**Install:**
- Single centered tabbed terminal (brew / go / binary)
- No explanatory text column — the code IS the explanation
- Copy button on each tab

**What's New:**
- Horizontal card pulling latest blog post
- Title, date, description, "Read more →" link

**Navigation update:**
- Add "Sign Up" accent CTA button (links to waitlist/platform section)
- Keep: Features, Docs, Blog, GitHub, Search, Theme toggle

## User Stories

1. As a developer, I want to see the CLI in action immediately so I can decide if it's worth installing.
2. As a security team lead, I want to understand the SaaS platform offering so I can evaluate it for my team.
3. As a potential customer, I want to join a waitlist so I'm notified when the platform launches.
4. As a visitor, I want to see that the project is active and maintained.

## Acceptance Criteria

- [x] Hero: split layout with copy left, terminal right, two CTAs
- [x] Hero: source badge strip (NVD, KEV, EPSS, GHSA, OSV)
- [x] Showcase section moves to position #2 with wider container (880px)
- [x] New Platform Preview section with 4 feature cards and email waitlist form
- [x] Features section: two-column Free vs Pro comparison list
- [x] Install section: single centered tabbed code block
- [x] What's New section: latest blog post card
- [x] Navbar: clean split with only Docs/Blog links, dual CTAs ("Install" outlined + "Join Waitlist" filled), removed landing page anchor links
- [x] Footer: updated with Blog link, removed redundant CTA
- [x] Tighter section spacing (96px → 72px)
- [x] `cd website && npm run build` succeeds
- [x] Responsive at 900px, 768px, and 600px breakpoints

## Priority

**High** — The website is the primary conversion surface for both CLI adoption and SaaS demand capture.

## Dependencies

- Blog section (completed) — needed for What's New strip

## Implementation Notes

- **Modified files:**
  - `website/src/pages/index.astro` — new section order and composition
  - `website/src/components/Hero.astro` — split layout redesign
  - `website/src/components/FeaturesSection.astro` — two-column Free vs Pro
  - `website/src/components/ShowcaseSection.astro` — wider container
  - `website/src/components/InstallSection.astro` — simplified centered block
  - `website/src/components/Navbar.astro` — add waitlist CTA
  - `website/src/components/Footer.astro` — updated links
  - `website/src/styles/global.css` — tighter spacing variables if needed
- **New files:**
  - `website/src/components/PlatformSection.astro` — SaaS preview + waitlist
  - `website/src/components/WhatsNew.astro` — latest blog post strip
  - `website/src/content/platform.ts` — platform feature card data
- **Removed files:**
  - `website/src/components/SourcesSection.astro` — folded into hero badge strip
- Keep all existing component APIs (TerminalWindow, TabbedPanel, etc.)
- Waitlist form: simple email input with submit button, no backend yet (can use Formspree, Buttondown, or just a mailto: link as placeholder)

## Documentation Updates

- **Website**: This IS the website update
- **README.md**: No changes needed
