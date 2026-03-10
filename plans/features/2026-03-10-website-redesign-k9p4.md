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
2. What's New (latest blog post inline strip)
3. Sources Flow (animated aggregation diagram: 5 sources → vulnex → 4 outputs)
4. Showcase (tabbed terminal demos, full-width)
5. Platform Preview (SaaS pitch + waitlist email capture)
6. Features (compact grouped list: Free CLI vs Pro Platform)
7. Install (single centered tabbed code block)
8. CI/CD (pipeline integration examples)
9. Footer (clean link bar)

**Visual direction:**
- Monochrome black & white palette with **red (#ef4444 dark / #dc2626 light) as the single accent color**
- Grain texture overlay via `PageBackground.astro` (SVG fractalNoise, shared across all pages)
- No cyan, teal, or blue anywhere — terminal syntax colors remapped to red/white/grey
- Alternating section backgrounds (`--bg` / `--bg-secondary`) with border separators for visual rhythm

**Hero:**
- Split layout: tagline + sub + two CTAs on left, terminal on right
- CTAs: "Install CLI" (primary red), "Join Waitlist" (secondary outline)
- Badge strip below: source abbreviations (NVD, KEV, EPSS, GHSA, OSV) in neutral grey pills
- Terminal shows `cve get` output with red-accent syntax highlighting

**What's New:**
- Minimal inline strip (no card/box) — centered row: "New" tag + title + date + arrow
- Sits directly after hero with tight spacing

**Sources Flow (NEW):**
- Animated aggregation diagram showing data flow: 5 intelligence sources → vulnex hub → 4 outputs
- Three-column grid: source nodes (right-aligned) | SVG connectors + center hub | output nodes (left-aligned)
- Center hub: red rounded square with icon + "vulnex" label, pulsing concentric rings
- Animated red dots flowing along cubic bezier SVG paths between nodes and hub
- Column headers: "Intelligence Sources" / "Actionable Output"
- Nodes: icon + label + subtitle cards with red hover states
- Mobile: stacks vertically, SVG paths hidden

**Showcase:**
- Tabbed demos at wider width (880px)
- Same demo data, better visual prominence

**Platform Preview:**
- Grid of 4 preview cards: Dashboard, Team Alerts, Scheduled Scans, REST API
- Each card: icon, title, short description
- Waitlist email capture form below the cards
- Subtle accent-tinted gradient background

**Features:**
- Two-column layout: Free (CLI) on left, Pro (Platform) on right
- Compact list items with checkmark icons, not card grid

**Install:**
- Single centered tabbed terminal (brew / go / binary)
- No explanatory text column — the code IS the explanation
- Copy button on each tab

**Navigation:**
- Clean split: Docs + Blog links on left, dual CTAs on right ("Install" outlined + "Join Waitlist" filled red)
- Backdrop blur nav with border-bottom

## User Stories

1. As a developer, I want to see the CLI in action immediately so I can decide if it's worth installing.
2. As a security team lead, I want to understand the SaaS platform offering so I can evaluate it for my team.
3. As a potential customer, I want to join a waitlist so I'm notified when the platform launches.
4. As a visitor, I want to see that the project is active and maintained.

## Acceptance Criteria

- [x] Hero: split layout with copy left, terminal right, two CTAs
- [x] Hero: source badge strip (NVD, KEV, EPSS, GHSA, OSV)
- [x] Showcase section with wider container (880px)
- [x] New Platform Preview section with 4 feature cards and email waitlist form
- [x] Features section: two-column Free vs Pro comparison list
- [x] Install section: single centered tabbed code block
- [x] What's New section: minimal inline strip after hero
- [x] Sources Flow section: animated aggregation diagram (5 sources → vulnex → 4 outputs) with SVG connectors and flowing dot animation
- [x] Navbar: clean split with only Docs/Blog links, dual CTAs ("Install" outlined + "Join Waitlist" filled), removed landing page anchor links
- [x] Footer: updated with Blog link, removed redundant CTA
- [x] Monochrome B&W palette with red (#ef4444/#dc2626) as single accent color — no cyan/teal/blue
- [x] Grain texture background via PageBackground.astro (shared across all pages including blog and docs)
- [x] Terminal syntax colors remapped to red/white/grey (no cyan)
- [x] `cd website && npm run build` succeeds
- [x] Responsive at 900px, 768px, and 600px breakpoints

## Priority

**High** — The website is the primary conversion surface for both CLI adoption and SaaS demand capture.

## Dependencies

- Blog section (completed) — needed for What's New strip

## Implementation Notes

- **Modified files:**
  - `website/src/pages/index.astro` — new section order and composition
  - `website/src/components/Hero.astro` — split layout redesign, red accent, no cyan
  - `website/src/components/FeaturesSection.astro` — two-column Free vs Pro
  - `website/src/components/ShowcaseSection.astro` — wider container, alternating bg
  - `website/src/components/InstallSection.astro` — simplified centered block, alternating bg
  - `website/src/components/CiCdSection.astro` — alternating bg
  - `website/src/components/Navbar.astro` — clean split with dual CTAs
  - `website/src/components/Footer.astro` — updated links
  - `website/src/components/PageBackground.astro` — grain texture (SVG fractalNoise data URI)
  - `website/src/styles/global.css` — B&W + red palette, terminal syntax remapping, no cyan
  - `website/src/layouts/DocsLayout.astro` — added PageBackground
- **New files:**
  - `website/src/components/PlatformSection.astro` — SaaS preview + waitlist
  - `website/src/components/WhatsNew.astro` — minimal latest blog post strip
  - `website/src/components/SourcesFlow.astro` — animated aggregation flow diagram
  - `website/src/content/platform.ts` — platform feature card data
- **Removed files:**
  - `website/src/components/SourcesSection.astro` — replaced by hero badge strip + SourcesFlow diagram
- Keep all existing component APIs (TerminalWindow, TabbedPanel, etc.)
- Waitlist form: simple email input with submit button (Formspree placeholder)

## Documentation Updates

- **Website**: This IS the website update
- **README.md**: No changes needed
