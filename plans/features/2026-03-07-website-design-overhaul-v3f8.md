---
name: Website Design Overhaul
description: Transform the vulnex website from a generic developer template into a distinctive, branded experience with custom typography, cyan/teal color palette, dot grid atmosphere, scroll animations, and layout variety.
date: 2026-03-07
status: completed
---

# Website Design Overhaul

## Description

Overhaul the vulnex website's visual identity to move away from the current generic GitHub-inspired template aesthetic. The redesign introduces:

1. **Cyan/teal + near-black color palette** replacing the overused purple-on-dark scheme
2. **Satoshi typeface** replacing the system font stack for a distinctive geometric identity
3. **Dot grid background pattern** in the hero area for a radar/threat-detection atmosphere
4. **Scroll-triggered animations** with staggered fade-in reveals across all sections
5. **Layout rhythm breaking** so sections don't all follow the same centered pattern
6. **Terminal enhancements** including a blinking cursor and subtle glow on the hero terminal
7. **Feature card redesign** with colored left borders instead of generic icon circles
8. **Footer upgrade** with logo, darker background, and closing CTA

## User Stories

1. As a visitor, I want the site to feel visually distinct so I remember vulnex among other CLI tools.
2. As a visitor, I want subtle animations on scroll so the page feels alive and modern.
3. As a visitor, I want the terminal demos to feel immersive so I can imagine using vulnex myself.
4. As a developer, I want the color palette to evoke security/terminal culture so the tool feels credible.

## Acceptance Criteria

### Color Palette (cyan/teal + near-black)
- [x] Replace `--accent: #8B5CF6` (purple) with cyan `#06B6D4`
- [x] Update `--accent-hover` (#0891B2) and `--accent-glow` (#67E8F9)
- [x] Update `--icon-bg` to use teal-tinted transparency
- [x] Update light theme accent colors (#0891B2, #0E7490, #06B6D4)
- [x] Update terminal syntax colors: `.t-green`, `.t-accent` to #06B6D4
- [x] Update `.t-prompt`, `.t-value`, `.y-key` to #67E8F9
- [x] All interactive states inherit via CSS vars
- [x] Dark bg shifted to #0a0f14 for deeper near-black

### Typography (Satoshi)
- [x] Add Satoshi font via Fontshare CDN in `BaseLayout.astro`
- [x] Update `body` font-family to `"Satoshi", sans-serif`
- [x] `--font-mono` unchanged for terminal/code contexts

### Background Atmosphere (dot grid)
- [x] Added `.hero-dots` div with `radial-gradient` repeating 1px dots at 28px spacing
- [x] Opacity via `--dot-color` CSS var (~0.10 dark, ~0.12 light)
- [x] Masked with radial-gradient ellipse fade for organic edge falloff
- [x] Works in both light and dark themes via CSS vars

### Scroll Animations
- [x] Added `IntersectionObserver` in `BaseLayout.astro` for `.reveal` elements
- [x] Staggered `.reveal-child` elements with 80ms delay per child
- [x] `prefers-reduced-motion` media query disables all transitions
- [x] Pure CSS transitions, no JS animation libraries

### Layout Rhythm Breaking
- [x] Install section uses split grid layout (text left, terminal right)
- [x] Hero terminal overlaps next section with negative margin-bottom
- [x] Sources section retains grid but with staggered child reveals for visual variety

### Terminal Enhancements
- [x] Blinking cursor (`_`) at prompt line in hero terminal
- [x] Teal-tinted box-shadow glow on hero terminal window
- [x] CSS `@keyframes blink` animation for cursor

### Feature Cards Redesign
- [x] Replaced circular icon bg with 3px colored left border accent
- [x] Added hover lift effect (translateY -2px) with box-shadow
- [x] Cards are `.reveal-child` for staggered entrance animation

### Footer Upgrade
- [x] Added vulnex shield SVG + wordmark
- [x] Uses `--bg-secondary` for distinct darker background
- [x] Added closing CTA: "Start securing your dependencies today" with install button
- [x] Added gradient fade transition from main content via `.footer-fade`

## Priority

**High** — The website is the first impression for the project. A distinctive visual identity directly impacts adoption and credibility.

## Dependencies

- Satoshi font availability (Google Fonts or Fontshare CDN)
- No dependency on other features; this is purely frontend/presentational

## Implementation Notes

### Files to modify:
- `website/src/styles/global.css` — color variables, typography, dot grid, animation keyframes
- `website/src/layouts/BaseLayout.astro` — font import
- `website/src/components/Hero.astro` — dot grid background, terminal glow, blinking cursor
- `website/src/components/Navbar.astro` — accent color updates (inherited via CSS vars)
- `website/src/components/FeatureCard.astro` — left border, hover effects
- `website/src/components/FeaturesSection.astro` — scroll animation classes, possible layout change
- `website/src/components/SourcesSection.astro` — layout variation
- `website/src/components/InstallSection.astro` — possible split layout
- `website/src/components/ShowcaseSection.astro` — scroll animation
- `website/src/components/CiCdSection.astro` — scroll animation
- `website/src/components/TerminalWindow.astro` — optional CRT/glow styles
- `website/src/components/Footer.astro` — logo, CTA, darker background
- `website/src/components/TabbedPanel.astro` — active tab color (inherited via CSS vars)

### Files NOT modified:
- `website/src/components/SearchDialog.astro` — colors inherited via CSS vars, no structural changes
- `website/src/components/DocsSidebar.astro` — docs layout unchanged
- `website/src/layouts/DocsLayout.astro` — docs layout unchanged

## Testing

Run these commands to verify the feature:

```bash
# Build the website (should complete without errors)
cd website && npx astro build

# Start the dev server and visually inspect
cd website && npx astro dev

# Check these in the browser:
# 1. Homepage: cyan/teal accent color throughout (not purple)
# 2. Hero: dot grid pattern visible behind heading, blinking cursor in terminal
# 3. Hero terminal: subtle teal glow shadow
# 4. Scroll down: sections fade in as they enter viewport
# 5. Feature cards: teal left border, lift on hover
# 6. Source cards: stagger in one by one
# 7. Install section: split layout (text left, terminal right)
# 8. Footer: darker background, vulnex logo, CTA button
# 9. Toggle light/dark theme: all colors adapt correctly
# 10. Resize to mobile: split layout stacks, responsive works
# 11. Docs pages: accent color is teal, Satoshi font applied
# 12. Search dialog (Cmd+K): accent colors are teal
```

## Documentation Updates

- No docs page changes required — this is a visual-only change
- README.md does not need updates — no functional changes
