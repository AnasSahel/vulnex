# App Cleanup & Redesign — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove unused pages (Watchlist, Exploits, SBOM Scans), strip placeholder UI, and apply a cleaner visual aesthetic inspired by viteplus.dev while keeping the red accent and light/dark themes.

**Architecture:** Three phases — (1) delete dead pages & sidebar links, (2) update CSS variables and global theme for cleaner aesthetic, (3) refine individual components. Each phase ends with a visual check and commit.

**Tech Stack:** Next.js 16, React 19, Tailwind CSS 4, shadcn/ui (@base-ui/react), CSS custom properties for theming.

---

### Task 1: Remove Watchlist, Exploits, and SBOM pages

**Files:**
- Delete: `app/src/app/dashboard/watchlist/` (entire directory)
- Delete: `app/src/app/dashboard/exploits/` (entire directory)
- Delete: `app/src/app/dashboard/sbom/page.tsx`
- Modify: `app/src/components/app-sidebar.tsx:40-44`

**Step 1: Delete the page directories and files**

```bash
rm -rf app/src/app/dashboard/watchlist
rm -rf app/src/app/dashboard/exploits
rm app/src/app/dashboard/sbom/page.tsx
rmdir app/src/app/dashboard/sbom 2>/dev/null || true
```

**Step 2: Remove Watchlist and Exploits from sidebar navigation**

In `app/src/components/app-sidebar.tsx`, change the `mainNav` array from:

```tsx
const mainNav = [
  { title: "Overview", href: "/dashboard", icon: LayoutDashboard },
  { title: "Products", href: "/dashboard/products", icon: FolderOpen },
  { title: "Watchlist", href: "/dashboard/watchlist", icon: Eye },
  { title: "Exploits", href: "/dashboard/exploits", icon: Zap },
];
```

To:

```tsx
const mainNav = [
  { title: "Overview", href: "/dashboard", icon: LayoutDashboard },
  { title: "Products", href: "/dashboard/products", icon: FolderOpen },
];
```

Also remove the unused icon imports `Eye` and `Zap` from the lucide-react import statement (line 8-9).

**Step 3: Verify the app compiles**

Run: `cd app && npx next build --no-lint 2>&1 | tail -20`

Expected: Build succeeds. No broken imports.

**Step 4: Commit**

```bash
git add -A app/src/app/dashboard/watchlist app/src/app/dashboard/exploits app/src/app/dashboard/sbom app/src/components/app-sidebar.tsx
git commit -m "refactor(app): remove Watchlist, Exploits, and SBOM pages

Products are now the single container for tracking CVEs.
Watchlist is replaced by creating a product.
Exploits feed was empty with no data pipeline.
SBOM upload remains as a product-level action."
```

---

### Task 2: Remove placeholder icons from top bar

**Files:**
- Modify: `app/src/app/dashboard/layout.tsx:1,36-46`

**Step 1: Remove the Bell icon button and its import**

In `app/src/app/dashboard/layout.tsx`:

Remove the `Bell` import from line 1:

```tsx
import { Bell } from "lucide-react";
```

Remove the Button import since only the Bell button uses it (check if SyncButton uses it — no, SyncButton is its own component):

```tsx
import { Button } from "@/components/ui/button";
```

Change the top-bar actions div (lines 36-46) from:

```tsx
          <div className="ml-auto flex items-center gap-1">
            <SyncButton />
            <ThemeToggle />
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 text-text-dim hover:text-foreground hover:bg-surface-overlay"
            >
              <Bell className="h-4 w-4" />
            </Button>
          </div>
```

To:

```tsx
          <div className="ml-auto flex items-center gap-1">
            <SyncButton />
            <ThemeToggle />
          </div>
```

**Step 2: Verify the app compiles**

Run: `cd app && npx next build --no-lint 2>&1 | tail -20`

Expected: Build succeeds.

**Step 3: Commit**

```bash
git add app/src/app/dashboard/layout.tsx
git commit -m "refactor(app): remove placeholder bell icon from top bar"
```

---

### Task 3: Update CSS theme variables for cleaner aesthetic

**Files:**
- Modify: `app/src/app/globals.css`

The goal is to improve contrast, refine spacing feel, and adopt a cleaner look. The changes are purely to CSS custom properties — no component changes yet.

**Step 1: Update light theme variables**

In `app/src/app/globals.css`, replace the light theme `:root` block (lines 67-119) with:

```css
/* ─── Light theme (default) ─── */
:root {
  --background: #fafafa;
  --foreground: #18181b;
  --card: #ffffff;
  --card-foreground: #18181b;
  --popover: #ffffff;
  --popover-foreground: #18181b;
  --primary: #dc2626;
  --primary-foreground: #ffffff;
  --secondary: #f4f4f5;
  --secondary-foreground: #18181b;
  --muted: #f4f4f5;
  --muted-foreground: #71717a;
  --accent: #f4f4f5;
  --accent-foreground: #18181b;
  --destructive: #dc2626;
  --border: #e4e4e7;
  --input: #e4e4e7;
  --ring: #dc2626;
  --radius: 0.5rem;

  --severity-critical: #dc2626;
  --severity-high: #ea580c;
  --severity-medium: #ca8a04;
  --severity-low: #71717a;

  --status-success: #16a34a;
  --status-info: #2563eb;
  --status-purple: #7c3aed;

  --surface-raised: #ffffff;
  --surface-overlay: #f4f4f5;

  --text-dim: #71717a;
  --text-dimmer: #a1a1aa;

  --border-subtle: #e4e4e780;

  --chart-1: #dc2626;
  --chart-2: #16a34a;
  --chart-3: #ea580c;
  --chart-4: #dc2626;
  --chart-5: #7c3aed;

  --sidebar: #ffffff;
  --sidebar-foreground: #18181b;
  --sidebar-primary: #dc2626;
  --sidebar-primary-foreground: #ffffff;
  --sidebar-accent: #f4f4f5;
  --sidebar-accent-foreground: #18181b;
  --sidebar-border: #e4e4e7;
  --sidebar-ring: #dc2626;
}
```

Key changes:
- `--background`: `#f6f8fa` → `#fafafa` (warmer, less blue-tinted)
- `--foreground`: `#1f2328` → `#18181b` (deeper black, better contrast)
- `--secondary/muted/accent`: `#eaeef2` → `#f4f4f5` (neutral gray, not blue-tinted)
- `--muted-foreground`: `#656d76` → `#71717a` (zinc scale, cleaner)
- `--border`: `#d1d9e0` → `#e4e4e7` (lighter, subtler borders)
- Severity/status colors: slightly more saturated for better pop
- `--text-dim/dimmer`: aligned to zinc scale

**Step 2: Update dark theme variables**

Replace the `.dark` block (lines 122-173) with:

```css
/* ─── Dark theme ─── */
.dark {
  --background: #09090b;
  --foreground: #fafafa;
  --card: #18181b;
  --card-foreground: #fafafa;
  --popover: #18181b;
  --popover-foreground: #fafafa;
  --primary: #f87171;
  --primary-foreground: #09090b;
  --secondary: #27272a;
  --secondary-foreground: #fafafa;
  --muted: #27272a;
  --muted-foreground: #a1a1aa;
  --accent: #27272a;
  --accent-foreground: #fafafa;
  --destructive: #ef4444;
  --border: #27272a;
  --input: #27272a;
  --ring: #f87171;

  --severity-critical: #ef4444;
  --severity-high: #f97316;
  --severity-medium: #eab308;
  --severity-low: #a1a1aa;

  --status-success: #22c55e;
  --status-info: #3b82f6;
  --status-purple: #a78bfa;

  --surface-raised: #18181b;
  --surface-overlay: #27272a;

  --text-dim: #a1a1aa;
  --text-dimmer: #52525b;

  --border-subtle: #27272a80;

  --chart-1: #f87171;
  --chart-2: #22c55e;
  --chart-3: #f97316;
  --chart-4: #ef4444;
  --chart-5: #a78bfa;

  --sidebar: #18181b;
  --sidebar-foreground: #fafafa;
  --sidebar-primary: #f87171;
  --sidebar-primary-foreground: #09090b;
  --sidebar-accent: #27272a;
  --sidebar-accent-foreground: #fafafa;
  --sidebar-border: #27272a;
  --sidebar-ring: #f87171;
}
```

Key changes:
- `--background`: `#0d1117` → `#09090b` (true dark, zinc scale)
- `--foreground`: `#e6edf3` → `#fafafa` (brighter text, better contrast)
- `--card`: `#161b22` → `#18181b` (zinc, not blue-tinted)
- `--secondary/muted/accent`: `#1c2129` → `#27272a` (neutral)
- `--border`: `#30363d` → `#27272a` (subtler)
- All colors aligned to Tailwind zinc scale for consistency

**Step 3: Verify the app compiles and renders**

Run: `cd app && npx next build --no-lint 2>&1 | tail -20`

Expected: Build succeeds. Open http://localhost:3000/dashboard — verify light and dark themes both look cleaner with better contrast.

**Step 4: Commit**

```bash
git add app/src/app/globals.css
git commit -m "style(app): update theme to zinc-based palette for cleaner contrast

Light theme: warmer neutral grays, less blue tint, deeper foreground.
Dark theme: true dark zinc scale, brighter text, neutral card colors.
Red accent preserved. Both themes have improved contrast ratios."
```

---

### Task 4: Refine dashboard layout — spacing, max-width, top bar

**Files:**
- Modify: `app/src/app/dashboard/layout.tsx`
- Modify: `app/src/app/dashboard/overview-client.tsx`

**Step 1: Update dashboard layout with better spacing and refined top bar**

Replace the full content of `app/src/app/dashboard/layout.tsx` with:

```tsx
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { Separator } from "@/components/ui/separator";
import { AppSidebar } from "@/components/app-sidebar";
import { ThemeToggle } from "@/components/theme-toggle";
import { SyncButton } from "@/components/dashboard/sync-button";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <header className="sticky top-0 z-50 flex h-14 shrink-0 items-center gap-2 border-b border-border bg-background/80 backdrop-blur-xl px-4">
          <SidebarTrigger className="-ml-1 text-muted-foreground hover:text-foreground" />
          <Separator orientation="vertical" className="mr-2 !h-4" />

          <div className="flex items-center gap-1.5 rounded-full bg-secondary px-2.5 py-1 border border-border">
            <span className="h-1.5 w-1.5 rounded-full bg-status-success animate-pulse-dot" />
            <span className="hidden sm:inline text-[11px] font-medium text-status-success">
              All sources online
            </span>
          </div>

          <div className="ml-auto flex items-center gap-1">
            <SyncButton />
            <ThemeToggle />
          </div>
        </header>

        <main className="flex-1 px-6 py-8 sm:px-8 lg:px-12">{children}</main>
      </SidebarInset>
    </SidebarProvider>
  );
}
```

Changes:
- Removed gradient top line (visual noise)
- Simplified color classes: `border-border-subtle` → `border-border`, `bg-surface-overlay` → `bg-secondary`
- Increased main content padding: `px-4 py-8 sm:px-6` → `px-6 py-8 sm:px-8 lg:px-12`
- Removed Bell button and its imports

**Step 2: Add max-width constraint to overview page**

In `app/src/app/dashboard/overview-client.tsx`, change the root div from:

```tsx
    <div className="space-y-8">
```

To:

```tsx
    <div className="space-y-8 max-w-6xl">
```

**Step 3: Verify layout looks correct**

Run: `cd app && npx next dev &` then open http://localhost:3000/dashboard

Expected: More breathing room around content. Top bar is simpler. Content doesn't stretch edge-to-edge on wide screens.

**Step 4: Commit**

```bash
git add app/src/app/dashboard/layout.tsx app/src/app/dashboard/overview-client.tsx
git commit -m "style(app): refine dashboard layout with better spacing and simpler top bar"
```

---

### Task 5: Refine priority strip and section headers

**Files:**
- Modify: `app/src/components/dashboard/priority-strip.tsx`
- Modify: `app/src/components/dashboard/section-header.tsx`

**Step 1: Update PriorityStrip with pill-style badges**

Replace the full content of `app/src/components/dashboard/priority-strip.tsx` with:

```tsx
"use client";

const levels = [
  { key: "p0", label: "P0", color: "var(--severity-critical)" },
  { key: "p1", label: "P1", color: "var(--severity-high)" },
  { key: "p2", label: "P2", color: "var(--severity-medium)" },
  { key: "p3", label: "P3", color: "var(--severity-low)" },
  { key: "p4", label: "P4", color: "var(--text-dimmer)" },
] as const;

export function PriorityStrip({
  counts,
}: {
  counts: { p0: number; p1: number; p2: number; p3: number; p4: number };
}) {
  return (
    <div className="flex items-center gap-2 flex-wrap">
      {levels.map(({ key, label, color }) => (
        <div
          key={key}
          className="flex items-center gap-1.5 rounded-full border border-border px-3 py-1.5"
        >
          <span
            className="inline-block h-1.5 w-1.5 rounded-full"
            style={{ backgroundColor: color }}
          />
          <span className="text-xs font-medium text-muted-foreground">
            {label}
          </span>
          <span
            className="text-sm font-semibold tabular-nums"
            style={{ color }}
          >
            {counts[key]}
          </span>
        </div>
      ))}
    </div>
  );
}
```

Changes:
- `rounded-md` → `rounded-full` (pill shape)
- `bg-surface-raised` removed (transparent background, border only)
- `border-border-subtle` → `border-border` (slightly more visible)
- Dot size: `h-2 w-2` → `h-1.5 w-1.5` (subtler)
- Font: `text-[11px] font-semibold text-text-dim` → `text-xs font-medium text-muted-foreground`
- Count: `font-bold` → `font-semibold`

**Step 2: Simplify SectionHeader**

Replace the full content of `app/src/components/dashboard/section-header.tsx` with:

```tsx
export function SectionHeader({
  title,
  count,
  countLabel,
}: {
  title: string;
  count?: number;
  countLabel?: string;
}) {
  return (
    <div className="flex items-center gap-3">
      <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
        {title}
      </h2>
      <div className="flex-1 h-px bg-border" />
      {count != null && (
        <span className="text-xs text-muted-foreground tabular-nums">
          {count} {countLabel ?? ""}
        </span>
      )}
    </div>
  );
}
```

Changes:
- `text-text-dim` → `text-muted-foreground` (standard Tailwind/shadcn)
- `tracking-widest` → `tracking-wider` (less extreme)
- `text-[11px]` → `text-xs` (standard scale)
- `gap-2` → `gap-3`
- Gradient divider → solid `bg-border` (cleaner)
- Count: `text-[11px]` → `text-xs`

**Step 3: Verify**

Open http://localhost:3000/dashboard — priority strip should now show pill-shaped badges, section headers should look cleaner.

**Step 4: Commit**

```bash
git add app/src/components/dashboard/priority-strip.tsx app/src/components/dashboard/section-header.tsx
git commit -m "style(app): refine priority strip to pills and simplify section headers"
```

---

### Task 6: Refine product list and activity feed

**Files:**
- Modify: `app/src/components/dashboard/product-list.tsx`
- Modify: `app/src/components/dashboard/activity-feed.tsx`

**Step 1: Update ProductList styling**

In `app/src/components/dashboard/product-list.tsx`, make these changes:

Change the container div (line 95):

```tsx
      <div className="rounded-lg border border-border-subtle bg-surface-raised overflow-hidden">
```

To:

```tsx
      <div className="rounded-lg border border-border overflow-hidden">
```

Change each product link row (line 102):

```tsx
              className={`flex items-center gap-3 px-4 py-3 transition-colors hover:bg-surface-overlay ${
                idx !== products.length - 1
                  ? "border-b border-border/30"
                  : ""
              }`}
```

To:

```tsx
              className={`flex items-center gap-3 px-4 py-3.5 transition-colors hover:bg-secondary ${
                idx !== products.length - 1
                  ? "border-b border-border"
                  : ""
              }`}
```

Also update the empty-state container (line 95 in the empty branch) similarly.

Do the same for the empty-state container at the ProductList empty case — no change needed there as it uses EmptyState.

**Step 2: Update ActivityFeed styling**

In `app/src/components/dashboard/activity-feed.tsx`, change the container (line 11):

```tsx
      <div className="rounded-lg border border-border-subtle bg-surface-raised overflow-hidden">
```

To:

```tsx
      <div className="rounded-lg border border-border overflow-hidden">
```

Change each alert row (line 20):

```tsx
              className={`flex items-start gap-2.5 px-4 py-2.5 transition-colors hover:bg-surface-overlay ${
                idx !== alerts.length - 1 ? "border-b border-border/30" : ""
              }`}
```

To:

```tsx
              className={`flex items-start gap-2.5 px-4 py-3 transition-colors hover:bg-secondary ${
                idx !== alerts.length - 1 ? "border-b border-border" : ""
              }`}
```

**Step 3: Verify**

Open http://localhost:3000/dashboard — product rows should have slightly more padding, cleaner borders, and a subtle hover background.

**Step 4: Commit**

```bash
git add app/src/components/dashboard/product-list.tsx app/src/components/dashboard/activity-feed.tsx
git commit -m "style(app): refine product list and activity feed borders and spacing"
```

---

### Task 7: Refine CVE table

**Files:**
- Modify: `app/src/components/dashboard/cve-table.tsx`

**Step 1: Update table container and row styling**

In `app/src/components/dashboard/cve-table.tsx`:

Change the container (line 149):

```tsx
      <div className="rounded-lg border border-border-subtle bg-surface-raised overflow-hidden overflow-x-auto">
```

To:

```tsx
      <div className="rounded-lg border border-border overflow-hidden overflow-x-auto">
```

Change the header row (line 152):

```tsx
            <TableRow className="border-border/30 hover:bg-transparent">
```

To:

```tsx
            <TableRow className="border-border hover:bg-transparent">
```

Change the data rows (line 209):

```tsx
                  className="border-border/20 hover:bg-surface-overlay transition-colors"
```

To:

```tsx
                  className="border-border hover:bg-secondary transition-colors"
```

Change the pagination container (line 245):

```tsx
          <div className="flex items-center justify-between px-4 py-3 border-t border-border-subtle">
```

To:

```tsx
          <div className="flex items-center justify-between px-4 py-3 border-t border-border">
```

**Step 2: Update the `thClass` variable (line 139)**

From:

```tsx
  const thClass =
    "text-[11px] font-semibold text-text-dim uppercase tracking-wider cursor-pointer select-none hover:text-foreground transition-colors";
```

To:

```tsx
  const thClass =
    "text-[11px] font-semibold text-muted-foreground uppercase tracking-wider cursor-pointer select-none hover:text-foreground transition-colors";
```

Also update the non-sortable `TableHead` elements (lines 153, 156, 177) — change `text-text-dim` to `text-muted-foreground`.

**Step 3: Verify**

Open http://localhost:3000/dashboard/products/{id} — table should have consistent, visible borders without the partial-opacity look.

**Step 4: Commit**

```bash
git add app/src/components/dashboard/cve-table.tsx
git commit -m "style(app): refine CVE table borders, hover states, and header styling"
```

---

### Task 8: Refine CVE detail page

**Files:**
- Modify: `app/src/app/dashboard/cve/[id]/cve-detail-client.tsx`

**Step 1: Update card dividers and text colors**

In `app/src/app/dashboard/cve/[id]/cve-detail-client.tsx`:

Change all `border-border/30` dividers (lines 125, 156) to `border-border`:

```tsx
              <div className="border-t border-border/30" />
```

→

```tsx
              <div className="border-t border-border" />
```

Change `text-text-dim` to `text-muted-foreground` and `text-text-dimmer` to `text-muted-foreground/60` throughout the file. Specifically:

- Line 51: `text-text-dim` → `text-muted-foreground`
- Line 69: `text-text-dim` → `text-muted-foreground`
- Line 79: `text-text-dim` → `text-muted-foreground`
- Lines 94, 129, 160: `text-text-dim` → `text-muted-foreground`
- Line 118: `text-text-dimmer` → `text-muted-foreground/60`
- Lines 207, 216-217, 272: `text-text-dimmer` → `text-muted-foreground/60`
- Lines 174, 176, 180, 182: `text-text-dim` → `text-muted-foreground`

**Step 2: Add max-width to the page**

Change the root div (line 47):

```tsx
    <div className="space-y-6">
```

To:

```tsx
    <div className="space-y-6 max-w-6xl">
```

**Step 3: Verify**

Open http://localhost:3000/dashboard/cve/CVE-2018-25159 — cleaner dividers, consistent text colors.

**Step 4: Commit**

```bash
git add app/src/app/dashboard/cve/[id]/cve-detail-client.tsx
git commit -m "style(app): refine CVE detail page dividers, text colors, and max-width"
```

---

### Task 9: Refine product detail page

**Files:**
- Modify: `app/src/app/dashboard/products/[id]/product-detail-client.tsx`

**Step 1: Update text color classes**

In `app/src/app/dashboard/products/[id]/product-detail-client.tsx`:

Change `text-text-dim` to `text-muted-foreground` on:
- Line 51: back link
- Line 62: source/date info

**Step 2: Add max-width**

Change the root div (line 47):

```tsx
    <div className="space-y-8">
```

To:

```tsx
    <div className="space-y-8 max-w-6xl">
```

**Step 3: Verify**

Open http://localhost:3000/dashboard/products/{id} — consistent with overview page styling.

**Step 4: Commit**

```bash
git add app/src/app/dashboard/products/[id]/product-detail-client.tsx
git commit -m "style(app): refine product detail page text colors and max-width"
```

---

### Task 10: Refine settings page

**Files:**
- Modify: `app/src/app/dashboard/settings/page.tsx`

**Step 1: Standardize card styling**

In `app/src/app/dashboard/settings/page.tsx`:

Change all card classes from:

```tsx
        <Card className="mt-4 border-border-subtle bg-surface-raised ring-0">
```

To:

```tsx
        <Card className="mt-4 border-border ring-0">
```

(There are 3 regular cards + 1 danger zone card. The danger zone card keeps its `border-destructive/30`.)

Change `text-text-dim` to `text-muted-foreground` throughout:
- Lines 37, 43, 74, 87, 107, 108, 136: `text-text-dim` → `text-muted-foreground`

Change `bg-border-subtle` separators:

```tsx
            <Separator className="bg-border-subtle" />
```

To:

```tsx
            <Separator className="bg-border" />
```

Change input styling (line 46):

```tsx
                  className="bg-background border-border-subtle focus-visible:ring-primary/30 focus-visible:border-primary/50"
```

To:

```tsx
                  className="bg-background border-border focus-visible:ring-primary/30 focus-visible:border-primary/50"
```

And the disabled input (line 54):

```tsx
                  className="bg-background border-border-subtle"
```

To:

```tsx
                  className="bg-background border-border"
```

Change the outline button (line 116):

```tsx
            <Button variant="outline" className="border-border-subtle text-text-dim hover:text-foreground hover:bg-surface-overlay">
```

To:

```tsx
            <Button variant="outline" className="border-border text-muted-foreground hover:text-foreground hover:bg-secondary">
```

**Step 2: Verify**

Open http://localhost:3000/dashboard/settings — cards should have consistent border styling.

**Step 3: Commit**

```bash
git add app/src/app/dashboard/settings/page.tsx
git commit -m "style(app): refine settings page card borders and text colors"
```

---

### Task 11: Final cleanup — remove dead CSS utilities and verify

**Files:**
- Modify: `app/src/app/globals.css` (optional cleanup)

**Step 1: Check for any remaining references to removed custom properties**

Run: `cd app && grep -r "text-text-dim\|text-text-dimmer\|bg-surface-raised\|bg-surface-overlay\|border-border-subtle" src/ --include="*.tsx" --include="*.ts" -l`

For any remaining files, update:
- `text-text-dim` → `text-muted-foreground`
- `text-text-dimmer` → `text-muted-foreground/60`
- `bg-surface-raised` → remove (use default or `bg-card`)
- `bg-surface-overlay` → `bg-secondary`
- `border-border-subtle` → `border-border`

Note: Do NOT remove the CSS custom properties themselves from globals.css yet — some components may use them via inline `style={}` props (like severity colors). Only rename the Tailwind utility usage.

**Step 2: Full build check**

Run: `cd app && npx next build --no-lint 2>&1 | tail -20`

Expected: Build succeeds with no errors.

**Step 3: Visual verification**

Open each page and verify in both light and dark mode:
- http://localhost:3000/dashboard (Overview)
- http://localhost:3000/dashboard/products/{id} (Product detail)
- http://localhost:3000/dashboard/cve/CVE-2018-25159 (CVE detail)
- http://localhost:3000/dashboard/settings (Settings)

Check:
- [ ] No broken layouts
- [ ] Priority strip shows pill badges
- [ ] Tables have consistent borders
- [ ] Cards have subtle borders, no heavy shadows
- [ ] Light theme has good contrast (not washed out)
- [ ] Dark theme is deep and clean
- [ ] Sidebar shows only Overview + Products
- [ ] Top bar has no bell icon
- [ ] Navigating to /dashboard/watchlist returns 404

**Step 4: Commit**

```bash
git add -A app/src/
git commit -m "style(app): final cleanup of legacy color utilities"
```
