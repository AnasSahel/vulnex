# Dashboard Redesign Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Restructure the vulnex.cloud dashboard from a flat CVE dump to a project-centric, priority-first interface with the vulnex red brand identity.

**Architecture:** Replace the single-page dashboard with a three-level hierarchy (overview → project → CVE detail). Add a `project` table to the database. Rewrite queries to be project-scoped. Swap all blue accent CSS variables to vulnex red.

**Tech Stack:** Next.js 15 (App Router, Server Components), Drizzle ORM, shadcn/ui, Tailwind CSS, @vulnex/db shared package.

---

### Task 1: Swap Brand Colors — Blue to Red

Replace all GitHub-blue accent values with vulnex red. This is a CSS-only change that touches one file.

**Files:**
- Modify: `app/src/app/globals.css`

**Step 1: Replace light theme blue variables**

In `globals.css`, find the `:root` block and change:

```css
/* FROM */
--primary: #0969da;
--ring: #0969da;
--status-info: #0969da;
--chart-1: #0969da;
--sidebar-primary: #0969da;
--sidebar-ring: #0969da;

/* TO */
--primary: #dc2626;
--ring: #dc2626;
--status-info: #0969da;  /* keep — info is semantically blue */
--chart-1: #dc2626;
--sidebar-primary: #dc2626;
--sidebar-ring: #dc2626;
```

**Step 2: Replace dark theme blue variables**

In the `.dark` block, change:

```css
/* FROM */
--primary: #58a6ff;
--ring: #58a6ff;
--status-info: #58a6ff;
--chart-1: #58a6ff;
--sidebar-primary: #58a6ff;
--sidebar-ring: #58a6ff;

/* TO */
--primary: #f87171;
--ring: #f87171;
--status-info: #58a6ff;  /* keep */
--chart-1: #f87171;
--sidebar-primary: #f87171;
--sidebar-ring: #f87171;
```

**Step 3: Verify visually**

Run: `cd app && bun run dev`
Check: sidebar active items, buttons, CVE ID links, and sync button should all be red now.

**Step 4: Build check**

Run: `cd app && bun run build`
Expected: build succeeds, no errors.

**Step 5: Commit**

```
git add app/src/app/globals.css
git commit -m "style(app): replace blue accent with vulnex red brand identity"
```

---

### Task 2: Add Project Table to Database Schema

Add a `project` table and a `project_cve` join table to the shared DB package, then push to Neon.

**Files:**
- Modify: `packages/db/src/schema.ts`

**Step 1: Add project and project_cve tables**

Add after the `watchlist` table definition in `packages/db/src/schema.ts`:

```typescript
export const project = pgTable("project", {
  id: text("id").primaryKey(), // nanoid
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  source: text("source").notNull().default("manual"), // "cli", "sbom", "manual"
  lastScannedAt: timestamp("last_scanned_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
}, (t) => [
  index("project_user_id_idx").on(t.userId),
]);

export const projectCve = pgTable("project_cve", {
  id: serial("id").primaryKey(),
  projectId: text("project_id")
    .notNull()
    .references(() => project.id, { onDelete: "cascade" }),
  cveId: text("cve_id")
    .notNull()
    .references(() => cve.id, { onDelete: "cascade" }),
  addedAt: timestamp("added_at").notNull().defaultNow(),
}, (t) => [
  unique().on(t.projectId, t.cveId),
  index("project_cve_project_id_idx").on(t.projectId),
]);
```

**Step 2: Re-export from schema**

The `packages/db/src/index.ts` already does `export * from "./schema"`, so no changes needed there.

**Step 3: Push schema to database**

Run: `cd packages/db && bunx drizzle-kit push --force`
Expected: "Changes applied"

**Step 4: Build check**

Run: `cd app && bun run build`
Expected: build succeeds.

**Step 5: Commit**

```
git add packages/db/src/schema.ts
git commit -m "feat(db): add project and project_cve tables"
```

---

### Task 3: Write Project Queries

Add query functions for projects: list, detail, risk summary, and project-scoped CVEs.

**Files:**
- Create: `app/src/lib/queries/projects.ts`
- Modify: `app/src/lib/queries.ts` (rename to `app/src/lib/queries/cves.ts` and create barrel export)

**Step 1: Restructure queries into a directory**

Create `app/src/lib/queries/` directory. Move current `queries.ts` to `queries/cves.ts`. Create `queries/index.ts` that re-exports everything:

```typescript
// app/src/lib/queries/index.ts
export * from "./cves";
export * from "./projects";
```

Update the import path `@/lib/queries` — since the barrel export at `queries/index.ts` matches, all existing imports continue to work.

**Step 2: Write project query functions**

Create `app/src/lib/queries/projects.ts`:

```typescript
import { db } from "@/lib/db";
import { project, projectCve, cve, cveScore, kevEntry } from "@/lib/db/schema";
import { eq, desc, sql, count, and, isNotNull } from "drizzle-orm";

export type ProjectSummary = {
  id: string;
  name: string;
  source: string;
  lastScannedAt: string | null;
  cveCount: number;
  p0: number;
  p1: number;
  p2: number;
  p3: number;
  p4: number;
};

export type ProjectDetail = ProjectSummary & {
  createdAt: string;
};

export async function getUserProjects(userId: string): Promise<ProjectSummary[]> {
  const rows = await db.execute(sql`
    SELECT
      p.id,
      p.name,
      p.source,
      p.last_scanned_at,
      COALESCE(stats.cve_count, 0) AS cve_count,
      COALESCE(stats.p0, 0) AS p0,
      COALESCE(stats.p1, 0) AS p1,
      COALESCE(stats.p2, 0) AS p2,
      COALESCE(stats.p3, 0) AS p3,
      COALESCE(stats.p4, 0) AS p4
    FROM project p
    LEFT JOIN LATERAL (
      SELECT
        COUNT(*)::int AS cve_count,
        COUNT(*) FILTER (WHERE priority = 'P0')::int AS p0,
        COUNT(*) FILTER (WHERE priority = 'P1')::int AS p1,
        COUNT(*) FILTER (WHERE priority = 'P2')::int AS p2,
        COUNT(*) FILTER (WHERE priority = 'P3')::int AS p3,
        COUNT(*) FILTER (WHERE priority = 'P4')::int AS p4
      FROM (
        SELECT
          pc.cve_id,
          CASE
            WHEN (EXISTS (SELECT 1 FROM kev_entry k WHERE k.cve_id = pc.cve_id))
                 AND COALESCE(cvss.cvss_v3_score, 0) >= 9.0 THEN 'P0'
            WHEN (EXISTS (SELECT 1 FROM kev_entry k WHERE k.cve_id = pc.cve_id))
                 OR (COALESCE(cvss.cvss_v3_score, 0) >= 9.0 AND COALESCE(epss.epss_score, 0) >= 0.7) THEN 'P0'
            WHEN COALESCE(cvss.cvss_v3_score, 0) >= 7.0 AND COALESCE(epss.epss_score, 0) >= 0.5 THEN 'P1'
            WHEN COALESCE(cvss.cvss_v3_score, 0) >= 7.0 OR COALESCE(epss.epss_score, 0) >= 0.4 THEN 'P2'
            WHEN COALESCE(cvss.cvss_v3_score, 0) >= 4.0 THEN 'P3'
            ELSE 'P4'
          END AS priority
        FROM project_cve pc
        LEFT JOIN LATERAL (
          SELECT cs.cvss_v3_score FROM cve_score cs
          WHERE cs.cve_id = pc.cve_id AND cs.source = 'nvd' AND cs.cvss_v3_score IS NOT NULL
          ORDER BY cs.scored_at DESC LIMIT 1
        ) cvss ON true
        LEFT JOIN LATERAL (
          SELECT cs.epss_score FROM cve_score cs
          WHERE cs.cve_id = pc.cve_id AND cs.source = 'epss' AND cs.epss_score IS NOT NULL
          ORDER BY cs.scored_at DESC LIMIT 1
        ) epss ON true
        WHERE pc.project_id = p.id
      ) enriched
    ) stats ON true
    WHERE p.user_id = ${userId}
    ORDER BY COALESCE(stats.p0, 0) DESC, COALESCE(stats.p1, 0) DESC, p.updated_at DESC
  `);

  return rows.rows.map((r: any) => ({
    id: r.id,
    name: r.name,
    source: r.source,
    lastScannedAt: r.last_scanned_at ? new Date(r.last_scanned_at).toISOString() : null,
    cveCount: r.cve_count,
    p0: r.p0,
    p1: r.p1,
    p2: r.p2,
    p3: r.p3,
    p4: r.p4,
  }));
}

export async function getProjectDetail(projectId: string): Promise<ProjectDetail | null> {
  const [row] = await db
    .select()
    .from(project)
    .where(eq(project.id, projectId))
    .limit(1);

  if (!row) return null;

  const projects = await getUserProjects(row.userId);
  const summary = projects.find((p) => p.id === projectId);
  if (!summary) return null;

  return {
    ...summary,
    createdAt: row.createdAt.toISOString(),
  };
}

export async function getGlobalPriorityCounts(userId: string) {
  const projects = await getUserProjects(userId);
  return {
    p0: projects.reduce((sum, p) => sum + p.p0, 0),
    p1: projects.reduce((sum, p) => sum + p.p1, 0),
    p2: projects.reduce((sum, p) => sum + p.p2, 0),
    p3: projects.reduce((sum, p) => sum + p.p3, 0),
    p4: projects.reduce((sum, p) => sum + p.p4, 0),
  };
}
```

**Step 3: Build check**

Run: `cd app && bun run build`
Expected: build succeeds.

**Step 4: Commit**

```
git add app/src/lib/queries/
git rm app/src/lib/queries.ts
git commit -m "feat(app): add project queries and restructure query modules"
```

---

### Task 4: Redesign Overview Page

Replace the current flat dashboard with the project-centric overview: P0–P4 priority strip + project list + activity feed.

**Files:**
- Rewrite: `app/src/app/dashboard/page.tsx`
- Rewrite: `app/src/app/dashboard/dashboard-client.tsx`
- Create: `app/src/components/dashboard/priority-strip.tsx`
- Create: `app/src/components/dashboard/project-list.tsx`
- Create: `app/src/components/dashboard/activity-feed.tsx`
- Remove: `app/src/components/dashboard/quick-actions.tsx` (search moves to project detail)
- Remove: `app/src/components/dashboard/risk-posture.tsx` (replaced by priority strip)

**Step 1: Create PriorityStrip component**

`app/src/components/dashboard/priority-strip.tsx`:

```tsx
"use client";

type PriorityCounts = { p0: number; p1: number; p2: number; p3: number; p4: number };

const priorityConfig = [
  { key: "p0", label: "P0", color: "var(--severity-critical)" },
  { key: "p1", label: "P1", color: "var(--severity-high)" },
  { key: "p2", label: "P2", color: "var(--severity-medium)" },
  { key: "p3", label: "P3", color: "var(--severity-low)" },
  { key: "p4", label: "P4", color: "var(--text-dimmer)" },
] as const;

export function PriorityStrip({ counts }: { counts: PriorityCounts }) {
  const total = counts.p0 + counts.p1 + counts.p2 + counts.p3 + counts.p4;

  return (
    <div className="flex items-center gap-3 p-3 rounded-lg bg-surface-raised border border-border-subtle">
      <span className="text-[11px] font-semibold text-text-dim uppercase tracking-wider">Risk</span>
      <div className="flex items-center gap-2">
        {priorityConfig.map(({ key, label, color }) => (
          <div
            key={key}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-surface-overlay"
          >
            <span
              className="h-2 w-2 rounded-full"
              style={{ backgroundColor: color }}
            />
            <span className="text-[12px] font-semibold" style={{ color }}>
              {label}
            </span>
            <span className="text-[12px] font-mono text-foreground">
              {counts[key]}
            </span>
          </div>
        ))}
      </div>
      <span className="ml-auto text-[12px] text-text-dim">
        {total} total
      </span>
    </div>
  );
}
```

**Step 2: Create ProjectList component**

`app/src/components/dashboard/project-list.tsx`:

```tsx
"use client";

import Link from "next/link";
import { Terminal, Upload, FolderPlus, ChevronRight } from "lucide-react";
import type { ProjectSummary } from "@/lib/queries";
import { SectionHeader } from "./section-header";
import { EmptyState } from "./empty-state";

const sourceIcons: Record<string, typeof Terminal> = {
  cli: Terminal,
  sbom: Upload,
  manual: FolderPlus,
};

const priorityColors = [
  "var(--severity-critical)",
  "var(--severity-high)",
  "var(--severity-medium)",
  "var(--severity-low)",
  "var(--text-dimmer)",
];

function MiniPriorityBar({ p0, p1, p2, p3, p4 }: { p0: number; p1: number; p2: number; p3: number; p4: number }) {
  const total = p0 + p1 + p2 + p3 + p4;
  if (total === 0) return <span className="text-[12px] text-text-dimmer">No CVEs</span>;

  const segments = [p0, p1, p2, p3, p4];
  return (
    <div className="flex items-center gap-2">
      <div className="flex h-1.5 w-24 rounded-full overflow-hidden bg-surface-overlay">
        {segments.map((count, i) => {
          const pct = (count / total) * 100;
          if (pct === 0) return null;
          return (
            <div
              key={i}
              className="h-full"
              style={{ width: `${pct}%`, backgroundColor: priorityColors[i] }}
            />
          );
        })}
      </div>
      <span className="text-[12px] text-text-dim font-mono">{total}</span>
    </div>
  );
}

function StatusDot({ p0, p1 }: { p0: number; p1: number }) {
  if (p0 > 0) return <span className="h-2 w-2 rounded-full bg-[var(--severity-critical)]" />;
  if (p1 > 0) return <span className="h-2 w-2 rounded-full bg-[var(--severity-high)]" />;
  return <span className="h-2 w-2 rounded-full bg-[var(--status-success)]" />;
}

function timeAgo(iso: string | null): string {
  if (!iso) return "Never";
  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function ProjectList({ projects }: { projects: ProjectSummary[] }) {
  if (projects.length === 0) {
    return (
      <div className="space-y-4">
        <SectionHeader title="Projects" count={0} countLabel="projects" />
        <EmptyState
          title="No projects yet"
          description="Push scan results from the CLI with `vulnex push`, upload an SBOM, or create a project manually."
        />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <SectionHeader title="Projects" count={projects.length} countLabel="projects" />
      <div className="rounded-lg border border-border-subtle bg-surface-raised overflow-hidden divide-y divide-border-subtle">
        {projects.map((project) => {
          const Icon = sourceIcons[project.source] ?? FolderPlus;
          return (
            <Link
              key={project.id}
              href={`/dashboard/projects/${project.id}`}
              className="flex items-center gap-4 px-4 py-3 hover:bg-surface-overlay transition-colors group"
            >
              <StatusDot p0={project.p0} p1={project.p1} />
              <Icon className="h-4 w-4 text-text-dim" />
              <div className="flex-1 min-w-0">
                <span className="text-[13px] font-medium group-hover:text-primary transition-colors">
                  {project.name}
                </span>
              </div>
              <MiniPriorityBar {...project} />
              <span className="text-[11px] text-text-dimmer w-16 text-right">
                {timeAgo(project.lastScannedAt)}
              </span>
              <ChevronRight className="h-4 w-4 text-text-dimmer group-hover:text-text-dim transition-colors" />
            </Link>
          );
        })}
      </div>
    </div>
  );
}
```

**Step 3: Create ActivityFeed component**

`app/src/components/dashboard/activity-feed.tsx`:

```tsx
import type { DashboardAlert } from "@/lib/queries";
import { SectionHeader } from "./section-header";
import { SeverityBadge } from "./severity-badge";

export function ActivityFeed({ alerts }: { alerts: DashboardAlert[] }) {
  if (alerts.length === 0) return null;

  return (
    <div className="space-y-3">
      <SectionHeader title="Activity" count={alerts.length} countLabel="events" />
      <div className="space-y-1">
        {alerts.map((alert) => (
          <div
            key={alert.id}
            className="flex items-start gap-3 px-3 py-2 rounded-md hover:bg-surface-overlay transition-colors"
          >
            <SeverityBadge severity={alert.severity}>
              {alert.type === "kev_added" ? "KEV" : alert.type === "exploit" ? "EXP" : "ADV"}
            </SeverityBadge>
            <div className="flex-1 min-w-0">
              <span className="text-[12px] font-mono text-primary">{alert.cveId}</span>
              <p className="text-[12px] text-text-dim truncate">{alert.message}</p>
            </div>
            <span className="text-[11px] text-text-dimmer shrink-0">{alert.timestamp}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
```

**Step 4: Rewrite overview page (server component)**

`app/src/app/dashboard/page.tsx`:

```tsx
import { auth } from "@/lib/auth";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { getGlobalPriorityCounts, getUserProjects, getRecentAlerts } from "@/lib/queries";
import { OverviewClient } from "./overview-client";

export default async function DashboardPage() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session?.user) redirect("/login");

  const [counts, projects, alerts] = await Promise.all([
    getGlobalPriorityCounts(session.user.id),
    getUserProjects(session.user.id),
    getRecentAlerts(),
  ]);

  return <OverviewClient counts={counts} projects={projects} alerts={alerts} />;
}
```

**Step 5: Create OverviewClient (replaces dashboard-client.tsx)**

Rename `dashboard-client.tsx` to `overview-client.tsx`:

```tsx
"use client";

import { PriorityStrip } from "@/components/dashboard/priority-strip";
import { ProjectList } from "@/components/dashboard/project-list";
import { ActivityFeed } from "@/components/dashboard/activity-feed";
import type { ProjectSummary, DashboardAlert } from "@/lib/queries";

type PriorityCounts = { p0: number; p1: number; p2: number; p3: number; p4: number };

export function OverviewClient({
  counts,
  projects,
  alerts,
}: {
  counts: PriorityCounts;
  projects: ProjectSummary[];
  alerts: DashboardAlert[];
}) {
  return (
    <div className="space-y-6">
      <div className="animate-fade-up">
        <h1 className="text-2xl font-bold tracking-tight">Overview</h1>
        <p className="text-sm text-text-dim mt-1">
          Vulnerability intelligence across your projects
        </p>
      </div>

      <div className="animate-fade-up" style={{ animationDelay: "50ms" }}>
        <PriorityStrip counts={counts} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-2 animate-fade-up" style={{ animationDelay: "100ms" }}>
          <ProjectList projects={projects} />
        </div>
        <div className="animate-fade-up" style={{ animationDelay: "150ms" }}>
          <ActivityFeed alerts={alerts} />
        </div>
      </div>
    </div>
  );
}
```

**Step 6: Delete old components**

Delete `app/src/components/dashboard/quick-actions.tsx` and `app/src/components/dashboard/risk-posture.tsx`. Delete `app/src/app/dashboard/dashboard-client.tsx`.

**Step 7: Build check**

Run: `cd app && bun run build`
Expected: build succeeds.

**Step 8: Commit**

```
git add -A
git commit -m "feat(app): redesign overview with priority strip and project list"
```

---

### Task 5: Add Project Detail Page

Create the project detail route with project-scoped CVE triage table.

**Files:**
- Create: `app/src/app/dashboard/projects/[id]/page.tsx`
- Create: `app/src/app/dashboard/projects/[id]/project-detail-client.tsx`
- Add to queries: `getProjectCVEs(projectId)` function in `app/src/lib/queries/projects.ts`

**Step 1: Add getProjectCVEs query**

Append to `app/src/lib/queries/projects.ts`:

```typescript
import type { DashboardCVE } from "./cves";

export async function getProjectCVEs(projectId: string): Promise<DashboardCVE[]> {
  const rows = await db.execute(sql`
    SELECT
      c.id,
      c.description,
      c.last_modified,
      cvss.cvss_v3_score,
      epss.epss_score,
      (EXISTS (SELECT 1 FROM kev_entry k WHERE k.cve_id = c.id)) AS in_kev
    FROM project_cve pc
    INNER JOIN cve c ON c.id = pc.cve_id
    LEFT JOIN LATERAL (
      SELECT cs.cvss_v3_score FROM cve_score cs
      WHERE cs.cve_id = c.id AND cs.source = 'nvd' AND cs.cvss_v3_score IS NOT NULL
      ORDER BY cs.scored_at DESC LIMIT 1
    ) cvss ON true
    LEFT JOIN LATERAL (
      SELECT cs.epss_score FROM cve_score cs
      WHERE cs.cve_id = c.id AND cs.source = 'epss' AND cs.epss_score IS NOT NULL
      ORDER BY cs.scored_at DESC LIMIT 1
    ) epss ON true
    WHERE pc.project_id = ${projectId}
    ORDER BY c.last_modified DESC NULLS LAST
  `);

  return rows.rows.map((row: any) => {
    const cvssVal = row.cvss_v3_score ?? 0;
    const epssVal = row.epss_score ?? 0;
    const isKev = row.in_kev === true;
    return {
      id: row.id,
      description: row.description ?? "No description available",
      cvss: cvssVal,
      epss: epssVal,
      kev: isKev,
      priority: computePriority(cvssVal, epssVal, isKev),
      updatedAt: row.last_modified ? new Date(row.last_modified).toISOString().split("T")[0] : "",
    };
  });
}
```

Note: import `computePriority` from `./cves` — it needs to be exported from there.

**Step 2: Create server component page**

`app/src/app/dashboard/projects/[id]/page.tsx`:

```tsx
import { auth } from "@/lib/auth";
import { headers } from "next/headers";
import { redirect, notFound } from "next/navigation";
import { getProjectDetail, getProjectCVEs } from "@/lib/queries";
import { ProjectDetailClient } from "./project-detail-client";

export default async function ProjectPage({ params }: { params: Promise<{ id: string }> }) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session?.user) redirect("/login");

  const { id } = await params;
  const [project, cves] = await Promise.all([
    getProjectDetail(id),
    getProjectCVEs(id),
  ]);

  if (!project) notFound();

  return <ProjectDetailClient project={project} cves={cves} />;
}
```

**Step 3: Create client component**

`app/src/app/dashboard/projects/[id]/project-detail-client.tsx`:

```tsx
"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, RefreshCw, Terminal, Upload, FolderPlus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PriorityStrip } from "@/components/dashboard/priority-strip";
import { CveTable } from "@/components/dashboard/cve-table";
import type { ProjectDetail, DashboardCVE } from "@/lib/queries";

const sourceLabels: Record<string, { icon: typeof Terminal; label: string }> = {
  cli: { icon: Terminal, label: "CLI Push" },
  sbom: { icon: Upload, label: "SBOM Upload" },
  manual: { icon: FolderPlus, label: "Manual" },
};

export function ProjectDetailClient({
  project,
  cves,
}: {
  project: ProjectDetail;
  cves: DashboardCVE[];
}) {
  const [searchQuery, setSearchQuery] = useState("");
  const src = sourceLabels[project.source] ?? sourceLabels.manual;
  const Icon = src.icon;

  const counts = {
    p0: cves.filter((c) => c.priority === "P0").length,
    p1: cves.filter((c) => c.priority === "P1").length,
    p2: cves.filter((c) => c.priority === "P2").length,
    p3: cves.filter((c) => c.priority === "P3").length,
    p4: cves.filter((c) => c.priority === "P4").length,
  };

  return (
    <div className="space-y-6">
      <div className="animate-fade-up">
        <Link
          href="/dashboard"
          className="inline-flex items-center gap-1 text-[12px] text-text-dim hover:text-foreground transition-colors mb-3"
        >
          <ArrowLeft className="h-3 w-3" />
          Back to overview
        </Link>
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">{project.name}</h1>
            <div className="flex items-center gap-2 mt-1">
              <Icon className="h-3.5 w-3.5 text-text-dim" />
              <span className="text-[12px] text-text-dim">{src.label}</span>
              {project.lastScannedAt && (
                <>
                  <span className="text-text-dimmer">·</span>
                  <span className="text-[12px] text-text-dim">
                    Last scan: {new Date(project.lastScannedAt).toLocaleDateString()}
                  </span>
                </>
              )}
            </div>
          </div>
          <Button variant="outline" size="sm" className="border-border-subtle">
            <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
            Re-scan
          </Button>
        </div>
      </div>

      <div className="animate-fade-up" style={{ animationDelay: "50ms" }}>
        <PriorityStrip counts={counts} />
      </div>

      <div className="animate-fade-up" style={{ animationDelay: "100ms" }}>
        <div className="max-w-sm mb-4">
          <Input
            placeholder="Search CVEs..."
            className="bg-surface-raised border-border-subtle"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
        <CveTable cves={cves} searchQuery={searchQuery} title="Vulnerabilities" />
      </div>
    </div>
  );
}
```

**Step 4: Build check**

Run: `cd app && bun run build`
Expected: build succeeds.

**Step 5: Commit**

```
git add -A
git commit -m "feat(app): add project detail page with scoped CVE triage table"
```

---

### Task 6: Add CVE Detail Page

Create a CVE detail page showing full enrichment — the web version of `vulnex enrich`.

**Files:**
- Create: `app/src/app/dashboard/cve/[id]/page.tsx`
- Create: `app/src/app/dashboard/cve/[id]/cve-detail-client.tsx`
- Add to queries: `getCVEDetail(cveId)` function in `app/src/lib/queries/cves.ts`

**Step 1: Add getCVEDetail query**

Append to `app/src/lib/queries/cves.ts`:

```typescript
export type CVEDetail = {
  id: string;
  description: string;
  publishedAt: string | null;
  lastModified: string | null;
  status: string | null;
  sourceId: string | null;
  cvss: number;
  cvssVector: string | null;
  epss: number;
  epssPercentile: number;
  kev: boolean;
  kevVendor: string | null;
  kevProduct: string | null;
  kevDateAdded: string | null;
  kevDueDate: string | null;
  kevRansomware: boolean;
  priority: "P0" | "P1" | "P2" | "P3" | "P4";
  exploits: { source: string; title: string | null; url: string | null; publishedAt: string | null }[];
  advisories: { ghsaId: string | null; severity: string | null; summary: string | null; url: string | null }[];
  sources: string[];
};

export async function getCVEDetail(cveId: string): Promise<CVEDetail | null> {
  // Main CVE record
  const [cveRow] = await db
    .select()
    .from(cve)
    .where(eq(cve.id, cveId))
    .limit(1);

  if (!cveRow) return null;

  // Scores, KEV, exploits, advisories in parallel
  const [cvssRows, epssRows, kevRows, exploitRows, advisoryRows] = await Promise.all([
    db.select().from(cveScore)
      .where(and(eq(cveScore.cveId, cveId), eq(cveScore.source, "nvd"), isNotNull(cveScore.cvssV3Score)))
      .orderBy(desc(cveScore.scoredAt)).limit(1),
    db.select().from(cveScore)
      .where(and(eq(cveScore.cveId, cveId), eq(cveScore.source, "epss"), isNotNull(cveScore.epssScore)))
      .orderBy(desc(cveScore.scoredAt)).limit(1),
    db.select().from(kevEntry).where(eq(kevEntry.cveId, cveId)).limit(1),
    db.select().from(exploit).where(eq(exploit.cveId, cveId)).orderBy(desc(exploit.createdAt)),
    db.select().from(advisory).where(eq(advisory.cveId, cveId)).orderBy(desc(advisory.createdAt)),
  ]);

  const cvssVal = cvssRows[0]?.cvssV3Score ?? 0;
  const epssVal = epssRows[0]?.epssScore ?? 0;
  const isKev = kevRows.length > 0;
  const kev = kevRows[0];

  // Determine which sources have data
  const sources: string[] = ["NVD"]; // always present if CVE exists
  if (epssRows.length > 0) sources.push("EPSS");
  if (isKev) sources.push("KEV");
  if (advisoryRows.length > 0) sources.push("GHSA");
  if (exploitRows.length > 0) sources.push("Exploits");

  return {
    id: cveRow.id,
    description: cveRow.description ?? "No description available",
    publishedAt: cveRow.publishedAt?.toISOString() ?? null,
    lastModified: cveRow.lastModified?.toISOString() ?? null,
    status: cveRow.status,
    sourceId: cveRow.sourceId,
    cvss: cvssVal,
    cvssVector: cvssRows[0]?.cvssV3Vector ?? null,
    epss: epssVal,
    epssPercentile: epssRows[0]?.epssPercentile ?? 0,
    kev: isKev,
    kevVendor: kev?.vendor ?? null,
    kevProduct: kev?.product ?? null,
    kevDateAdded: kev?.dateAdded ?? null,
    kevDueDate: kev?.dueDate ?? null,
    kevRansomware: kev?.knownRansomware ?? false,
    priority: computePriority(cvssVal, epssVal, isKev),
    exploits: exploitRows.map((e) => ({
      source: e.source,
      title: e.title,
      url: e.url,
      publishedAt: e.publishedAt?.toISOString() ?? null,
    })),
    advisories: advisoryRows.map((a) => ({
      ghsaId: a.ghsaId,
      severity: a.severity,
      summary: a.summary,
      url: a.url,
    })),
    sources,
  };
}
```

**Step 2: Create server component page**

`app/src/app/dashboard/cve/[id]/page.tsx`:

```tsx
import { notFound } from "next/navigation";
import { getCVEDetail, getEpssTrends } from "@/lib/queries";
import { CVEDetailClient } from "./cve-detail-client";

export default async function CVEPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const cveId = decodeURIComponent(id);

  const [detail, trends] = await Promise.all([
    getCVEDetail(cveId),
    getEpssTrends([cveId]),
  ]);

  if (!detail) notFound();

  return <CVEDetailClient detail={detail} trends={trends} />;
}
```

**Step 3: Create CVEDetailClient**

`app/src/app/dashboard/cve/[id]/cve-detail-client.tsx` — a two-column layout:

Left column: CVE ID, description, priority explanation, CVSS/EPSS/KEV scores, references.
Right column: source coverage checklist, EPSS trend chart (reuse existing EpssChart), exploits list, "Add to watchlist" button.

This is a large component (~200 lines). The implementer should use existing `SeverityBadge`, `EpssChart`, and shadcn `Card` components. Link CVE IDs in the table (`cve-table.tsx`) to `/dashboard/cve/[id]`.

**Step 4: Update CveTable to link CVE IDs**

In `app/src/components/dashboard/cve-table.tsx`, wrap the CVE ID cell content in a `Link`:

```tsx
import Link from "next/link";

// In the TableCell for CVE ID:
<TableCell className="font-mono text-[13px] font-medium">
  <Link href={`/dashboard/cve/${cve.id}`} className="text-primary hover:underline">
    {cve.id}
  </Link>
</TableCell>
```

**Step 5: Build check and commit**

```
git add -A
git commit -m "feat(app): add CVE detail page with full enrichment view"
```

---

### Task 7: Update Sidebar Navigation

Update the sidebar to match the new information architecture: Overview, Projects, Watchlist, Exploits, Settings. Remove SBOM from top-level nav.

**Files:**
- Modify: the sidebar component (likely `app/src/components/app-sidebar.tsx` or within `layout.tsx`)

**Step 1: Find and update sidebar nav items**

Look for the sidebar navigation definition (the component rendering "Overview", "Watchlist", "SBOM Scans", "Exploits" links). Update to:

```typescript
const platformItems = [
  { title: "Overview", url: "/dashboard", icon: LayoutDashboard },
  { title: "Projects", url: "/dashboard/projects", icon: FolderOpen },
  { title: "Watchlist", url: "/dashboard/watchlist", icon: Eye },
  { title: "Exploits", url: "/dashboard/exploits", icon: Zap },
];

const supportItems = [
  { title: "Settings", url: "/dashboard/settings", icon: Settings },
  { title: "Help & Docs", url: "/docs", icon: HelpCircle },
];
```

Remove "SBOM Scans" from top-level — it becomes a project-level action.

**Step 2: Add a Projects index page**

Create `app/src/app/dashboard/projects/page.tsx` that redirects to `/dashboard` (projects are shown on the overview for now, a dedicated page can come later):

```tsx
import { redirect } from "next/navigation";
export default function ProjectsPage() {
  redirect("/dashboard");
}
```

**Step 3: Build check and commit**

```
git add -A
git commit -m "refactor(app): update sidebar navigation for project-centric layout"
```

---

### Task 8: Create Feature Specs

Write feature spec files in `plans/features/` for each major piece of this redesign.

**Files:**
- Create: `plans/features/2026-03-13-dashboard-redesign-colors-a3k7.md`
- Create: `plans/features/2026-03-13-project-model-b5m2.md`
- Create: `plans/features/2026-03-13-overview-redesign-c7n4.md`
- Create: `plans/features/2026-03-13-project-detail-d9p6.md`
- Create: `plans/features/2026-03-13-cve-detail-page-e2r8.md`

Each spec should follow the standard frontmatter format with acceptance criteria. Set status to `in progress` for the current task, `proposed` for the rest.

**Step: Commit**

```
git add plans/features/
git commit -m "docs: add feature specs for dashboard redesign"
```

---

Plan complete and saved to `docs/plans/2026-03-13-dashboard-redesign.md`. Two execution options:

**1. Subagent-Driven (this session)** — I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** — Open new session with executing-plans, batch execution with checkpoints

Which approach?