# Dashboard Redesign

## Problem

The current vulnex.cloud dashboard looks like a generic SaaS app — GitHub-blue accent, flat CVE table, no connection to the CLI's core value (multi-source enrichment, P0–P4 prioritization, project-scoped scans). It doesn't reflect the vulnex brand or serve the two target users: developers who use the CLI and security leads who need oversight.

## Design Decisions

### Visual Identity

- **Primary accent**: vulnex red (`#ef4444` / `#f87171`) replaces GitHub blue everywhere — buttons, links, active states, logo
- **Severity colors**: unchanged (critical red, high orange, medium yellow, low gray) — industry standard
- **Priority badges (P0–P4)**: follow the severity gradient — P0 critical red through P4 dim gray
- **Backgrounds**: keep current dark (`#0d1117`) / light (`#f6f8fa`) — clean and professional
- **Typography**: Satoshi headings, system monospace for CVE IDs and scores — already aligned with website
- **Personality**: professional, dense but not cluttered, no terminal chrome. Red as a signature accent, not overwhelming.

### Information Architecture — Three Levels

**Level 1 — Overview (home)**

Top bar: horizontal strip of P0–P4 chips with counts, color-coded by severity. Clickable to filter. Replaces the current "Risk Posture" cards that show raw unactionable counts.

Main area: project list. Each project is a row showing:
- Name + source icon (CLI push, SBOM upload, manual)
- Last scanned timestamp
- Mini priority breakdown (colored dots/bars for P0–P4 distribution)
- Total CVE count
- Status indicator (healthy / needs attention / critical)

Projects with P0/P1 issues sort to top by default. Sortable by name, last scan, or risk.

Secondary column: activity feed replacing "Recent Alerts". Shows new KEV additions, EPSS spikes, new exploits, sync status. Compact and scrollable.

Removed from overview: search bar (moves to project detail), EPSS chart (moves to CVE detail), flat global CVE table (moves to project detail).

**Level 2 — Project detail**

Header: project name, source, last scan, "Re-scan" button, compact P0–P4 summary.

Main content: CVE triage table sorted by priority (P0 first). Columns: CVE ID, description, CVSS, EPSS, KEV, priority badge, sources (NVD/EPSS/KEV/GHSA/OSV icons). Paginated at 20 rows. Search + filter by priority level.

Empty state: "No scans yet. Run `vulnex push` from your project directory, or upload an SBOM." with CLI command snippet.

**Level 3 — CVE detail (page or panel)**

Left column:
- CVE ID + full description
- Priority badge with explanation ("P0 — actively exploited, critical CVSS, high EPSS")
- Scores: CVSS gauge, EPSS score + percentile, KEV status with due date
- References list

Right column:
- Source coverage: which databases have data (NVD, KEV, EPSS, GHSA, OSV) with checkmarks
- EPSS trend chart (relocated from overview — contextually meaningful here)
- Linked exploits
- "Add to watchlist" button

### Sidebar Navigation

- Overview (home)
- Projects
- Watchlist (cross-project, user-curated CVEs)
- Exploits (global feed)
- Settings

SBOM Scans moves inside a project (project-level action, not top-level nav).

### How Projects Enter the System

Primary flow: `vulnex push` sends CLI scan results to the cloud. Projects appear automatically.

Secondary flow: manual CVE addition or SBOM upload through the UI.

The cloud is the CLI's persistent layer, not a standalone scanner.

### Target Users

- **Developer (CLI user)**: persistent view of CLI findings, watchlist, historical trends, CI/CD results over time
- **Security lead / manager**: cross-project overview, team risk posture, triage prioritization

## What Changes vs Current

| Current | Redesign |
|---------|----------|
| GitHub blue accent | vulnex red accent |
| Flat global CVE table on home | Project-scoped CVE tables |
| "Risk Posture" raw count cards | P0–P4 priority chips (actionable) |
| EPSS chart on overview | EPSS chart on CVE detail |
| SBOM as top-level nav | SBOM as project-level action |
| No project concept | Projects as primary organizing unit |
| "Watched CVEs" label confusion | Clear separation: overview shows projects, watchlist shows user-curated CVEs |
| No CVE detail view | Full enrichment page per CVE |

## Out of Scope

- CLI `vulnex push` command implementation (separate feature)
- Real-time WebSocket updates
- Team/org multi-tenancy
- Compliance reporting
