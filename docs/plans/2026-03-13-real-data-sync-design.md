# Real-Time Vulnerability Data Sync — Design

## Problem

The VulneX Cloud dashboard displays hardcoded mock data. Users need real, continuously updated vulnerability intelligence from public APIs.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   Monorepo                       │
│                                                  │
│  ┌──────────────┐       ┌─────────────────────┐ │
│  │  Next.js App │       │   Motia Workers     │ │
│  │  (app/)      │       │   (workers/)        │ │
│  │              │       │                     │ │
│  │  Dashboard ──┼──DB──▶│  sync-nvd.step.ts   │ │
│  │  reads from  │       │  sync-epss.step.ts  │ │
│  │  Drizzle     │       │  sync-kev.step.ts   │ │
│  │              │◀─HTTP─│  sync-ghsa.step.ts  │ │
│  │  "Sync Now"  │       │  sync-exploits.step │ │
│  │  button hits │       │                     │ │
│  │  Motia API   │       │  Cron: every 6h     │ │
│  └──────────────┘       └─────────────────────┘ │
│                                                  │
│  ┌──────────────────────────────────────────┐   │
│  │  packages/db/                             │   │
│  │  Shared Drizzle schema + client           │   │
│  └──────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

## Decisions

- **Orchestration**: Motia (via iii engine) — self-hostable, step-based, supports cron + HTTP triggers
- **Language**: TypeScript for all workers — shares Drizzle schema with Next.js app
- **Database**: Shared Postgres via Drizzle (Neon for dev, self-hosted for prod)
- **Sync strategy**: Incremental — each source tracks its last cursor/timestamp in `sync_log`
- **Monorepo layout**: `app/` (Next.js), `workers/` (Motia), `packages/db/` (shared schema)

## Data Sources

| Source | API | Schedule | Data |
|--------|-----|----------|------|
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` | Every 6h | CVE records, CVSS scores |
| EPSS | `api.first.org/data/v1/epss` | Every 6h | Exploit probability scores |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | Every 12h | Known exploited vulns |
| GHSA | GitHub GraphQL API | Every 6h | Security advisories |
| ExploitDB/GitHub | Multiple | Every 12h | Public exploit references |

## New Database Tables

- `cve` — Core CVE records (id, description, published, modified, status)
- `cve_score` — CVSS + EPSS per CVE (versioned, timestamped)
- `kev_entry` — CISA KEV catalog entries
- `exploit` — Public exploit records (source, url, cve_id)
- `advisory` — GHSA advisories
- `sync_log` — Last sync cursor per source
- `watchlist` — User-CVE association (per-user watchlist)

## Feature Breakdown

1. **Shared DB package** — Extract Drizzle schema to `packages/db/`, add vuln tables
2. **Motia project scaffold** — Set up `workers/` with iii config
3. **NVD sync worker** — Fetch CVEs + CVSS from NVD API
4. **EPSS sync worker** — Fetch exploit probability scores
5. **KEV sync worker** — Fetch CISA KEV catalog
6. **GHSA sync worker** — Fetch GitHub security advisories
7. **Exploit sync worker** — Aggregate from ExploitDB + GitHub
8. **Dashboard data integration** — Replace mock data with DB queries
9. **Sync control UI** — "Sync Now" button + sync status display

## Out of Scope

- Webhook notifications on new data
- Rate limiting / NVD API key management
- Historical EPSS tracking over time
- SBOM file parsing (separate feature)
