---
name: Shared Database Package
description: Extract Drizzle schema to packages/db/ and add vulnerability data tables for shared use by Next.js app and Motia workers.
date: 2026-03-13
status: completed
---

# Shared Database Package

## Description

The Drizzle schema currently lives inside `app/src/lib/db/` and is only accessible to the Next.js app. To support Motia workers reading/writing the same database, the schema and client need to move to a shared package at `packages/db/`.

### Current problems

1. Schema is locked inside the Next.js app — workers can't import it.
2. No tables exist for vulnerability data (CVEs, scores, exploits, advisories).
3. No mechanism to track sync state across data sources.

### Target design

**Monorepo workspace package at `packages/db/`:**
- `schema.ts` — All table definitions (auth tables + new vuln tables)
- `index.ts` — Drizzle client export
- `drizzle.config.ts` — Drizzle Kit config for migrations
- `package.json` — Workspace package with `drizzle-orm`, `@neondatabase/serverless`

**New tables:**

```
cve (
  id             text PK        -- "CVE-2024-3094"
  description    text
  published_at   timestamp
  last_modified  timestamp
  source_id      text            -- NVD source identifier
  status         text            -- "Analyzed", "Modified", etc.
  created_at     timestamp
  updated_at     timestamp
)

cve_score (
  id             serial PK
  cve_id         text FK → cve
  cvss_v3_score  real
  cvss_v3_vector text
  epss_score     real
  epss_percentile real
  source         text            -- "nvd", "epss"
  scored_at      timestamp       -- when this score was recorded
  created_at     timestamp
)

kev_entry (
  id              serial PK
  cve_id          text FK → cve
  vendor          text
  product         text
  vulnerability_name text
  date_added      date
  due_date        date
  known_ransomware boolean
  notes           text
  created_at      timestamp
)

exploit (
  id              serial PK
  cve_id          text FK → cve
  source          text           -- "metasploit", "nuclei", "exploitdb", "github"
  title           text
  url             text
  published_at    timestamp
  created_at      timestamp
)

advisory (
  id              serial PK
  ghsa_id         text UNIQUE
  cve_id          text FK → cve (nullable)
  severity        text
  summary         text
  description     text
  published_at    timestamp
  updated_at      timestamp
  url             text
  created_at      timestamp
)

sync_log (
  id              serial PK
  source          text UNIQUE    -- "nvd", "epss", "kev", "ghsa", "exploits"
  last_cursor     text           -- API-specific cursor/offset
  last_synced_at  timestamp
  status          text           -- "success", "error"
  error_message   text
  items_synced    integer
  created_at      timestamp
  updated_at      timestamp
)

watchlist (
  id              serial PK
  user_id         text FK → user
  cve_id          text FK → cve
  added_at        timestamp
  notes           text
  UNIQUE(user_id, cve_id)
)
```

**Update `app/` imports:**
- `app/src/lib/db/` becomes a thin re-export from `@vulnex/db` or uses workspace path imports
- `drizzle.config.ts` in app/ points to the shared schema

## User Stories

1. As a developer, I want a single source of truth for the DB schema so both the web app and workers stay in sync.
2. As the system, I need tables to store vulnerability data fetched from public APIs.

## Acceptance Criteria

- [x] `packages/db/` exists as a workspace package
- [x] All existing auth tables (`user`, `session`, `account`, `verification`) are in the shared schema
- [x] New tables (`cve`, `cve_score`, `kev_entry`, `exploit`, `advisory`, `sync_log`, `watchlist`) are defined
- [x] `app/` imports the shared schema — existing auth flow still works
- [x] `bun run db:push` applies the schema to the database
- [x] `bun run build` in `app/` still succeeds

## Priority

**High** — Blocks all sync workers and dashboard data integration.

## Dependencies

- `2026-03-13-auth-integration-k8v3` (completed — provides existing auth schema)

## Implementation Notes

- Use Bun workspaces in root `package.json`
- Export schema and client from `packages/db/src/index.ts`
- Keep the Neon driver for now — production will use a different driver
- Run `drizzle-kit push` from `packages/db/` to apply schema
- Auth tables must remain identical to what better-auth expects

## Documentation Updates

No changes needed — internal infrastructure.
