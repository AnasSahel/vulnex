---
name: Motia Workers Scaffold
description: Set up the Motia project in workers/ with iii config, dev scripts, and sync-all flow definition.
date: 2026-03-13
status: completed
---

# Motia Workers Scaffold

## Description

Set up the Motia project structure at `workers/` in the monorepo. This provides the orchestration runtime for all vulnerability data sync jobs.

### Current problems

1. No background job infrastructure exists — the app can only serve HTTP requests.
2. No way to run scheduled data syncs or trigger them on demand.

### Target design

**Project structure:**
```
workers/
├── iii-config.yaml          # iii engine configuration
├── package.json             # Motia + shared DB dependency
├── tsconfig.json
├── .env.local               # DATABASE_URL (same as app)
└── src/
    └── sync-all.step.ts     # Orchestrator step (cron + API trigger)
```

**iii-config.yaml** configures the Motia runtime — points to `src/` for step discovery, sets port for the HTTP API.

**sync-all.step.ts** is the entry point flow:
- Cron trigger: runs every 6 hours
- API trigger: POST `/api/sync` for on-demand sync
- Emits events that individual source steps listen to

**Dev workflow:**
```bash
cd workers && bun run dev    # starts iii engine with hot reload
```

## User Stories

1. As a developer, I want to run sync jobs locally with a single command.
2. As the dashboard, I want to trigger a sync via HTTP POST.

## Acceptance Criteria

- [x] `workers/` directory exists with valid Motia project structure
- [x] `iii` engine starts successfully with `bun run dev` in `workers/`
- [x] `sync-all.step.ts` registers both cron and API triggers
- [x] POST to the Motia HTTP API returns a success response
- [x] `workers/` uses `packages/db` as a workspace dependency

## Priority

**High** — Blocks all individual sync worker implementations.

## Dependencies

- `2026-03-13-shared-db-package-a2k7` (shared DB schema)
- iii engine installed locally

## Implementation Notes

- Install iii engine: `curl -fsSL https://install.iii.dev/iii/main/install.sh | sh`
- Install Motia: `bun add motia` in `workers/`
- Add `workers/` to root Bun workspace
- The sync-all step should emit source-specific topics: `sync.nvd`, `sync.epss`, `sync.kev`, `sync.ghsa`, `sync.exploits`
- Individual source steps (separate features) will subscribe to these topics

## Documentation Updates

No changes needed — internal infrastructure.
