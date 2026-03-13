---
name: Seed Demo Data
description: Script that creates a sample product and links synced CVEs to it, validating the full UI pipeline end-to-end.
date: 2026-03-13
status: completed
---

# Seed Demo Data

## Description

Create a bun script that seeds the database with a sample product and links existing CVEs to it. This validates the Product → CVE → Dashboard pipeline works before building real creation flows.

### Target design

A script at `workers/seed-demo.ts` that:
- Creates a product named "Demo Application" owned by the first user in the database
- Links 200 high-priority CVEs (highest CVSS scores) to the product via `product_cve`
- Outputs a summary of what was created

Run with: `cd workers && DATABASE_URL=... bun run seed-demo.ts`

## User Stories

1. As a developer, I want to see real data in the new product-centric dashboard so I can verify the UI works.

## Acceptance Criteria

- [x] Script creates a product record in the `product` table
- [x] Script links ~200 CVEs to the product via `product_cve`
- [x] Dashboard overview shows the product with correct P0–P4 breakdown
- [x] Product detail page shows the linked CVEs
- [x] CVE detail page works when clicking a CVE ID
- [x] Script is idempotent (safe to run multiple times)

## Priority

**High** — Blocks visual validation of the entire dashboard redesign.

## Dependencies

- Dashboard redesign (017ce6f) — product tables and UI must exist
- Rename project → product (must be done first or simultaneously)

## Implementation Notes

- Query for the first user: `SELECT id FROM "user" LIMIT 1`
- Select top CVEs: `SELECT id FROM cve JOIN cve_score ON ... WHERE source='nvd' ORDER BY cvss_v3_score DESC LIMIT 200`
- Use `onConflictDoNothing()` for idempotency on `product_cve`

## Documentation Updates

No changes needed — internal tooling.
