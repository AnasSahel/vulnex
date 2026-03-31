---
name: Rename Project to Product
description: Rename all project references to product across database schema, queries, components, routes, and sidebar navigation.
date: 2026-03-13
status: completed
---

# Rename Project to Product

## Description

The "project" concept is being replaced by "product" to align with the Cyber Resilience Act (CRA) where the regulatory unit is a product. This is a rename across the entire codebase.

### Current problems

1. Database tables are named `project` and `project_cve` but the entity they represent is a product.
2. All query functions, types, components, and routes use "project" naming.
3. The sidebar says "Projects" but should say "Products".

### Target design

Rename everything:
- DB: `project` → `product`, `project_cve` → `product_cve`
- Queries: `getUserProjects` → `getUserProducts`, `ProjectSummary` → `ProductSummary`, etc.
- Routes: `/dashboard/projects/[id]` → `/dashboard/products/[id]`
- Components: `ProjectList` → `ProductList`, `ProjectDetailClient` → `ProductDetailClient`
- Sidebar: "Projects" → "Products"

## User Stories

1. As a user, I see "Products" in the UI which aligns with CRA terminology.

## Acceptance Criteria

- [x] Database tables renamed to `product` and `product_cve`
- [x] All query functions and types use "product" naming
- [x] Routes use `/dashboard/products/[id]`
- [x] Sidebar shows "Products"
- [x] `bun run build` succeeds
- [x] No remaining references to "project" in dashboard code (except git history)

## Priority

**High** — Must be done before other milestone 1 features to avoid double-renaming.

## Dependencies

- Dashboard redesign (017ce6f)

## Implementation Notes

- Use `drizzle-kit push --force` after schema rename
- The rename is mechanical — find/replace across files
- Update the design docs to reflect new naming

## Documentation Updates

Update `docs/plans/2026-03-13-dashboard-redesign-design.md` to use product terminology.
