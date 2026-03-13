---
name: Add CVEs to Product
description: Search and link CVEs to a product from the product detail page, with support for bulk CVE ID input.
date: 2026-03-13
status: completed
---

# Add CVEs to Product

## Description

From a product's detail page, users can search for CVEs and add them to the product. Also supports pasting a list of CVE IDs for bulk addition.

### Target design

**Search and add:**
- "Add CVEs" button on the product detail page
- Opens a dialog with a search input
- Search queries the `cve` table by ID or description keyword
- Results show CVE ID, CVSS score, and a checkbox
- Select CVEs and click "Add" to link them to the product

**Bulk add:**
- A textarea where users can paste CVE IDs (one per line or comma-separated)
- Validates IDs exist in the database
- Links all valid IDs to the product in one operation

## User Stories

1. As a user, I want to add specific CVEs to my product so I can track them.
2. As a user, I want to paste a list of CVE IDs from a scanner output to bulk-add them.

## Acceptance Criteria

- [x] "Add CVEs" button on product detail page
- [x] Search input with results from the CVE database
- [x] Multi-select and add to product
- [x] Bulk add via pasted CVE ID list
- [x] Duplicate CVEs are silently ignored (idempotent)
- [x] Product's CVE count and priority breakdown update after adding
- [x] `bun run build` succeeds

## Priority

**High** — Without this, the only way to populate a product is via the seed script.

## Dependencies

- Rename project → product
- Create Product UI

## Implementation Notes

- API routes: `POST /api/products/[id]/cves` for adding, `GET /api/cves/search?q=...` for searching
- Use `onConflictDoNothing()` on `product_cve` for idempotency
- Limit search results to 50 to keep the dialog responsive
- Future: this is also the endpoint `vulnex push` will call

## Documentation Updates

No changes needed.
