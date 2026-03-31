---
name: Create Product UI
description: Add a "New Product" creation flow to the dashboard with name, description, and version fields.
date: 2026-03-13
status: completed
---

# Create Product UI

## Description

Add a button on the dashboard overview that opens a product creation form. Creating a product redirects to its detail page.

### Target design

- "New Product" button on the overview page next to the Products section header
- Clicking opens a dialog/modal with fields: name (required), description (optional), version (optional)
- On submit: POST to `/api/products` which creates the record and returns the product ID
- Redirect to `/dashboard/products/[id]`

## User Stories

1. As a user, I want to create a product so I can start tracking its vulnerabilities.

## Acceptance Criteria

- [x] "New Product" button visible on overview page
- [x] Modal/dialog with name field
- [x] Form validation (name required)
- [x] API route creates product in database
- [x] Redirect to product detail page after creation
- [x] Product appears in the overview product list
- [x] `bun run build` succeeds

## Priority

**High** — Core CRUD needed before any product-related feature works.

## Dependencies

- Rename project → product

## Implementation Notes

- API route at `app/src/app/api/products/route.ts` — POST handler
- Use nanoid for product IDs
- Auth: verify session before creating
- Use shadcn Dialog component for the form
- The description field maps to a future CRA "intended purpose" field

## Documentation Updates

No changes needed.
