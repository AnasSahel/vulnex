---
name: CRA Product Metadata
description: Extend product with CRA-required fields (manufacturer, category, support period) and settings UI.
date: 2026-03-13
status: proposed
---

# CRA Product Metadata

## Description

### Current problems

1. Products have only basic fields (name, source, last scanned) — no CRA-specific metadata.
2. CRA requires products to declare manufacturer info, product category, and support period.
3. Product category (default/important Class I/important Class II/critical) determines reporting obligations — this is not captured anywhere.

### Target design

Extend the `product` table with CRA-required fields and add a settings tab to the product detail page for managing this metadata.

**Schema additions to `product` table:**

- `manufacturer_name` (text, nullable)
- `manufacturer_contact` (text, nullable — email or URL)
- `product_category` (text, default "default" — values: default/important_class_I/important_class_II/critical)
- `support_end_date` (date, nullable)
- `intended_use` (text, nullable)
- `technical_documentation_url` (text, nullable)

**Route:** `/dashboard/products/[id]/settings`

**UI:**

- Form with fields for all CRA metadata
- Product category selector with explanations of each category's obligations
- CRA readiness indicator showing which required fields are filled
- Save button with validation

## User Stories

1. As a manufacturer, I want to record my product's CRA category so I know which reporting obligations apply.
2. As a compliance officer, I want to see which CRA metadata fields are missing so I can drive completeness.
3. As a product owner, I want to set a support end date so remediation obligations are tracked correctly.

## Acceptance Criteria

- [ ] Product table extended with all CRA metadata fields
- [ ] `/dashboard/products/[id]/settings` route renders the CRA metadata form
- [ ] Product category dropdown with 4 options and brief explanations
- [ ] All fields are saveable and persist correctly
- [ ] CRA readiness indicator shows completion percentage
- [ ] Required fields for CRA compliance are clearly marked
- [ ] Validation prevents invalid data (e.g., past support_end_date)
- [ ] Migration adds columns without breaking existing products (all nullable or with defaults)
- [ ] `bun run build` succeeds

## Priority

**High** — Product category determines reporting obligations. Must be in place before vulnerability disclosure features.

## Dependencies

- `2026-03-13-rename-project-product-n4r8.md` (product table must exist)

## Implementation Notes

- Add columns to existing `product` table in `packages/db/src/schema.ts`
- Create API route `PUT /api/products/[id]/settings` for updating metadata
- Product category enum should be defined in schema as a check constraint or validated in code
- CRA readiness calculation: count filled required fields / total required fields
- Settings tab added to product detail page navigation
- Form uses existing Shadcn UI form components

## Documentation Updates

- Document CRA metadata fields and what each means
- Add guide on CRA product categories and their implications
