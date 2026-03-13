---
name: Product SBOM Upload
description: Upload CycloneDX or SPDX SBOM files to a product for storage. Parsing deferred to milestone 2.
date: 2026-03-13
status: completed
---

# Product SBOM Upload

## Description

Allow users to upload SBOM files (CycloneDX or SPDX) to a product. Files are stored in the `product_sbom` table but not parsed — component extraction is a milestone 2 feature. This establishes the SBOM storage layer needed for CRA compliance.

### Target design

**Upload flow:**
- On the product detail page, an "Upload SBOM" button/zone
- Accepts .json and .xml files
- Detects format (CycloneDX or SPDX) from file content
- Stores the file content in the `product_sbom` table

**SBOM list:**
- Product detail page shows a "SBOMs" section listing uploaded files
- Each entry shows: filename, format, upload date, file size
- "Pending analysis" badge (until milestone 2 parsing is built)

**Database:**
- Add `product_sbom` table: id, productId, filename, format, content (text/jsonb), fileSize, uploadedAt

### CRA alignment

The CRA requires manufacturers to provide a complete SBOM for each product. Storing multiple SBOMs per product (one per artifact) prepares for milestone 3's merged SBOM export.

## User Stories

1. As a user, I want to upload SBOMs to my product so they're stored alongside vulnerability data.
2. As a compliance officer, I want SBOMs associated with products for CRA reporting.

## Acceptance Criteria

- [x] `product_sbom` table exists in the schema
- [x] Upload button on product detail page
- [x] File format auto-detection (CycloneDX vs SPDX)
- [x] Uploaded SBOMs listed on product detail page
- [x] "Pending analysis" indicator shown (parsing not yet implemented)
- [x] File size validation (reject files > 10MB)
- [x] `bun run build` succeeds

## Priority

**Medium** — Establishes the storage layer for milestone 2 but doesn't block other M1 features.

## Dependencies

- Rename project → product
- Create Product UI

## Implementation Notes

- API route: `POST /api/products/[id]/sboms` — multipart form upload
- Detect format: check for `"bomFormat": "CycloneDX"` or `<spdx:` / `"spdxVersion"` in content
- Store raw content as text — can migrate to file storage later if sizes become an issue
- The SBOM page (`/dashboard/sbom`) can redirect to the product that owns the SBOM, or be removed entirely

## Documentation Updates

No changes needed.
