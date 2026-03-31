---
name: SBOM Parser
description: Parse CycloneDX and SPDX SBOMs into components stored in the database.
date: 2026-03-13
status: proposed
---

# SBOM Parser

## Description

### Current problems

1. SBOM upload (M1) stores files but does not parse them — no component extraction.
2. Without parsed components, there is no way to auto-match CVEs or build a component inventory.
3. CRA requires machine-readable SBOMs with full component lists — raw file storage is insufficient.

### Target design

A new `packages/sbom/` workspace package that parses CycloneDX (JSON + XML) and SPDX (JSON + tag-value) formats. Parsed components are stored in a `component` table linked to the `sbom` table. Parsing runs automatically after upload and can be retriggered manually.

**New schema tables (`packages/db/src/schema.ts`):**

- `sbom`: id, product_id, filename, format (cyclonedx/spdx), spec_version, uploaded_at, parsed_at, component_count, raw_storage_key
- `component`: id, sbom_id, name, version, purl, license, supplier, type (library/framework/application/os/container), created_at

**Parser package (`packages/sbom/`):**

- Detect format from file content (JSON structure or XML root element)
- Normalize components to a common `ParsedComponent` type
- Return structured result: metadata + component list + parse errors

## User Stories

1. As a developer, I want my uploaded SBOM automatically parsed so I can see which components my product contains.
2. As a security lead, I want components extracted with purl identifiers so they can be matched against vulnerability databases.
3. As a CRA compliance officer, I want support for industry-standard SBOM formats (CycloneDX, SPDX) so our existing SBOMs work without conversion.

## Acceptance Criteria

- [ ] `sbom` and `component` tables added to schema with proper foreign keys and indexes
- [ ] CycloneDX JSON parsing extracts components with name, version, purl, license, supplier, type
- [ ] CycloneDX XML parsing extracts the same fields
- [ ] SPDX JSON parsing extracts components with the same fields
- [ ] SPDX tag-value parsing extracts components with the same fields
- [ ] Format auto-detection works without user specifying format
- [ ] Parse errors are captured and stored (partial parse succeeds with warnings)
- [ ] After upload, SBOM is parsed and `parsed_at` + `component_count` are set
- [ ] Re-parse action available (deletes old components, re-parses)
- [ ] Drizzle migration generated and applies cleanly

## Priority

**High** — Foundational for all M2 features and CRA compliance. Components are the bridge between SBOMs and CVEs.

## Dependencies

- `2026-03-13-rename-project-product-n4r8.md` (product table must exist)
- `2026-03-13-product-sbom-upload-r8w4.md` (SBOM upload flow must exist)

## Implementation Notes

- Create `packages/sbom/` as a new bun workspace package
- Export a `parseSBOM(content: string | Buffer): ParseResult` function
- Use no external SBOM parsing libraries — CycloneDX JSON/XML and SPDX JSON/TV are simple enough to parse directly
- Store raw file in object storage (or filesystem for now), parsed components in DB
- Add `sbom` FK to `product`, `component` FK to `sbom`
- Index `component(sbom_id)` and `component(purl)` for later matching

## Documentation Updates

- Update product detail docs to mention SBOM parsing
- Add SBOM format support matrix to docs
