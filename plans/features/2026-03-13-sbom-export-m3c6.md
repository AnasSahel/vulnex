---
name: SBOM Export
description: Generate and export merged product-level SBOMs in CycloneDX and SPDX formats with VEX data.
date: 2026-03-13
status: proposed
---

# SBOM Export

## Description

### Current problems

1. SBOMs are uploaded per artifact but there is no merged product-level SBOM.
2. CRA requires SBOM delivery with the product — currently no export capability.
3. No VEX (Vulnerability Exploitability eXchange) data is included with SBOMs.

### Target design

Generate a merged product-level SBOM from all artifact SBOMs. Export in CycloneDX and SPDX formats, optionally including VEX data (vulnerability status for each component-CVE match).

**API endpoint:** `GET /api/products/[id]/sbom/export?format=cyclonedx|spdx&include_vex=true|false`

**UI:**

- Download button on product detail page
- Format selector (CycloneDX JSON, SPDX JSON)
- Toggle to include VEX data
- Preview of SBOM metadata before download

**Merge logic:**

- Combine all component lists from all SBOMs for the product
- Deduplicate components by purl (keep the most recent version if duplicates exist)
- Set product-level metadata (name, version, manufacturer from CRA metadata)
- Optionally embed VEX: for each component-CVE match, include status (affected/not_affected/under_investigation)

## User Stories

1. As a manufacturer, I want to export a product-level SBOM to deliver with my product per CRA requirements.
2. As a compliance officer, I want VEX data included so recipients know which vulnerabilities are actually exploitable.
3. As a developer, I want to download the merged SBOM in standard formats for integration with other tools.

## Acceptance Criteria

- [ ] API endpoint generates CycloneDX JSON format SBOM
- [ ] API endpoint generates SPDX JSON format SBOM
- [ ] Merged SBOM contains deduplicated components from all product SBOMs
- [ ] Product metadata (name, manufacturer) is included in exported SBOM
- [ ] VEX data is optionally included with vulnerability status per component
- [ ] Download button on product detail page works
- [ ] Format selector allows choosing between CycloneDX and SPDX
- [ ] Generated SBOM validates against format spec (CycloneDX schema, SPDX schema)
- [ ] Large products (1000+ components) export without timeout
- [ ] `bun run build` succeeds

## Priority

**Medium** — Required for CRA compliance but depends on having good component data first.

## Dependencies

- `2026-03-13-sbom-parser-m2a1.md` (components must be parsed)
- `2026-03-13-cra-product-metadata-m3a2.md` (manufacturer info for SBOM metadata)

## Implementation Notes

- Reuse `packages/sbom/` package — add export functions alongside parsing
- CycloneDX export: generate JSON following CycloneDX 1.5+ spec
- SPDX export: generate JSON following SPDX 2.3 spec
- VEX in CycloneDX uses the `vulnerabilities` array
- VEX in SPDX uses external VEX document (CSAF or OpenVEX format)
- Streaming response for large SBOMs to avoid memory issues
- Set Content-Disposition header for file download

## Documentation Updates

- Document SBOM export feature and supported formats
- Add guide on VEX data and how to interpret it
