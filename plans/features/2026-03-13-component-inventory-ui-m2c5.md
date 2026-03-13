---
name: Component Inventory UI
description: Product detail page tab showing all components across SBOMs with filtering, sorting, and license breakdown.
date: 2026-03-13
status: proposed
---

# Component Inventory UI

## Description

Add a dedicated components section to the product detail page. This provides a full inventory of all software components extracted from the product's SBOMs, with filtering, sorting, and a license summary view. The component inventory is a key CRA deliverable -- manufacturers must know exactly what is inside their products.

### Current problems

1. There is no UI to view parsed component data -- users can only see SBOM file metadata (filename, format, upload date).
2. No way to see the aggregate component picture across multiple SBOMs for a product.
3. No visibility into license distribution, which is important for both compliance and legal review.
4. No way to navigate from a component to the CVEs that affect it.

### Target design

**Route:** `/dashboard/products/[id]/components`

**Components table:**
- Columns: Component Name, Version, purl, License, Supplier, Source SBOM, CVE Count
- Each row links to a component detail view or expands to show linked CVEs
- CVE Count is a badge showing the number of matched CVEs (from `component_cve`)
- Source SBOM shows which SBOM file the component was extracted from

**Filtering:**
- Filter by SBOM (dropdown of all SBOMs for this product)
- Filter by component type (library, framework, application, os)
- Search by component name

**Sorting:**
- Sort by CVE count (descending, default) to surface riskiest components first
- Sort by name (alphabetical)
- Sort by version

**Component detail (click-through or expandable row):**
- Show all linked CVEs with severity, EPSS score, KEV status
- Show component metadata (full purl, license, supplier, type)
- Link to the source SBOM

**License summary view:**
- Pie chart or horizontal bar breakdown of license distribution across all components
- Shows: license name, component count, percentage
- Highlights unknown/missing licenses

**Navigation:**
- Tab or link on the product detail page alongside existing CVEs and SBOMs sections
- Breadcrumb: Products > [Product Name] > Components

## User Stories

1. As a product owner, I want to see all software components in my product so I understand my dependency surface.
2. As a security analyst, I want to sort components by CVE count so I can prioritize remediation of the riskiest dependencies.
3. As a compliance officer, I want a license breakdown so I can verify all components have acceptable licenses.
4. As a user, I want to filter components by SBOM so I can review each artifact independently.
5. As a user, I want to click a component to see its linked CVEs so I can assess the risk of a specific dependency.

## Acceptance Criteria

- [ ] `/dashboard/products/[id]/components` route exists and renders the component table
- [ ] Table shows columns: Name, Version, Purl, License, Supplier, SBOM filename, CVE count
- [ ] Filter by SBOM works (dropdown populated from product's SBOMs)
- [ ] Filter by component type works
- [ ] Search by component name works
- [ ] Sort by CVE count (default descending), name, and version works
- [ ] Clicking a component shows its linked CVEs with severity and EPSS data
- [ ] License summary view shows distribution as a chart or breakdown
- [ ] Unknown/missing licenses are highlighted
- [ ] Pagination at 50 rows per page
- [ ] Empty state shown when product has no parsed SBOMs
- [ ] Tab/link accessible from the product detail page navigation
- [ ] Server query uses efficient joins (no N+1 queries)
- [ ] Responsive layout for smaller screens
- [ ] `bun run build` succeeds

## Priority

**Medium** -- Important for CRA compliance visibility but not a blocker for other M2 features.

## Dependencies

- SBOM Parser (M2-1, `2026-03-13-sbom-parser-m2a1.md`) -- provides parsed component data
- Component to CVE Auto-Matching (M2-2, `2026-03-13-component-cve-matching-m2b3.md`) -- provides CVE counts per component (UI can render without this, showing 0 CVEs)

## Implementation Notes

- Add `getProductComponents(productId)` query in `app/src/lib/queries/products.ts`
- Query components joined with `component_cve` count: `SELECT component.*, COUNT(component_cve.id) as cve_count FROM component LEFT JOIN component_cve ON ... GROUP BY component.id`
- For the license chart, aggregate in a server query: `SELECT license, COUNT(*) FROM component WHERE sbom_id IN (product's sboms) GROUP BY license`
- Use existing Shadcn UI table components with sorting/filtering patterns from the CVE table
- Pagination at 50 rows per page -- some SBOMs have thousands of components
- The license pie chart can use a lightweight chart library already in the project, or a simple CSS-based horizontal bar chart
- Component detail can be an expandable row (accordion) rather than a separate page to reduce navigation friction
- Add "Components" tab to product detail page navigation alongside existing tabs
- Reuse `CveTable` component for the expanded CVE list per component

## Documentation Updates

- Update product detail page docs to include the components tab
- Document the license visibility feature
