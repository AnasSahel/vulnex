# Product & CRA Compliance Roadmap

## Problem

The dashboard redesign introduced a "project" concept as a named collection of CVEs, but the model needs to align with the Cyber Resilience Act (CRA) where the regulatory unit is a **product**. A product contains multiple SBOMs (one per artifact), SBOMs contain components, and components map to CVEs. The current "project" abstraction is too loose to support CRA compliance reporting.

## Design Decisions

### Data Model

The hierarchy is: **Product → SBOMs → Components → CVEs**

- **Product**: top-level entity. Named, versioned, owned by a user. Represents what gets reported for CRA compliance.
- **SBOM**: attached to a product. One per artifact (frontend, backend, container). Stored as file, parsed into components.
- **Component**: extracted from SBOM parsing. Has name, version, purl, license, supplier.
- **CVE**: linked to a product via `product_cve`. Source tracks how it got there (manual, cli, sbom).

For milestone 1, only Product, SBOM (storage), and direct Product→CVE links are built. Component extraction and auto-matching come in milestone 2.

### What "Product" Means

A product is an abstract, named container for CVEs. It is source-agnostic — CVEs can enter from:
- Manual addition (search and link in the UI)
- CLI push (`vulnex push` sends scan results)
- SBOM upload (parsed in milestone 2, stored in milestone 1)
- Automatic repo scanning (future)

This keeps the model flexible while building toward CRA compliance.

### Milestone Structure

**Milestone 1 — Product Foundation** (build now)
- Seed demo data script
- Rename project → product (DB, queries, UI, routes)
- Create Product UI (form + creation flow)
- Add CVEs to product (search + bulk add)
- SBOM upload (storage only, no parsing)
- `vulnex push` CLI command

**Milestone 2 — SBOM Intelligence** (next)
- SBOM parser (CycloneDX + SPDX → components)
- Component → CVE auto-matching
- Component inventory UI
- SBOM diff (version comparison)

**Milestone 3 — CRA Compliance** (future)
- CRA product metadata (manufacturer, category, support period)
- Vulnerability disclosure reporting (remediation tracking)
- SBOM export (merged product-level SBOM)
- Compliance dashboard (completeness score, SLA tracking, reports)

### Renamed Entities

| Before | After |
|--------|-------|
| `project` table | `product` table |
| `project_cve` table | `product_cve` table |
| `/dashboard/projects/[id]` | `/dashboard/products/[id]` |
| Sidebar "Projects" | Sidebar "Products" |
| `getUserProjects()` | `getUserProducts()` |
| `getProjectDetail()` | `getProductDetail()` |
| `getProjectCVEs()` | `getProductCVEs()` |
| `ProjectSummary` type | `ProductSummary` type |

## Out of Scope

- Multi-tenancy / organization-level products
- Automated repo scanning (GitHub/GitLab integration)
- Real-time EPSS monitoring alerts
- Paid tier gating
