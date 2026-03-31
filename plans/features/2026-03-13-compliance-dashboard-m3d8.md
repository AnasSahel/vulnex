---
name: Compliance Dashboard
description: Cross-product CRA compliance scoring, SLA tracking, and exportable audit reports.
date: 2026-03-13
status: proposed
---

# Compliance Dashboard

## Description

### Current problems

1. No aggregate view of CRA compliance readiness across products.
2. No compliance scoring to track progress toward full CRA compliance.
3. No exportable reports for auditors or regulatory bodies.
4. No SLA metrics for vulnerability remediation performance.

### Target design

A top-level compliance dashboard showing per-product and cross-product compliance scores, SLA tracking, and exportable reports.

**Route:** `/dashboard/compliance` (new top-level nav item)

**Compliance score (0-100%) per product:**

Based on weighted criteria:
- SBOM completeness: at least one parsed SBOM with components (20%)
- CRA metadata filled: manufacturer, category, support period (20%)
- Vulnerability remediation: % of CVEs in remediated/accepted state (30%)
- Disclosure SLA adherence: no overdue reporting deadlines (20%)
- SBOM freshness: most recent SBOM uploaded within 90 days (10%)

**Cross-product overview:**

- Product list sorted by compliance score (lowest first)
- Color-coded scores: green (80-100%), yellow (50-79%), red (0-49%)
- Aggregate stats: total products, average score, products with overdue SLAs

**Per-product breakdown:**

- Click product to see detailed compliance breakdown
- Each criterion shows: status (pass/fail/partial), score contribution, actionable next step
- History chart showing compliance score over time (weekly snapshots)

**SLA tracking:**

- Time-to-remediate metrics: average, median, P90 across all products
- Overdue count with drill-down to specific CVEs
- Trend chart: remediation performance over time

**Export:**

- PDF compliance report per product (for auditors)
- CSV export of all compliance data
- Report includes: product info, SBOM summary, vulnerability status, compliance score breakdown

## User Stories

1. As a CISO, I want a cross-product compliance view so I can see which products need attention.
2. As a compliance officer, I want exportable reports so I can provide evidence to auditors.
3. As a product owner, I want actionable compliance breakdowns so I know exactly what to fix.
4. As a manager, I want SLA metrics so I can track my team's vulnerability response performance.

## Acceptance Criteria

- [ ] `/dashboard/compliance` route renders the compliance dashboard
- [ ] Compliance score calculated per product based on the 5 weighted criteria
- [ ] Cross-product overview shows all products sorted by score
- [ ] Scores are color-coded: green (80-100%), yellow (50-79%), red (0-49%)
- [ ] Aggregate stats displayed: total products, average score, overdue SLA count
- [ ] Click product to see detailed compliance breakdown with actionable items
- [ ] SLA metrics: average/median/P90 time-to-remediate
- [ ] Compliance score history chart (weekly snapshots)
- [ ] PDF report export per product
- [ ] CSV export of compliance data
- [ ] "Compliance" item added to sidebar navigation
- [ ] Empty state when no products exist
- [ ] `bun run build` succeeds

## Priority

**Medium** — Capstone feature that ties everything together. Only valuable once M1, M2, and M3-1/M3-2 are complete.

## Dependencies

- `2026-03-13-cra-product-metadata-m3a2.md` (CRA metadata for scoring)
- `2026-03-13-vulnerability-disclosure-m3b4.md` (disclosure status for scoring)
- `2026-03-13-sbom-export-m3c6.md` (SBOM completeness for scoring)

## Implementation Notes

- Compliance score computation in a server query function: `getProductComplianceScore(productId)`
- Score calculation queries multiple tables — cache results or compute on-demand with reasonable indexes
- Weekly snapshots: store in a `compliance_snapshot` table (product_id, score, breakdown_json, snapshot_date)
- Snapshot job runs weekly (Motia cron step or manual trigger)
- PDF generation: use @react-pdf/renderer for styled reports
- Add "Compliance" to sidebar navigation after "Exploits"
- Dashboard should be fast even with many products — use aggregate queries, not per-product loops

## Documentation Updates

- Document compliance scoring methodology
- Add guide on interpreting compliance reports
- Document CRA compliance requirements and how VulneX maps to them
