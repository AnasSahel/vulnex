---
name: SBOM Command Documentation Page
description: Add a comprehensive website docs page for the sbom command (sbom check and sbom diff), update docs-nav.ts with sbom entry and subcommands, and update demos.ts with an sbom check demo tab.
date: 2026-03-05
status: completed
---

# SBOM Command Documentation Page

## Description

The `sbom` command is one of the most feature-rich commands in vulnex (check, diff, VEX, enrichment, suppression, policy) but has no dedicated documentation page on the website. Users have to read `--help` output or guess at workflows. This feature adds a full docs page covering both subcommands, all supported formats, enrichment, VEX, suppression, CI gating, and how sbom relates to `scan` and `prioritize`.

Key sections:
1. Overview with pain points the command solves.
2. `sbom check` — usage, examples (lockfile, SBOM, enriched, VEX), full flags table.
3. `sbom diff` — usage, examples (basic diff, CI gate), flags table.
4. Supported formats grid — CycloneDX, SPDX, and 9 lockfile formats.
5. Enrichment section explaining `--enrich` (EPSS, KEV, CVSS, exploit, risk priority).
6. VEX output section explaining `--vex`.
7. Suppression section explaining `.vulnexignore` integration.
8. Comparison table: `sbom check` vs `scan` vs `prioritize` — when to use which.
9. Tips & recipes: CI pipelines, enrichment pipelines, ecosystem filtering.
10. Related commands.

Also:
- Update `docs-nav.ts` with sbom entry (subcommands: sbom check, sbom diff).
- Update `demos.ts` with an `sbom check` demo tab showing enriched output.

## User Stories

- As a user, I want to understand what `sbom check` does so I know when to use it instead of `scan` or `prioritize`.
- As a user, I want examples of scanning a lockfile and an SBOM so I can get started quickly.
- As a user, I want to know all supported lockfile formats so I can check if mine is covered.
- As a user, I want to understand `--enrich` so I know what extra data it adds and when to use it.
- As a user, I want to understand `--vex` so I can share vulnerability triage decisions.
- As a user, I want to see how `sbom diff` works in CI so I can gate PRs on new vulnerabilities.
- As a user, I want a clear comparison between sbom check, scan, and prioritize so I pick the right command.

## Acceptance Criteria

- [ ] New `website/src/pages/docs/sbom.astro` page with all sections listed above.
- [ ] `docs-nav.ts` updated with sbom entry under Commands with subcommands `sbom check` and `sbom diff`.
- [ ] `demos.ts` updated with an sbom check demo showing enriched output with EPSS/KEV/priority.
- [ ] Page follows the same layout/style patterns as existing docs pages (exploit.astro, prioritize.astro).
- [ ] `npm run build` passes in the website directory.
- [ ] No README changes needed (already documented).

## Implementation Details

### Files modified

#### `website/src/pages/docs/sbom.astro` (new)
New docs page with sections:
- **Overview**: badge, title, lead paragraph, pain points box, subcommand cards for `sbom check` and `sbom diff`.
- **sbom check**: usage, 4 terminal examples (lockfile scan, SBOM scan, enriched scan, VEX output), flags table.
- **sbom diff**: usage, 2 terminal examples (basic diff, CI gate), flags table.
- **Supported formats**: grid of cards — CycloneDX JSON, SPDX JSON, and 9 lockfile formats grouped by ecosystem.
- **Enrichment**: explanation of `--enrich` flag, what data it adds (EPSS, KEV, CVSS, exploit status, risk priority).
- **VEX output**: explanation of `--vex` flag, what a VEX document is, when to use it.
- **Suppression**: brief explanation with link to suppress demo/docs.
- **When to use which**: comparison table between `sbom check`, `scan`, and `prioritize`.
- **Tips & recipes**: CI pipeline, enrichment pipeline, ecosystem filtering.
- **Related commands**: links to prioritize, exploit, scoring, cve get.

#### `website/src/content/docs-nav.ts`
Add sbom entry under Commands:
```ts
{
  slug: "sbom", title: "sbom", description: "Parse SBOMs and lockfiles, check for vulnerabilities, diff between versions, and generate VEX documents.",
  subcommands: [
    { id: "sbom-check", label: "sbom check" },
    { id: "sbom-diff", label: "sbom diff" },
  ],
},
```

#### `website/src/content/demos.ts`
Update the existing `sc-lockfile` demo (which uses `vulnex scan`) to show `vulnex sbom check` with enriched output, or add a new demo tab for sbom check with enrichment. Keep existing demos intact.

### Target terminal examples

**sbom check — lockfile:**
```
$ vulnex sbom check pnpm-lock.yaml
Parsed 847 components from pnpm-lock.yaml
Querying OSV for 847 components...
Found 4 vulnerabilities

postcss 8.4.14 (npm)
  ID                        Severity  Fixed    Summary
  GHSA-7fh5-64p2-3v2j      MEDIUM    8.4.31   Parsing error in PostCSS

semver 6.3.0 (npm)
  GHSA-c2qf-rxjj-qqgw      MEDIUM    6.3.1    semver vuln to ReDoS

Summary: 847 components scanned, 2 vulnerable, 4 findings
  MEDIUM: 4
```

**sbom check — enriched:**
```
$ vulnex sbom check bom.json --enrich
Parsed 12 components from bom.json
Querying OSV for 12 components...
Enriching 3 unique CVE IDs...

golang.org/x/net 0.7.0 (Go)
  ID                  Severity   CVSS   EPSS       KEV   Priority        Fixed
  CVE-2023-44487      HIGH       7.5    94.4%↑     YES   P0-CRITICAL     0.17.0
    → In CISA KEV — confirmed active exploitation, 94% exploitation probability. Patch immediately.
  CVE-2023-39325      HIGH       7.5    0.2%       —     P3-LOW          0.17.0

Summary: 12 components scanned, 1 vulnerable, 2 findings
  HIGH: 2

Prioritization
  Action required    1 finding — patch immediately (P0+P1)
  Can wait           1 finding — low exploitation risk (P2-P4)
  Top priority       CVE-2023-44487 in golang.org/x/net — upgrade to 0.17.0
```

**sbom diff:**
```
$ vulnex sbom diff old-bom.json new-bom.json
Diff: +2 added, -1 removed, =55 unchanged

+ ADDED (2 vulnerabilities)
  flask 0.12.0 (PyPI)
    GHSA-562c-5r94-xh97   HIGH      0.12.3   Flask is vulnerable to...

- REMOVED (1 vulnerability)
  lodash 4.17.20 (npm)
    GHSA-35jh-r3h4-6jhm   HIGH      4.17.21  Command Injection in ...

Summary: old=3 components (56 vulns), new=4 components (57 vulns)
  +2 added  -1 removed
```

## Priority

**Medium** — Documentation-only change, no code changes to the CLI.

## Dependencies

- `cmd/sbom.go` — Existing sbom check and sbom diff commands
- `cmd/scan.go` — Shared `runScanPipeline` function
- `internal/sbom/` — Parser supporting CycloneDX, SPDX, and 9 lockfile formats
- Existing docs page patterns (exploit.astro, prioritize.astro)

## Testing Commands

```bash
cd website && npm run build
```

## Documentation

- New `website/src/pages/docs/sbom.astro` page.
- `docs-nav.ts` updated with sbom entry and subcommands.
- `demos.ts` updated with sbom check demo.
- No README changes needed.
