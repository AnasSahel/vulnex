---
name: Correlate Command
description: Add `vulnex correlate` to find relationships between CVEs — shared CWE families, same-library clusters, and attack chain grouping.
date: 2026-03-09
status: proposed
---

# Correlate Command

## Description

When triaging a scan result with 40+ CVEs, engineers treat each one in isolation. But vulnerabilities are often related — 5 CVEs might all be in your logging stack, 3 might share the same CWE weakness class, and 2 might form an exploit chain (initial access + privilege escalation). Understanding these clusters dramatically changes triage priority.

`vulnex correlate` takes a set of CVEs (from stdin, SBOM, or direct args) and groups them by relationship, surfacing patterns that flat lists hide.

### Current problems

1. `sbom check` and `prioritize` output flat lists sorted by severity — no grouping
2. Users manually cross-reference CWE IDs to understand weakness patterns
3. No way to see "your Jackson dependency has 4 CVEs" as a single triage unit
4. Attack chain relationships (e.g., SSRF → RCE) aren't surfaced

### Target design

```
$ vulnex correlate --from-sbom bom.json

 CORRELATION ANALYSIS  42 CVEs → 8 clusters

 ■ LIBRARY CLUSTERS
 ┌─ jackson-databind (4 CVEs)
 │  CVE-2022-42003  P1  Polymorphic deserialization
 │  CVE-2022-42004  P2  Deep nesting DoS
 │  CVE-2020-36518  P2  Deep nesting DoS
 │  CVE-2020-36189  P3  Gadget chain RCE
 │  ➜ Recommendation: upgrade jackson-databind to ≥2.14.0 (fixes all 4)
 └─

 ■ WEAKNESS CLUSTERS (by CWE family)
 ┌─ CWE-502: Deserialization (6 CVEs)
 │  Affects: jackson-databind, commons-collections, snakeyaml
 │  ➜ Pattern: Java deserialization surface is overexposed
 └─
 ┌─ CWE-79: XSS (3 CVEs)
 │  Affects: spring-web, thymeleaf
 └─

 ■ PRIORITY SUMMARY
 Fixing jackson-databind + snakeyaml resolves 7 of 42 CVEs (17%)
 Top 3 libraries account for 15 CVEs (36%)
```

Correlation strategies (applied in order):
1. **Library clustering** — group by affected package/library (from GHSA/OSV data)
2. **CWE family clustering** — group by weakness class (from NVD CWE data)
3. **Fix deduplication** — identify single upgrades that resolve multiple CVEs
4. **Priority aggregation** — rank clusters by combined risk, not individual CVEs

## User Stories

1. As a security engineer triaging 50 CVEs from a scan, I want to see them grouped by library so I can prioritize one upgrade that fixes many.
2. As a developer, I want to understand weakness patterns in my dependencies (too many deserialization issues → architectural concern).
3. As a team lead, I want a summary showing "fix these 3 libraries to resolve 60% of findings" for sprint planning.

## Acceptance Criteria

- [ ] `vulnex correlate <CVE-ID...>` accepts CVE IDs as arguments
- [ ] `--stdin` reads CVE IDs from stdin (pipe from other commands)
- [ ] `--from-sbom <path>` correlates all CVEs found in an SBOM
- [ ] `--from-scan <path>` correlates CVEs from a scanner output (Trivy/Grype/SARIF)
- [ ] Library clusters group CVEs by affected package name
- [ ] CWE clusters group CVEs by weakness family
- [ ] Fix recommendations show when a single upgrade resolves multiple CVEs
- [ ] Priority summary shows effort-to-impact ratio (fewest fixes for most CVEs)
- [ ] All output formats supported (table, json, csv, markdown, yaml)
- [ ] Works with enrichment data — automatically enriches CVEs if not cached
- [ ] Snapshots are saved for all correlated CVEs (builds temporal history)

## Priority

**Medium** — High value but depends on both snapshots and watch diff being stable. More complex data correlation logic.

## Dependencies

- **Temporal Snapshots** (`2026-03-09-temporal-snapshots-a3k7.md`) — for saving snapshots during correlation
- Watch diff is not a hard dependency but should ship first as it's simpler and higher impact

## Implementation Notes

- New files: `cmd/correlate.go`, `internal/correlator/correlator.go`
- The correlator needs access to: enriched CVE data (CWE IDs, affected packages), GHSA/OSV data (package versions, fix versions)
- Library clustering: extract package names from GHSA advisories and OSV affected entries, group CVEs that share a package
- CWE clustering: map CWE IDs to CWE families/categories (top-level groups). A static mapping of ~50 common CWE families is sufficient — no need to fetch the full MITRE CWE tree.
- Fix recommendations: if OSV/GHSA provides a "fixed in version" field, check if multiple CVEs share the same fix
- The correlator should be a separate package (`internal/correlator/`) — it orchestrates enrichment but has its own grouping logic
- Output should use the standard `app.Formatter` for json/csv/yaml but custom styled table for the grouped terminal output

## Documentation Updates

- **Website docs**: New `correlate` docs page in the commands section
- **README.md**: Add correlation to the feature list, update the "How it works" section
