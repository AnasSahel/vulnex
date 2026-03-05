---
name: Improve CLI Flag Descriptions and Add Examples
description: Rewrite unclear flag descriptions across all commands with plain-language wording and add usage examples for scoring weight flags.
date: 2026-03-05
status: completed
---

# Improve CLI Flag Descriptions and Add Examples

## Description

Several CLI flag descriptions use terse, jargon-heavy wording that assumes users already know what the flag does. The scoring weight flags (`--cvss-weight`, `--epss-weight`, `--kev-weight`) are the most confusing -- "Custom CVSS weight (0.0-1.0), overrides profile" doesn't explain *what* a weight does, *why* you'd change it, or *what happens* when you set it.

This is a documentation and UX improvement that touches:
1. **Cobra flag help strings** in `cmd/*.go` -- the text shown by `--help`
2. **Command `Example` fields** -- add concrete examples showing weight flags in action
3. **README.md** flag tables -- match the improved wording
4. **Website docs** -- match the improved wording

## User Stories

- As a new user, I want flag descriptions in `--help` to explain what the flag *does*, not just its value range, so I can use the tool without reading external docs.
- As a security engineer, I want examples showing how weight flags change scoring output so I can configure scoring for my team's priorities.
- As a developer integrating vulnex into CI, I want to understand flags like `--strict`, `--enrich`, and `--vex` from their help text alone.

## Acceptance Criteria

- [x] All 10 flags listed above have updated descriptions in their respective `cmd/*.go` files.
- [x] `vulnex enrich --help` and `vulnex cve get --help` show examples with weight flags.
- [x] `vulnex prioritize --help` shows examples with weight flags.
- [x] README.md flag tables match the updated descriptions.
- [x] Website docs (`cve.astro`) match the updated descriptions.
- [x] `go build ./...` succeeds.
- [x] `go test ./...` passes.

## Priority

**High** - Unclear flags are a barrier to adoption. Users who don't understand `--cvss-weight` won't use scoring at all.

## Dependencies

- No code logic changes -- descriptions only.

## Implementation Details

### Files modified

- `cmd/enrich.go` -- Updated flag descriptions + added scoring examples to `Example` field
- `cmd/cve_get.go` -- Updated flag descriptions + added scoring examples to `Example` field
- `cmd/prioritize.go` -- Updated flag descriptions for `--from`, `--strict`, scoring weights + added examples
- `cmd/root.go` -- Updated `--timeout` description with unit examples
- `cmd/scan.go` -- Updated `--vex`, `--enrich`, `--strict` descriptions
- `cmd/sbom.go` -- Updated `--vex`, `--enrich`, `--strict` descriptions (both `sbomCheckCmd` and `sbomDiffCmd`)
- `README.md` -- Updated flag tables for scan, enrich, sbom check, sbom diff; added custom weights example
- `website/src/pages/docs/cve.astro` -- Updated scoring flag descriptions in the flags table

### Summary of description changes

| Flag | Before | After |
|------|--------|-------|
| `--cvss-weight` | "Custom CVSS weight (0.0-1.0), overrides profile" | "How much severity (CVSS) influences the final score, from 0.0 (ignore) to 1.0 (full weight)" |
| `--epss-weight` | "Custom EPSS weight (0.0-1.0), overrides profile" | "How much exploit probability (EPSS) influences the final score, from 0.0 (ignore) to 1.0 (full weight)" |
| `--kev-weight` | "Custom KEV weight (0.0-1.0), overrides profile" | "How much known-exploited status (KEV) influences the final score, from 0.0 (ignore) to 1.0 (full weight)" |
| `--scoring-profile` | "Scoring profile: default, exploit-focused, severity-focused" | "Preset weight balance for scoring: default (balanced), exploit-focused, or severity-focused" |
| `--timeout` | "HTTP request timeout" | "HTTP request timeout (e.g., 30s, 1m, 2m30s)" |
| `--vex` | "Output an OpenVEX document instead of a table" | "Output a VEX (Vulnerability Exploitability eXchange) document for sharing triage decisions" |
| `--enrich` | "Enrich findings with EPSS, KEV, CVSS, and exploit data" | "Add exploit likelihood, known-exploitation status, and severity scores from multiple sources" |
| `--from` | "Input format hint: trivy, grype, sarif (auto-detected if omitted)" | "Input format: trivy, grype, or sarif (auto-detected from file content if omitted)" |
| `--strict` | "Ignore suppression file and report all findings" | "Show all findings, including those suppressed by .vulnexignore" |

### Note on `--no-rejected`

The `--no-rejected` flag was not changed because it already has `true` as its default value in the Cobra definition, and Cobra shows defaults in `--help` output automatically. Adding "(enabled by default)" to the string would be redundant.

## Testing Commands

```bash
# Verify build and tests pass
go build ./...
go test ./...

# Check help output for updated descriptions
go run . enrich --help
go run . cve get --help
go run . prioritize --help
go run . scan --help
go run . sbom check --help

# Verify website builds
cd website && npx astro build
```
