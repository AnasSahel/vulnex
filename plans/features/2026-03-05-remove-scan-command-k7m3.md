---
name: Remove scan command, make it a hidden alias for sbom check
description: Remove the top-level `scan` command and make it a hidden alias for `sbom check`. Move shared pipeline code into sbom.go.
date: 2026-03-05
status: completed
---

# Remove scan Command

## Description

The `vulnex scan` command is functionally identical to `vulnex sbom check` — both call `runScanPipeline()` with the same flags. This creates user confusion ("which one do I use?") and doubles documentation/maintenance surface. Since vulnex's value proposition is enrichment and prioritization (not competing with Trivy/Grype as a scanner), `sbom check` is the canonical command.

This feature:
1. Removes `scan` as a visible top-level command.
2. Keeps `scan` working as a **hidden** alias so existing scripts/CI pipelines don't break.
3. Moves `runScanPipeline()` and `enrichFindings()` from `cmd/scan.go` into `cmd/sbom.go` since `sbom check` is the canonical home.
4. Updates all documentation and website references.

## User Stories

- As a new user, I want a single clear command for vulnerability checking so I don't have to choose between `scan` and `sbom check`.
- As a CI pipeline author, I want my existing `vulnex scan` commands to keep working after the update.
- As a documentation reader, I want consistent references to `sbom check` so I'm not confused by two identical commands.

## Acceptance Criteria

- [x] `cmd/scan.go` is deleted.
- [x] `runScanPipeline()` and `enrichFindings()` live in `cmd/sbom.go`.
- [x] `vulnex scan go.sum` still works (hidden alias).
- [x] `vulnex --help` does NOT list `scan` (hidden command).
- [x] `vulnex scan --help` still shows help text with a note that it's an alias for `sbom check`.
- [x] README.md updated: remove `vulnex scan` section, update CI/CD gating line, update quickstart examples.
- [x] Website updated: `sbom.astro` comparison table removes `scan` column, tip box updated, getting-started.astro uses `sbom check`, CiCdSection.astro uses `sbom check`, cicd.ts uses `sbom check`.
- [x] `go build ./...` passes.
- [x] Website `npm run build` passes.

## Implementation Details

### Files modified

#### `cmd/scan.go` (deleted)
Remove entirely. All code moves to `cmd/sbom.go`.

#### `cmd/sbom.go` (modified)
- Move `runScanPipeline()` and `enrichFindings()` into this file.
- Add a hidden `scanCmd` alias in `init()`:
  ```go
  scanCmd := &cobra.Command{
      Use:    "scan <file>",
      Short:  "Alias for 'sbom check'",
      Long:   "This is a hidden alias for 'sbom check'. Use 'vulnex sbom check' instead.",
      Hidden: true,
      Args:   cobra.ExactArgs(1),
      RunE: func(cmd *cobra.Command, args []string) error {
          return runScanPipeline(cmd, args[0])
      },
  }
  // Copy same flags as sbomCheckCmd
  rootCmd.AddCommand(scanCmd)
  ```

#### `README.md` (modified)
- Remove the `### vulnex scan` section entirely.
- Update quickstart examples to use `vulnex sbom check` instead of `vulnex scan`.
- Update CI/CD gating line to reference only `sbom check`.
- Add a note that `vulnex scan` is a hidden alias for backwards compatibility.

#### `website/src/pages/docs/sbom.astro` (modified)
- Remove `scan` column from comparison table (keep `sbom check` and `prioritize`).
- Update tip box: instead of "scan is a shorthand alias", note that `scan` is deprecated in favor of `sbom check`.

#### `website/src/pages/docs/getting-started.astro` (modified)
- Change `vulnex scan go.sum` to `vulnex sbom check go.sum`.

#### `website/src/components/CiCdSection.astro` (modified)
- Change `vulnex scan` reference to `vulnex sbom check`.

#### `website/src/content/cicd.ts` (modified)
- Change `vulnex scan go.sum --severity critical` to `vulnex sbom check go.sum --severity critical`.

## Priority

**Medium** — Reduces confusion and maintenance overhead, no new functionality.

## Dependencies

- `cmd/sbom.go` — existing sbom check command
- `cmd/scan.go` — code to be moved/removed

## Testing Commands

```bash
# Build passes
go build ./...

# Hidden alias works
go run . scan --help
go run . sbom check --help

# scan is NOT in top-level help
go run . --help | grep -c "scan"  # should be 0

# Website builds
cd website && npm run build
```

## Documentation

- README.md: Remove `vulnex scan` section, update examples to `sbom check`.
- Website: Update sbom.astro, getting-started.astro, CiCdSection.astro, cicd.ts.
