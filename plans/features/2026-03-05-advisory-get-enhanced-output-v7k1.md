---
name: Advisory Get Enhanced Output
description: Improve the advisory get detail view with word wrapping, markdown stripping, version ranges, reference labels, and UX polish.
date: 2026-03-05
status: completed
---

# Advisory Get Enhanced Output

## Description

The `advisory get` command's detail view has several readability issues: raw markdown in descriptions, no word wrapping (lines break mid-word at terminal edge), duplicate Updated/Published dates, missing vulnerable version ranges, unlabeled references, verbose "no fix available" text, and no hint about `--long` when descriptions are truncated.

This feature addresses all seven issues to produce a polished, scannable detail view.

## User Stories

- As a user, I want the description to wrap at word boundaries so I can read it without mid-word breaks.
- As a user, I want markdown headings stripped or styled so the output looks clean in my terminal.
- As a user, I want to see the vulnerable version range alongside the fix version so I know which versions are affected.
- As a user, I want reference URLs labeled (Patch, Advisory, NVD) so I can quickly find what I need.

## Acceptance Criteria

- [x] Description text wraps at word boundaries (max 80 chars per line).
- [x] Markdown headings (`#`, `##`, `###`) are stripped or rendered as bold labels.
- [x] Updated date is hidden when truncated date matches Published date.
- [x] Affected Packages show vulnerable version range (e.g. `>= 4.0.0, < 4.17.23`).
- [x] "no fix available" shortened to `no fix`.
- [x] References tagged with labels based on URL patterns (Patch, Advisory, NVD).
- [x] Truncated descriptions show `(use --long for full output)` hint.
- [x] `go build ./...` passes.

## Implementation Details

### Files modified

- `internal/output/table.go` — Rewrite `FormatAdvisory` method:
  1. Add `wordWrap(text string, width int) string` helper.
  2. Add `stripMarkdownHeadings(text string) string` helper.
  3. Add `labelReference(url string) string` helper.
  4. Fix Updated vs Published date comparison (compare truncated forms).
  5. Show version range from `AffectedPkg.Ranges`.
  6. Shorten "no fix available" to "no fix".
  7. Add `--long` hint after truncated description.

- `cmd/advisory_get.go` — Pass `VulnerableVersionRange` through to `model.AffectedPkg.Ranges` using existing `parseVersionRange`.

- `model/reference.go` — No changes needed (AffectedPkg already has Ranges field).

### Word wrap approach

Simple word-boundary wrap: split on spaces, accumulate words until line exceeds width, then break. Preserve existing newlines. Indent continuation lines with 2 spaces to match the section indent.

### Reference labeling

Pattern-based URL classification:
- Contains `/commit/` or `/pull/` → `[Patch]`
- Contains `nvd.nist.gov` → `[NVD]`
- Contains `/advisories/` or `/security/` → `[Advisory]`
- Otherwise → no label

## Priority

**Medium** — UX polish for advisory detail view.

## Dependencies

- `internal/output/table.go` — Existing FormatAdvisory method
- `internal/api/ghsa/client.go` — Existing parseVersionRange function

## Testing Commands

```bash
go build ./...
go run . advisory get GHSA-xxjr-mmjv-4gpg
go run . advisory get GHSA-xxjr-mmjv-4gpg --long
go run . advisory get GHSA-g9w5-qffc-6762
```

## Documentation

- No README changes needed.
- Website advisory docs page will be updated if one exists.
