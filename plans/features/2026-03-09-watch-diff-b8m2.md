---
name: Watch Diff
description: Add `cve watch diff` to show what changed in your watched CVEs since the last check — EPSS spikes, KEV additions, new exploits.
date: 2026-03-09
status: proposed
---

# Watch Diff

## Description

`cve watch --refresh` shows the current state of watched CVEs but doesn't tell you what *changed*. After temporal snapshots are in place (feature 1), we can compare today's snapshot against a previous one and surface meaningful changes.

This is the killer feature — no other CLI vuln tool shows you "CVE-2024-XXXX exploitation probability jumped from 0.12 to 0.67 this week" or "2 watched CVEs were added to KEV since your last check."

### Current problems

1. `cve watch --refresh` is a flat list — same output every time, no sense of what's new
2. Users have to manually remember previous EPSS/CVSS values to notice changes
3. No alerting on critical transitions (not-in-KEV → in-KEV, low-EPSS → high-EPSS)

### Target design

New subcommand: `vulnex cve watch diff`

```
$ vulnex cve watch diff --since 7d

 WATCH LIST CHANGES (last 7 days)  3 of 12 CVEs changed

 ▲ ESCALATED
 CVE-2024-3094     P3 → P0   EPSS 0.12→0.67 (+458%)  Added to KEV
 CVE-2023-44228    P2 → P1   EPSS 0.45→0.78 (+73%)

 ● NEW EXPLOITS
 CVE-2024-21762    +2 exploits (GitHub PoC, Nuclei template)

 ○ STABLE (9 CVEs unchanged)
```

The output groups changes by significance:
- **Escalated** — priority level increased (most important)
- **De-escalated** — priority level decreased (good news)
- **New exploits** — exploit count increased
- **EPSS movement** — significant EPSS change (>20% relative) without priority change
- **Stable** — summary count of unchanged CVEs

Flags:
- `--since <duration>` — compare against snapshot from N days/hours ago (default: 7d)
- `--date <YYYY-MM-DD>` — compare against a specific date
- `--all` — show all CVEs including stable ones
- `--output json` — structured output for CI/CD integration

## User Stories

1. As a security engineer, I want to run `cve watch diff` weekly and instantly see which CVEs need re-triage.
2. As a team lead, I want to pipe `cve watch diff --output json` into a Slack webhook for automated threat updates.
3. As a developer, I want to see "nothing changed" as a quick confirmation that my risk posture is stable.

## Acceptance Criteria

- [ ] `vulnex cve watch diff` compares current enrichment against stored snapshots
- [ ] `--since` flag accepts Go duration format (7d, 24h, 30d)
- [ ] `--date` flag accepts YYYY-MM-DD for exact comparison
- [ ] Changes grouped by type: escalated, de-escalated, new exploits, EPSS movement, stable
- [ ] Priority transitions shown with arrow notation (P3 → P0)
- [ ] EPSS changes shown with delta and percentage
- [ ] KEV additions explicitly called out
- [ ] `--output json` returns structured diff for CI integration
- [ ] `--all` shows stable CVEs too (default hides them)
- [ ] Exit code 1 if any CVE escalated (for CI gating)
- [ ] Graceful handling when no previous snapshot exists ("no baseline — run `cve watch --refresh` first")
- [ ] Works with all output formats (table, json, csv, markdown)

## Priority

**High** — This is the primary user-facing feature of the Threat Intelligence Layer and the main differentiator.

## Dependencies

- **Temporal Snapshots** (`2026-03-09-temporal-snapshots-a3k7.md`) — must be implemented first

## Implementation Notes

- New file: `cmd/cve_watch_diff.go` — subcommand of `cveWatchCmd`
- New file: `internal/model/diff.go` — `WatchDiff`, `CVEChange` types
- Diff logic: load current enrichment + historical snapshot, compute deltas
- The diff command should automatically refresh (enrich + snapshot) before comparing, so users get a one-step workflow
- Consider a significance threshold for EPSS — small fluctuations (±0.01) aren't worth showing
- For table output, use lipgloss styles from `styles.go` (red for escalation, green for de-escalation)

## Documentation Updates

- **Website docs**: New section in the `cve` docs page covering `cve watch diff` with terminal examples
- **README.md**: Add "Threat Intelligence" to the feature list, mention temporal tracking
