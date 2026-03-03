# I Built a CLI That Diffs Your SBOMs for Vulnerabilities

Every dependency bump is a gamble.

You upgrade lodash to patch a command injection vulnerability. The CI pipeline goes green. You merge the PR. But somewhere in the transitive dependency tree, the upgrade pulled in a new version of a library you've never heard of -- and it has three unpatched CVEs.

Most teams don't catch this. They run a vulnerability scan periodically, get a report with 200 findings, and add it to the triage backlog. The delta -- what actually changed between this scan and the last one -- gets lost in the noise.

I built a command to fix that.

## The problem: scanning is not diffing

SBOM-based vulnerability scanners are good at answering "what's vulnerable right now?" They parse your CycloneDX or SPDX file, query advisory databases, and produce a list.

But in a CI/CD pipeline, the question that matters is different: "did this change make things better or worse?"

If your main branch has 55 known vulnerabilities and a PR introduces 3 new ones while fixing 2, that PR made your security posture worse. You want to catch that before it merges, not in next week's scan report.

This is what `vulnex sbom diff` does. It compares two SBOM files -- typically the main branch and the PR branch -- and tells you exactly which vulnerabilities were added, removed, or unchanged.

## How it works

The command takes two SBOM files:

```bash
vulnex sbom diff main-bom.json pr-bom.json
```

vulnex parses both files, queries vulnerability databases for every component in each SBOM, then computes the set difference. Each vulnerability finding is keyed by a combination of ecosystem, package name, version, and advisory ID, so the comparison is precise down to the individual finding.

The output is split into three buckets:

```
+ ADDED (2 vulnerabilities)
  flask 0.12.0 (PyPI)
    GHSA-562c-5r94-xh97       HIGH      0.12.3   Flask is vulnerable to Denial of...

- REMOVED (3 vulnerabilities)
  lodash 4.17.20 (npm)
    GHSA-35jh-r3h4-6jhm       HIGH      4.17.21  Command Injection in lodash

= UNCHANGED (55 vulnerabilities)
  django 3.2.0 (PyPI)
    GHSA-2gwj-7jmv-h26r       CRITICAL  2.2.28   SQL Injection in Django

Summary: old=3 components (58 vulns), new=4 components (57 vulns), +2 added, -3 removed
```

At a glance you see: the lodash upgrade fixed the command injection (good), but adding flask 0.12.0 introduced a high-severity denial of service (bad). That's the kind of insight that changes how you review a PR.

## The exit code is the feature

The most important thing `vulnex sbom diff` does isn't the output -- it's the exit code.

- **Exit 0**: No new vulnerabilities were introduced. The change is safe (or neutral) from a security standpoint.
- **Exit 1**: New vulnerabilities were added. The pipeline should fail.

This behavior is intentional. Removing vulnerabilities is always fine. Keeping existing ones is acceptable (you already know about them). But introducing new ones should require explicit acknowledgment.

This means you can drop it into any CI pipeline as a gate:

```bash
vulnex sbom diff main-bom.json pr-bom.json || exit 1
```

If the diff finds added vulnerabilities, the build fails. No configuration, no thresholds to tune, no dashboard to check.

## GitHub Actions integration

Here's a practical workflow. Generate an SBOM for the main branch, generate one for the PR branch, and diff them:

```yaml
name: SBOM Vulnerability Gate
on: pull_request

jobs:
  vuln-diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install vulnex
        run: go install github.com/trustin-tech/vulnex@latest

      - name: Generate main branch SBOM
        run: |
          git checkout ${{ github.event.pull_request.base.sha }}
          # Use your SBOM generator (syft, cdxgen, etc.)
          syft . -o cyclonedx-json > main-bom.json

      - name: Generate PR branch SBOM
        run: |
          git checkout ${{ github.sha }}
          syft . -o cyclonedx-json > pr-bom.json

      - name: Diff vulnerabilities
        run: vulnex sbom diff main-bom.json pr-bom.json
```

If the PR introduces new vulnerabilities, the action fails. If it only removes or preserves existing ones, it passes. The developer sees exactly which new findings were introduced in the action logs.

## Filtering by severity

Not every team wants to block a PR over a low-severity finding. You can filter the diff to only consider vulnerabilities at or above a given severity:

```bash
# Only fail on critical or high additions
vulnex sbom diff main-bom.json pr-bom.json --severity high
```

You can also filter by ecosystem if you only care about certain parts of your stack:

```bash
# Only check npm dependencies
vulnex sbom diff main-bom.json pr-bom.json --ecosystem npm
```

## JSON output for automation

For pipelines that need to parse the results programmatically, use JSON output:

```bash
vulnex sbom diff main-bom.json pr-bom.json -o json
```

This gives you a structured object with `added`, `removed`, and `unchanged` arrays. Each entry includes the ecosystem, package name, version, advisory ID, severity, fixed version, and summary. Feed it into jq, post it to Slack, or attach it to the PR as a comment.

## Why this matters

The security industry has spent years building tools that generate reports. What it hasn't built enough of are tools that fit into the developer workflow -- tools that run in CI, return a pass/fail, and show you exactly what changed.

SBOM diffing is not a new concept, but having it as a single command with sensible exit codes and no configuration makes it practical. You can add it to a pipeline in five minutes and immediately start catching regressions.

If you're already generating SBOMs (and you should be), you're one command away from turning them into a security gate.

## Try it

Install vulnex and try it on your own SBOMs:

```bash
brew install AnasSahel/tap/vulnex
vulnex sbom diff old-bom.json new-bom.json
```

The source code is on [GitHub](https://github.com/AnasSahel/vulnex). It's MIT-licensed and written in Go. Star the repo if you find it useful.

---

*This is part 2 of a 3-part series on practical vulnerability management with vulnex. Previously: "The problem with vulnerability management in 2026." Next up: "5 vulnerability workflows you can automate from your terminal."*
