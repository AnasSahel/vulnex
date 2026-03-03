# 5 Vulnerability Workflows You Can Automate from Your Terminal

Over the past two articles, I introduced [vulnex](https://github.com/AnasSahel/vulnex) and went deep on SBOM diffing. In this final piece, I want to get practical. Here are five workflows you can run from your terminal today, each one a building block for automating vulnerability management in your team.

All of these use vulnex, an open-source CLI that aggregates data from NVD, CISA KEV, EPSS, GitHub advisories, and OSV.dev. Install it with Homebrew and follow along:

```bash
brew install AnasSahel/tap/vulnex
```

## Workflow 1: Enrich a CVE with every available source

**The scenario**: A new CVE drops. Your team needs to decide whether to patch now, schedule it, or deprioritize it. You need the full picture -- severity, exploitation probability, whether it's actively exploited, and which packages are affected.

**The command**:

```bash
vulnex enrich CVE-2021-44228
```

This single command queries NVD, CISA KEV, EPSS, GitHub Advisory Database, and OSV.dev, then presents a unified view. You get the CVSS score, the EPSS exploitation probability, KEV status, affected packages with fixed versions, and a composite risk priority from P0 (drop everything) to P4 (backlog it).

For multiple CVEs, just list them:

```bash
vulnex enrich CVE-2024-3094 CVE-2023-44228 -o json
```

The `-o json` flag gives you structured output you can pipe into other tools or post to a Slack channel.

**Why it matters**: Instead of opening five browser tabs and cross-referencing manually, you get a prioritized triage decision in seconds. The composite scoring catches cases where signals disagree -- like a CVSS 9.8 that nobody is actually exploiting (P3), or a CVSS 6.5 that attackers are hammering daily (P1).

## Workflow 2: Scan an SBOM for all known vulnerabilities

**The scenario**: You have a CycloneDX or SPDX file from your build pipeline. You want to know every known vulnerability affecting your dependencies, grouped by component and sorted by severity.

**The command**:

```bash
vulnex sbom check bom.json
```

vulnex parses the SBOM, identifies the ecosystem for each component (npm, PyPI, Maven, Go, and more), queries advisory databases, and displays the results grouped by package:

```
Parsed 3 components from bom.json
Found 6 vulnerabilities

django 3.2.0 (PyPI)
  ID                        Severity  Fixed    Summary
  GHSA-2gwj-7jmv-h26r       CRITICAL  2.2.28   SQL Injection in Django
  GHSA-xpfp-f569-q3p2       CRITICAL  3.2.5    SQL Injection in Django

lodash 4.17.20 (npm)
  ID                        Severity  Fixed    Summary
  GHSA-35jh-r3h4-6jhm       HIGH      4.17.21  Command Injection in lodash

Summary: 3 components scanned, 2 vulnerable, 3 findings
  CRITICAL: 2  HIGH: 1
```

The command exits with code 1 when vulnerabilities are found, so you can use it directly as a CI gate. Filter by severity if you only want to fail on critical findings:

```bash
vulnex sbom check bom.json --severity critical
```

Need a machine-readable VEX document instead? Add `--vex` to generate an OpenVEX 0.2.0 compliant output that you can share with downstream consumers.

## Workflow 3: Diff SBOMs to gate a pull request

**The scenario**: A developer opens a PR that bumps several dependencies. You want to automatically check whether the change introduces new vulnerabilities, and block the merge if it does.

**The command**:

```bash
vulnex sbom diff main-bom.json pr-bom.json
```

This compares the vulnerability surface of two SBOMs and splits the findings into three buckets: added, removed, and unchanged. The exit code is what makes it a gate -- it returns 1 only when new vulnerabilities are introduced. Removing vulnerabilities or keeping existing ones passes cleanly.

In a GitHub Actions workflow:

```yaml
- name: Diff vulnerabilities
  run: vulnex sbom diff main-bom.json pr-bom.json --severity high
```

That single line blocks PRs that introduce high or critical vulnerabilities. No configuration file, no dashboard, no threshold tuning. I covered this in depth in [the previous article](https://github.com/AnasSahel/vulnex) -- check it out if you want the full GitHub Actions setup.

## Workflow 4: Bulk EPSS scoring from a file

**The scenario**: You have a vulnerability report -- maybe an export from another scanner, or a list from an audit. It's a plain text file with one CVE per line. You want to know the exploitation probability for each one so you can prioritize your remediation sprint.

**The command**:

```bash
cat cves.txt | vulnex epss score --stdin -o csv
```

This reads CVE IDs from stdin, queries the EPSS API for each one, and outputs a CSV with the CVE ID, exploitation probability, and percentile ranking. Redirect it to a file and open it in a spreadsheet, or pipe it into sort to find the highest-risk entries:

```bash
cat cves.txt | vulnex epss score --stdin -o csv | sort -t',' -k2 -rn | head -10
```

That gives you the top 10 most likely-to-be-exploited vulnerabilities from your list, sorted by EPSS score. It's a 30-second triage pass over hundreds of CVEs.

You can do the same with full enrichment if you want all five data sources:

```bash
cat cves.txt | vulnex enrich --stdin -o json > enriched.json
```

Now you have a single JSON file with the complete intelligence picture for every CVE in your backlog.

## Workflow 5: Offline triage with a warm cache

**The scenario**: You're on a flight, at a conference with unreliable WiFi, or working in an air-gapped environment. You still need to triage vulnerabilities.

**The setup** (run once while online):

```bash
# Warm the cache with your known CVEs
cat cves.txt | vulnex enrich --stdin > /dev/null

# Warm the cache with your SBOM
vulnex sbom check bom.json > /dev/null
```

vulnex stores all fetched data in a local SQLite database. Once the cache is warm, you can run any command with the `--offline` flag:

```bash
vulnex enrich CVE-2021-44228 --offline
vulnex sbom check bom.json --offline
```

No network requests. Everything comes from the local cache. The results are identical to online mode -- you just won't get data for CVEs you haven't previously queried.

## Putting it all together

These five workflows cover the full vulnerability management lifecycle:

1. **Investigate** a specific CVE with full context (enrich)
2. **Audit** your current dependencies for known vulnerabilities (sbom check)
3. **Gate** changes that would increase your vulnerability surface (sbom diff)
4. **Prioritize** a backlog of CVEs by exploitation likelihood (epss score)
5. **Work offline** when connectivity isn't available (cache + offline)

Each one is a single command. They compose with standard Unix tools -- pipes, redirects, jq, sort. They return meaningful exit codes for CI/CD integration. And they all share the same local cache, so data fetched in one workflow is available in the next.

## Get started

vulnex is open source, MIT-licensed, and written in Go. It's a single static binary with zero dependencies.

```bash
# Install
brew install AnasSahel/tap/vulnex

# Try it
vulnex enrich CVE-2021-44228
```

Star the repo on [GitHub](https://github.com/AnasSahel/vulnex) if you find it useful. If you have ideas for new workflows or features, open an issue -- the roadmap includes SARIF output, direct lockfile scanning, and a policy-as-code engine.

---

*This is part 3 of a 3-part series on practical vulnerability management with vulnex. Previously: "The problem with vulnerability management in 2026" and "I built a CLI that diffs your SBOMs for vulnerabilities."*
