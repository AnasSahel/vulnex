# The Problem with Vulnerability Management in 2026

It's 9 AM. You have a Slack thread from your security team about a new critical CVE. You open five tabs: NIST NVD to get the CVSS score, the CISA KEV catalog to check if it's actively exploited, FIRST.org for the EPSS probability, GitHub advisories for ecosystem-specific context, and OSV.dev for open-source impact. You cross-reference everything in a spreadsheet. By 10 AM, you have a partial picture of one vulnerability.

Now multiply that by the 28,000+ CVEs published last year.

This is the state of vulnerability management in 2026. The data exists, it's authoritative, and it's free. But it's scattered across five different sources, each with its own API, format, and update cadence. If you're responsible for triaging vulnerabilities, you spend more time collecting data than acting on it.

I got tired of this workflow, so I built a tool to fix it.

## Pain point 1: Too many sources, not enough time

Each vulnerability data source tells you something different. NVD gives you the severity score. CISA KEV tells you if attackers are actively exploiting it in the wild. EPSS predicts the probability of exploitation in the next 30 days. GitHub advisories map it to affected packages and versions. OSV.dev covers the open-source ecosystem more broadly.

No single source gives you the full picture. A CVE with a CVSS of 9.8 sounds terrifying -- until you check the EPSS score and see it's 0.02, meaning almost nobody is exploiting it. Meanwhile, a CVSS 6.5 with an EPSS of 0.85 is flying under your radar while attackers hammer it daily.

To make good decisions, you need all five sources. But correlating them manually is tedious and error-prone.

## Pain point 2: No real risk prioritization

CVSS alone is not a risk score. It measures theoretical severity, not real-world likelihood. The industry has known this for years, yet most tools still sort by CVSS and call it a day.

Real prioritization requires combining signals:

- Is the CVE in CISA's Known Exploited Vulnerabilities catalog? Then it's urgent regardless of score.
- Is the EPSS above 0.7? Then exploitation is statistically likely.
- Does a high CVSS disagree with a low EPSS? That's a signal too -- the vulnerability is theoretically severe but practically low-risk.

These combinations produce a prioritization that maps to action, not just alarm.

## Pain point 3: No way to track what changes

Your SBOM is a snapshot. You scan it on Monday, get a list of vulnerabilities, and start triaging. On Wednesday, a developer bumps three dependencies. Did the overall risk go up or down? Did the upgrade fix two vulns but introduce four new ones?

Most tools can tell you the current state. Almost none can tell you the delta. And if you can't see the delta, you can't use vulnerability scanning as a CI gate. You're just generating reports nobody reads.

## So I built vulnex

[vulnex](https://github.com/AnasSahel/vulnex) is an open-source CLI tool that aggregates vulnerability data from NVD, CISA KEV, EPSS, GitHub advisories, and OSV.dev into a single command.

Here's what enriching a CVE looks like:

```bash
vulnex enrich CVE-2021-44228
```

One command, five sources. You get the CVSS score, EPSS probability, KEV status, affected packages, and a composite risk priority -- all in your terminal.

vulnex assigns each vulnerability a priority from P0 to P4 based on the combination of signals:

- **P0 (Critical)**: In CISA KEV -- it's actively exploited, drop everything.
- **P1 (High)**: EPSS >= 0.7 or CVSS >= 9.0 -- exploitation is likely or impact is extreme.
- **P2 (Medium)**: EPSS >= 0.3, or CVSS >= 7.0 with EPSS >= 0.1 -- meaningful risk that needs planning.
- **P3 (Low)**: CVSS >= 7.0 but EPSS < 0.1 -- looks bad on paper, low real-world risk.
- **P4 (Minimal)**: Low severity, low exploitation probability -- backlog it.

The tool also flags when signals disagree, like a high CVSS with a low EPSS. These are the cases where blindly sorting by severity leads you astray.

## What else vulnex does

Beyond single-CVE enrichment, vulnex handles the full triage workflow:

- **SBOM scanning**: Point it at a CycloneDX or SPDX file and get every known vulnerability across all components, grouped and prioritized.
- **SBOM diffing**: Compare two SBOMs and see exactly which vulnerabilities were added, removed, or stayed the same. This is the feature that makes it work as a CI gate.
- **Bulk processing**: Pipe a list of CVEs from stdin, get enriched results in JSON, CSV, or Markdown.
- **Offline mode**: vulnex caches everything locally in SQLite. Warm the cache once, then triage on a plane.
- **Multiple output formats**: Table, JSON, CSV, Markdown, YAML. Pipe it into jq, feed it to a dashboard, paste it into a ticket.

It's a single static binary with zero dependencies. Install it via Homebrew and you're running in seconds:

```bash
brew install AnasSahel/tap/vulnex
```

## What's next

In the next article, I'll go deep on the feature I'm most excited about: SBOM diffing. It's the ability to compare two snapshots of your dependency tree and see exactly how your vulnerability surface changed. It turns vulnerability scanning from a report into a gate.

If this sounds useful, check out [vulnex on GitHub](https://github.com/AnasSahel/vulnex) and give it a star. It's MIT-licensed and contributions are welcome.

---

*This is part 1 of a 3-part series on practical vulnerability management with vulnex. Next up: "I built a CLI that diffs your SBOMs for vulnerabilities."*
