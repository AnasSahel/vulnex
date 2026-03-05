---
status: incorporated
type: idea
date: 2026-03-03
title: Feature Brainstorm — 8 Expert Perspectives
---

# vulnex Feature Brainstorm — 2026-03-03

Synthesized from 8 expert perspectives: Cybersecurity, Pentesting, DevSecOps, Digital Identity, GRC, Sales, Consulting, and Devil's Advocate.

---

## Cross-Expert Consensus: Top Themes

Features ranked by how many experts independently proposed them (convergence = high signal).

### Tier 1 — Universal Agreement (6+ experts)

| Feature | Champions | Why it matters |
|---------|-----------|----------------|
| **Suppression / ignore file** (`.vulnexignore`) | DevSecOps, Devil's Advocate, GRC, Sales, Consultant, Identity | Without it, teams drown in noise and disable the gate entirely. Needs audit trail with expiry dates, approver, justification. The #1 adoption blocker. |
| **Executive/compliance report generation** (`vulnex report`) | Sales, Consultant, GRC, Cybersecurity, DevSecOps | Engineers love CLIs; budget holders need PDFs. Compliance evidence packages (SOC2, ISO 27001, FedRAMP) replace 6-8 hours of manual toil per audit cycle. |
| **Exploit availability tracking** (`vulnex exploit`) | Pentest, Cybersecurity, Devil's Advocate, Sales, Consultant | EPSS is a prediction; teams want to know "is there a working exploit RIGHT NOW?" Cross-reference ExploitDB, Metasploit, Nuclei, GitHub PoCs. All indexable offline. |

### Tier 2 — Strong Agreement (4-5 experts)

| Feature | Champions | Why it matters |
|---------|-----------|----------------|
| **SARIF output format** | DevSecOps, Sales, Consultant, GRC | Lingua franca of code scanning. Unlocks GitHub Code Scanning, Azure DevOps, IDE integrations. Low effort, very high integration ROI. |
| **Baseline management** (`vulnex baseline`) | DevSecOps, Consultant, Sales, Devil's Advocate | Snapshot current state, only alert on regressions. Solves "inherited tech debt" for teams onboarding vulnex into existing projects. |
| **Policy-as-code** (OPA/Rego or YAML policies) | DevSecOps, Sales, GRC, Consultant | Real policies aren't "fail on CRITICAL." They're "fail if KEV AND EPSS > 0.7 AND severity >= HIGH." Replaces blunt `--severity` flag. |
| **Native CI actions** (GitHub Action, GitLab CI) | DevSecOps, Sales, Devil's Advocate, Consultant | Drop-in 5-line integration. Handles binary caching, SARIF upload, PR comments. The viral growth engine that made Snyk/Dependabot household names. |
| **SLA tracking & remediation deadlines** | GRC, Consultant, Cybersecurity, Sales | FedRAMP: 30 days for Critical. PCI-DSS: 1 month. Without tracking, can't prove compliance. Turns scanner into program management tool. |

### Tier 3 — Specialized but High-Value (2-3 experts)

| Feature | Champions | Why it matters |
|---------|-----------|----------------|
| **MITRE ATT&CK mapping** | Pentest, Cybersecurity | Maps CVEs to adversary techniques (T1190, T1059). Answers "what can an attacker DO with this?" Static offline JSON dataset. |
| **Lockfile/image scanning** (`vulnex scan go.sum`) | Devil's Advocate, DevSecOps | Eliminates 2-tool friction. Generate SBOM internally from lockfiles. The actual workflow users want. |
| **Threat actor attribution** | Cybersecurity, Pentest | Which APT groups are exploiting this CVE? Targeted sectors? Changes priority dramatically for threat-intel-driven orgs. |
| **Vulnerability chaining** (`vulnex chain`) | Cybersecurity, Pentest | Chain CVEs into attack paths (RCE + LPE + lateral). Recommends which CVE to fix to break the longest chain. No open-source CLI equivalent. |
| **Multi-project workspaces** | Consultant, GRC | Named workspaces with isolated caches, configs, watch lists. Table stakes for consulting firms and MSSPs. |
| **Asset-aware prioritization** | Cybersecurity, Consultant | A CRITICAL CVE on a decommissioned test server != CRITICAL on your public API. Context-aware re-scoring. |
| **Ticketing integration** (Jira, ServiceNow) | Consultant, GRC | Pre-populated tickets with CVE details. Closes the findings-to-fix gap. |
| **POA&M generation** | GRC, Consultant | Mandatory for FedRAMP/FISMA. Auto-generate from scan results in NIST column schema. |
| **VEX consumption** | Devil's Advocate, Identity | vulnex outputs VEX but can't consume it. If a team marked CVE-X as "not affected," the gate still fails. |
| **Software provenance** (`sbom verify`) | Identity, GRC | Validate SBOM signatures (Sigstore/Cosign), check SLSA build levels. Aligns with EO 14028 and CISA mandates. |
| **Identity CWE profiles** | Identity | `--profile identity` scopes to auth-related CWEs (287, 295, 306, 798...). Low effort, high discoverability for IAM teams. |
| **Auth library flagging** | Identity | `--flag-auth-libs` annotates JWT/OAuth/SAML components with `[AUTH]` marker, applies stricter thresholds. |
| **Credential exposure detection** | Identity | Cross-reference SBOM components against malware/secret-exposure advisory corpus. |
| **Onboarding wizard** (`vulnex init`) | Sales, Devil's Advocate | Detect language, generate SBOM, run first scan, suggest CI snippet. Time-to-first-value under 2 minutes. |
| **Reachability analysis** | Cybersecurity | 60-80% of SBOM findings are in unreachable code. Accept call-graph input, filter to reachable-only. |

---

## Devil's Advocate: Critical Weaknesses

These aren't features — they're fundamental gaps that prevent vulnex from being taken seriously:

1. **No persistent team state.** SQLite on one laptop is useless for a team of 10. Consider a server mode or shared database.
2. **No false positive management.** Without `.vulnexignore`, teams stop using it within a week.
3. **The composite scoring is a black box.** P0-P4 thresholds must be transparent and configurable.
4. **SBOM scanning is thin vs Grype/Trivy.** They scan images directly; vulnex needs a pre-generated SBOM.
5. **"Offline-capable" is oversold.** No pre-population mechanism, no air-gapped sync, no local NVD mirror.
6. **No community/ecosystem.** No issue templates, no contribution guide, no Discord, no roadmap.
7. **No VEX consumption.** Outputs VEX but can't honor existing "not affected" decisions.
8. **Positioning problem.** Don't compete with Trivy/Grype on scanning — own the "what to fix first" layer.

---

## Strategic Positioning

**Don't compete with Trivy/Grype on scanning. Own the "what to fix first" layer.**

Trivy (Aqua Security) and Grype (Anchore) have years of headstart, massive communities,
and corporate backing on vulnerability scanning. They answer **"what vulnerabilities exist?"**
vulnex answers **"which ones matter, and what do I fix first?"**

These are complementary, not competitive. vulnex should sit **on top of** existing scanners
as the intelligence and prioritization layer, not replace them.

**What vulnex does that they can't:**
- Multi-source enrichment (NVD + KEV + EPSS + GHSA + OSV + exploit intel in one view)
- Composite risk scoring with configurable profiles and transparent P0-P4 thresholds
- Exploit availability checking across 4 sources (ExploitDB, Metasploit, Nuclei, GitHub PoCs)
- Temporal intelligence (EPSS trend tracking — is this CVE getting more dangerous?)

**What vulnex should NOT invest in:**
- More lockfile/image parsers (Trivy supports 20+ languages, images, IaC, secrets, licenses)
- Container image scanning (Trivy/Grype's core strength)
- Reachability analysis (govulncheck, Snyk, Semgrep own this — requires deep per-language call-graph work)
- Baseline management (Trivy already has `.trivyignore` and baseline diffing)

**The unlock:** Accept scanner output as input. `trivy fs . -f json | vulnex prioritize`
makes vulnex a force multiplier. Users keep their scanner, add vulnex for intelligence.

---

## Recommended Roadmap

Based on convergence across all 8 experts, effort/impact ratio, competitive positioning,
and lessons learned from Phase 1 implementation.

> **Last updated:** 2026-03-04 (post Phase 1 + Technical Debt & Foundations completion)

### Phase 1 — Adoption Unblockers ✅ COMPLETE
1. ✅ `.vulnexignore` suppression file with audit trail and expiry
2. ✅ SARIF output format (`-o sarif`)
3. ✅ Lockfile scanning (`vulnex scan go.sum`, `package-lock.json`, etc.) — includes batch OSV queries
4. ✅ Transparent, configurable composite scoring (`vulnex scoring`, `--scoring-profile`, custom weights)
5. ✅ Exploit availability tracking (`vulnex exploit`) — ExploitDB, Metasploit, Nuclei, GitHub PoCs *(pulled forward from original Phase 3)*

### Immediate — Technical Debt & Foundations ✅ COMPLETE
Architectural gaps discovered during Phase 1, now resolved:

6. ✅ **Wire up cache for all API clients** — NVD (2h TTL), EPSS (24h TTL, per-CVE with batch miss optimization), GHSA (4h TTL, both GetAdvisory and FindByCVE), and OSV (4h TTL, both GetVulnerability and QueryByCVE) now use the SQLite cache following the KEV pattern. Advisory cache count added to `vulnex cache stats`.
7. ✅ **Clean up dead code** — Deleted unused VulnCheck client and plugin registry. Moved EPSS time-series logic into `epss.Client.GetTimeSeries()` (removed raw HTTP bypass). Moved `ScoreConflict` to model package, wired `ReconcileScores` into enricher merge, and surfaced conflicts in table/markdown output.
8. ✅ **Enriched SBOM findings** — `vulnex scan --enrich` now enriches findings with EPSS scores, KEV status, CVSS scores, risk priority, and exploit availability. CVE IDs are extracted from OSV aliases. Table output shows CVSS/EPSS/KEV/Priority columns when enriched. JSON/CSV/YAML get enrichment fields via struct tags.

### Phase 2 — The Intelligence Layer (differentiation)
Position vulnex as the prioritization brain that any scanner can feed into.

9. **Scanner output ingestion** (`vulnex prioritize`) — Accept Trivy JSON, Grype JSON, and generic SARIF as input. Enrich each finding with EPSS, KEV, exploit status, and composite score. This is the single most important feature for positioning: users keep their scanner, add vulnex for the "so what?" layer. Example: `trivy fs . -f json | vulnex prioritize -o table`.
10. **Policy-as-code** (YAML rules) — Replace blunt `--severity` flag with composable rules: "fail if KEV AND EPSS > 0.7", "allow MEDIUM if devDependency", "warn if exploit available." Natural evolution of the suppression system. Required for CI gates that aren't just `|| true`.
11. **Temporal intelligence** — Surface EPSS trend data in enrichment output. "This CVE had EPSS 0.02 last month, now it's 0.87 and a Metasploit module just dropped." EPSS time-series API is already used by `epss trend`; connect it to the enricher and prioritization flow. No scanner does this.
12. **`vulnex init` onboarding wizard** — Detect project type, run first scan/prioritize, suggest CI snippet. Time-to-first-value under 2 minutes.

### Phase 3 — CI/CD & Reporting (viral growth + monetization signal)
13. **Official GitHub Action / GitLab CI component** — Drop-in integration: run scanner → pipe to `vulnex prioritize` → upload SARIF → PR comment with top findings. Depends on policy-as-code for real-world gate configs.
14. **Report generation** (`vulnex report` — HTML/PDF) — 5 experts flagged this. Budget holders need artifacts for audits. Include: executive summary, P0-P4 breakdown, exploit status, EPSS trends, compliance evidence (SOC2, ISO 27001). The #1 enterprise signal.
15. **Cross-repo aggregation** (`vulnex portfolio`) — "Across my 50 repos, what are the top 10 things to fix this week?" Ingest multiple scan results, deduplicate CVEs across repos, rank by composite score. No scanner does this — they all operate on a single target.
16. **VEX consumption** — Honor existing "not affected" decisions from upstream VEX documents. The VEX model already exists in `internal/sbom/vex.go`; this adds the read path.

### Phase 4 — Enterprise & Compliance
17. SLA tracking and remediation deadlines (FedRAMP: 30d Critical, PCI-DSS: 1 month)
18. POA&M generation (NIST column schema for FedRAMP/FISMA)
19. Multi-project workspaces (named workspaces with isolated configs for MSSPs)
20. Ticketing integration (Jira, ServiceNow, GitHub Issues — pre-populated from findings)
21. Server mode (`vulnex serve`) — HTTP API + shared database for team state

### Future / Research
- MITRE ATT&CK technique mapping *(niche audience, demo-grade impact)*
- Threat actor attribution *(same reasoning)*
- Vulnerability chaining and attack path analysis
- Software provenance verification (SLSA/Sigstore)
- Asset-aware contextual prioritization
- Identity protocol CVE trending / CWE profiles
- `vulnex sbom fix` — automated remediation plan (upgrade suggestions)

### Explicitly Not On Roadmap
These are areas where Trivy/Grype have insurmountable leads. Don't invest here:
- Container image scanning
- Additional lockfile format parsers beyond the current 9
- IaC misconfiguration scanning
- Secret detection
- License compliance scanning
- Language-specific reachability analysis

---

## Expert Panel Summary

| Expert | Focus | Top Pick |
|--------|-------|----------|
| Cybersecurity | Threat intel, attack paths | Vulnerability chaining |
| Pentesting | Offensive operations, recon | Exploit availability tracker |
| DevSecOps | Pipeline integration, shift-left | SARIF output + suppression file |
| Digital Identity | Auth protocols, IAM, provenance | Identity CWE profiles + auth lib flagging |
| GRC | Compliance frameworks, audit evidence | Compliance evidence package export |
| Sales | Adoption, GTM, enterprise hooks | Executive HTML/PDF reports |
| Consultant | Multi-client, reporting, metrics | Multi-project workspaces + reports |
| Devil's Advocate | Contrarian critique | Suppression file + lockfile scanning |
