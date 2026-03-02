# Cybersecurity Domain Requirements for CVE CLI Tool

> Written from the perspective of a security practitioner who has worked in SOCs, conducted penetration testing, and managed enterprise vulnerability programs. This document captures real-world requirements, workflows, and domain expertise to guide the design and feature prioritization of the CVE CLI tool.

---

## Table of Contents

1. [User Personas and Real-World Workflows](#1-user-personas-and-real-world-workflows)
2. [Data Source Prioritization and Trust](#2-data-source-prioritization-and-trust)
3. [Key Features from a Security Practitioner's Perspective](#3-key-features-from-a-security-practitioners-perspective)
4. [Risk Scoring and Prioritization](#4-risk-scoring-and-prioritization)
5. [Compliance and Reporting](#5-compliance-and-reporting)
6. [Data Freshness, Trust, and the NVD Crisis](#6-data-freshness-trust-and-the-nvd-crisis)
7. [Competitive Landscape and Differentiation](#7-competitive-landscape-and-differentiation)
8. [Recommended Feature Prioritization](#8-recommended-feature-prioritization)

---

## 1. User Personas and Real-World Workflows

### Persona 1: SOC Analyst (Tier 1-2) -- Vulnerability Triage

**Context:** SOC analysts working vulnerability management spend significant time correlating scan results with threat intelligence. They receive vulnerability scan reports from tools like Qualys, Tenable, or Rapid7 and need to rapidly determine which findings represent actual risk.

**Daily workflow:**
- Morning: Review overnight scan results, filter by severity and asset criticality
- Correlate CVEs against CISA KEV to identify mandated remediation targets
- Check EPSS scores to prioritize CVEs most likely to be exploited
- Verify if public exploits exist (Exploit-DB, GitHub PoCs, Metasploit modules)
- Generate tickets for remediation teams with context (CVSS, exploit status, affected systems)
- Afternoon: Track remediation progress, escalate overdue KEV items

**What they need from a CLI tool:**
```
# "Which of these 47 CVEs from last night's scan are actually dangerous?"
cve lookup CVE-2024-21762 CVE-2024-3400 CVE-2024-1709 --format table

# "Show me everything in KEV that we haven't patched"
cve search --kev --vendor fortinet --severity critical

# "What's the EPSS on this CVE the scanner flagged?"
cve info CVE-2025-0282 --show epss,kev,exploits

# "Bulk enrich my scan export"
cat scan-cves.txt | cve enrich --output json > enriched.json
```

**Pain point:** They currently have to open 4-5 browser tabs (NVD, CISA KEV page, FIRST EPSS lookup, Exploit-DB, vendor advisory) to get the full picture on a single CVE. A CLI tool that aggregates all of this into one query saves 3-5 minutes per CVE, which across a 50-CVE scan report is 2.5-4 hours of analyst time.

### Persona 2: Penetration Tester -- Target Reconnaissance

**Context:** Pentesters scoping engagements need to quickly identify known vulnerabilities in target technology stacks. During active testing, they need to pivot from discovered software versions to known exploits.

**Typical workflow:**
- Pre-engagement: Client provides technology inventory, pentester maps to known CVEs
- During testing: Discover software version via banner grab, immediately check for CVEs
- Post-testing: Cross-reference findings with CVSS and exploit availability for report severity ratings

**What they need:**
```
# "I found Apache 2.4.49 -- what can I hit it with?"
cve search --cpe "cpe:2.3:a:apache:http_server:2.4.49:*" --has-exploit

# "What are the juiciest vulns for Fortinet this year?"
cve search --vendor fortinet --year 2025 --sort epss-desc --limit 20

# "Give me all RCEs for this product"
cve search --product confluence --cwe CWE-94 --severity critical

# "Map CVE to Nuclei template or Metasploit module"
cve info CVE-2023-22515 --show exploits,references
```

**Pain point:** Tools like `searchsploit` only cover Exploit-DB. Pentesters juggle multiple databases. A single CLI that maps CVE to exploit availability across Exploit-DB, GitHub PoCs, Metasploit, and Nuclei templates is extremely valuable.

### Persona 3: DevSecOps Engineer -- Dependency Vulnerability Management

**Context:** DevSecOps engineers integrate security into CI/CD pipelines. They need to assess vulnerabilities in software dependencies and make build/deploy decisions.

**Typical workflow:**
- CI pipeline flags vulnerable dependency via Grype/Trivy/Snyk
- Engineer investigates: Is this CVE actually exploitable in our context?
- Check if the CVE is in KEV (regulatory urgency), EPSS score (likelihood), fix availability
- Decide: block deploy, accept risk, or schedule patch
- Document decision in VEX format for compliance

**What they need:**
```
# "Pipeline flagged CVE-2024-38816 in Spring Framework -- how bad is it really?"
cve info CVE-2024-38816 --show cvss,epss,kev,references,fix

# "Enrich my SBOM with vulnerability data"
cve sbom-check ./sbom.cyclonedx.json --output vex

# "What's exploitable in my dependency list?"
cat dependencies.txt | cve check --kev-only --epss-above 0.5

# "Is there a fixed version?"
cve info CVE-2024-38816 --show fix-versions
```

**Pain point:** Existing SCA tools (Grype, Trivy, Snyk) do container/package scanning well but are not general-purpose CVE lookup tools. When a DevSecOps engineer needs to investigate a specific CVE or enrich data beyond what their scanner provides, they fall back to web browsers.

### Persona 4: Compliance/GRC Analyst -- Audit and Reporting

**Context:** Governance, Risk, and Compliance teams need to demonstrate vulnerability management compliance, particularly for frameworks like NIST CSF, PCI DSS, FedRAMP, and BOD 22-01.

**Typical workflow:**
- Generate reports showing KEV remediation compliance within mandated timelines
- Track CVSS distribution across the environment for risk posture reporting
- Map CVEs to CWE categories for root cause analysis
- Export data for ticketing systems and audit evidence

**What they need:**
```
# "Show me all KEV items added in the last 30 days with due dates"
cve search --kev --added-after 2025-02-01 --show due-date

# "Export critical CVEs for our Jira import"
cve search --severity critical --year 2025 --format csv > jira-import.csv

# "CWE breakdown for our quarterly report"
cve stats --year 2025 --group-by cwe --limit 20

# "How many CVEs were published this month vs last?"
cve stats --year 2025 --group-by month
```

### Persona 5: Vulnerability Researcher -- Deep Analysis

**Context:** Security researchers tracking specific vulnerability classes, monitoring vendor response patterns, or analyzing exploitation trends.

**What they need:**
```
# "Show me all command injection CVEs in network equipment from 2024-2025"
cve search --cwe CWE-78 --keyword "router OR firewall OR switch" --year 2024-2025

# "Track CVE publication rate for a specific vendor"
cve stats --vendor microsoft --year 2025 --group-by month

# "Find CVEs that were published but have no NVD analysis yet"
cve search --status awaiting-analysis --year 2025 --limit 50

# "Show CVEs with high EPSS but low CVSS (underrated vulns)"
cve search --epss-above 0.7 --cvss-below 7.0
```

---

## 2. Data Source Prioritization and Trust

### Primary Data Sources (Must-Have)

| Source | What It Provides | Freshness | Trust Level | API Availability |
|--------|-----------------|-----------|-------------|-----------------|
| **NVD (NIST)** | CVE descriptions, CVSS scores, CPE mappings, CWE classifications, references | Significant backlog (44% awaiting analysis), updates every 2 hours recommended | High for analyzed CVEs, but enrichment is incomplete for ~26,800+ CVEs | NVD API 2.0: 5 req/30s (public), 50 req/30s (with key) |
| **CISA KEV** | Confirmed actively exploited CVEs with remediation deadlines | Updated multiple times per week, currently 1,484+ entries | Very high -- requires evidence of active exploitation | JSON download, no auth required |
| **EPSS (FIRST.org)** | Probability of exploitation in next 30 days (0.0-1.0) | Updated daily | High -- outperforms CVSS for prioritization (AUC 0.838) | CSV download, free API |
| **MITRE CVE List** | Canonical CVE IDs, descriptions, references | Near real-time from CNAs | Authoritative -- the source of record | CVE Services API 2.0 |

### Secondary Data Sources (High Value)

| Source | What It Provides | Notes |
|--------|-----------------|-------|
| **OSV.dev (Google)** | Open-source package vulnerabilities with precise version ranges | Aggregates GitHub Security Advisories, PyPA, RustSec, and more. Best for open-source/dependency CVEs. |
| **VulnCheck** | Enhanced CVE enrichment, exploit intelligence, extended KEV | 142% more KEVs than CISA. Free community tier. CLI available. |
| **GitHub Advisory Database** | Vulnerability advisories for open-source packages | Excellent for npm, PyPI, Maven, Go, Rust ecosystems |
| **Exploit-DB / PoC-in-GitHub** | Public exploit code availability | Critical for assessing real-world risk |

### Freshness vs. Completeness Tradeoffs

This is the central tension in vulnerability data today:

- **MITRE CVE List** is the fastest source for new CVE IDs -- CNAs publish within hours/days of discovery. But it only has descriptions and references, no CVSS or CPE data.
- **NVD** provides the richest enrichment (CVSS, CPE, CWE) but has a massive backlog. As of early 2025, 44% of recent CVEs are "awaiting analysis." NIST has marked all pre-2018 unenriched CVEs as "Deferred" -- they will never be enriched.
- **EPSS** updates daily and provides forward-looking risk prediction independent of NVD enrichment. This is essential when NVD enrichment is delayed.
- **CISA KEV** is the highest-confidence signal for active exploitation but only covers ~1,500 CVEs total out of 250,000+ published CVEs.

**Recommended data strategy:** Use MITRE CVE List for the canonical record, NVD for enrichment where available, EPSS for prioritization regardless of NVD status, and CISA KEV as an absolute priority override. Fall back to VulnCheck or OSV.dev when NVD enrichment is missing.

### How KEV, EPSS, and CVSS Complement Each Other

These three signals answer different questions:

- **CVSS** answers: "How bad could this be if exploited?" (theoretical severity)
- **EPSS** answers: "How likely is this to be exploited in the next 30 days?" (probabilistic risk)
- **KEV** answers: "Is this being exploited right now in the wild?" (confirmed threat)

The most dangerous CVEs score high on all three. But the real value is in the disagreements:

- **High CVSS, low EPSS, not in KEV:** Theoretically severe but practically low risk. Deprioritize.
- **Low CVSS, high EPSS:** Underrated by traditional scoring, but attackers are interested. Investigate.
- **In KEV regardless of CVSS/EPSS:** Mandatory action. Active exploitation confirmed.
- **High EPSS, not yet in KEV:** Early warning signal. Exploitation is likely imminent.

A good CLI tool should surface these disagreements to help analysts make smarter prioritization decisions.

---

## 3. Key Features from a Security Practitioner's Perspective

### 3.1 Core Lookup and Search

These are the bread-and-butter queries every security professional runs:

```bash
# Single CVE lookup with full context
cve info CVE-2024-3400
# Expected output: description, CVSS (base/temporal), EPSS score+percentile,
# KEV status+due date, CWE, affected products (CPE), references, exploit availability

# Multi-CVE batch lookup (from scan results)
cve info CVE-2024-3400 CVE-2024-21762 CVE-2024-1709

# Pipe-friendly batch processing
cat scanner-output.txt | cve enrich --format json

# Search by vendor/product
cve search --vendor paloaltonetworks --product pan-os --year 2024

# Search by CPE (precise software matching)
cve search --cpe "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"

# Search by CWE (vulnerability class)
cve search --cwe CWE-89  # All SQL injection CVEs

# Combined filters
cve search --vendor fortinet --severity critical --year 2024 --kev --sort epss-desc
```

### 3.2 Risk Prioritization Queries

These queries separate a CVE lookup tool from a vulnerability intelligence tool:

```bash
# "What should I patch first?" -- the essential triage query
cve search --kev --epss-above 0.5 --severity critical,high --sort epss-desc

# "Show me underrated vulns" -- EPSS disagrees with CVSS
cve search --epss-above 0.7 --cvss-below 7.0

# "What's being exploited in my tech stack?"
cve search --vendor microsoft,apache,fortinet --kev --year 2025

# "Emerging threats" -- high EPSS but not yet in KEV
cve search --epss-above 0.8 --no-kev --year 2025

# "Show exploit availability"
cve search --has-exploit --severity critical --year 2025
```

### 3.3 SBOM/Dependency Integration

```bash
# Check an SBOM against vulnerability data
cve sbom-check ./sbom.cyclonedx.json --format table
cve sbom-check ./sbom.spdx.json --kev-only

# Generate VEX document from analysis
cve sbom-check ./sbom.cyclonedx.json --output vex --vex-format cyclonedx

# Check a package.json / requirements.txt style input
cve check-deps --ecosystem npm --file package-lock.json
```

### 3.4 Statistics and Trend Analysis

```bash
# Monthly CVE publication trend
cve stats --year 2025 --group-by month

# Top CWEs this year
cve stats --year 2025 --group-by cwe --limit 20

# Vendor comparison
cve stats --vendor microsoft,apple,google --year 2025

# KEV addition rate
cve stats --kev --group-by month --year 2025

# EPSS distribution for a search result
cve search --vendor apache --year 2025 --stats
```

### 3.5 Export and Integration

```bash
# JSON for programmatic consumption
cve search --vendor fortinet --year 2025 --format json > vulns.json

# CSV for spreadsheet/Jira import
cve search --kev --format csv --fields cve,description,cvss,epss,due-date > kev-report.csv

# JSONL for streaming/pipeline processing
cve search --severity critical --year 2025 --format jsonl | jq '.epss_score'

# Markdown for reports
cve info CVE-2024-3400 --format markdown >> pentest-report.md

# Quiet mode for scripting
cve search --kev --severity critical --format ids-only
# Output: CVE-2024-3400 CVE-2024-21762 CVE-2024-1709
```

---

## 4. Risk Scoring and Prioritization

### 4.1 The Problem with CVSS Alone

CVSS base scores are the most widely used metric, but they are a poor prioritization tool in isolation:

- CVSS measures **theoretical severity**, not **likelihood of exploitation**
- A CVSS 9.8 that requires local physical access to an airgapped system is lower risk than a CVSS 7.5 that is being mass-exploited over the internet
- CVSS scores are static -- they do not change as threat landscape evolves
- The NVD backlog means many recent CVEs lack CVSS scores entirely

Industry research consistently shows that prioritizing by CVSS alone results in organizations patching thousands of CVEs that will never be exploited while missing the hundreds that will.

### 4.2 Composite Risk Model

A modern vulnerability prioritization approach combines multiple signals. Here is a recommended composite scoring model for the CLI tool:

```
Risk Priority = f(CVSS_severity, EPSS_probability, KEV_status, Exploit_availability)
```

**Proposed Priority Levels:**

| Priority | Criteria | Action |
|----------|----------|--------|
| **P0 - CRITICAL** | In CISA KEV (regardless of other scores) | Immediate remediation. BOD 22-01 mandates 2-week deadline. |
| **P1 - HIGH** | EPSS >= 0.7 OR (CVSS >= 9.0 AND exploit available) | Remediate within 7 days |
| **P2 - MEDIUM** | EPSS >= 0.3 OR (CVSS >= 7.0 AND EPSS >= 0.1) | Remediate within 30 days |
| **P3 - LOW** | CVSS >= 7.0 but EPSS < 0.1 and no known exploit | Remediate within 90 days |
| **P4 - MINIMAL** | CVSS < 7.0 AND EPSS < 0.1 | Risk-accept or scheduled maintenance |

**Key design principle:** KEV status is always an override. If CISA says it is being exploited, it is P0 regardless of CVSS or EPSS.

### 4.3 What Commercial Tools Do Well (and Where CLI Can Differentiate)

**Qualys VMDR:**
- Strengths: Real-time TruRisk scoring, asset context, auto-prioritization
- Gap: Requires full platform deployment, expensive, not useful for ad-hoc lookup

**Tenable.io:**
- Strengths: VPR (Vulnerability Priority Rating) combines CVSS, exploit maturity, threat intel
- Gap: Proprietary scoring, locked to Tenable ecosystem

**Rapid7 InsightVM:**
- Strengths: Real Risk Score, Active Risk integration
- Gap: Same vendor lock-in issues

**Where a CLI tool differentiates:**
1. **No vendor lock-in:** Uses open data sources (NVD, EPSS, KEV) -- transparent scoring
2. **Ad-hoc lookup:** Does not require a deployed scanner or agent infrastructure
3. **Pipeline integration:** Can be embedded in CI/CD, scripts, automation
4. **Offline capability:** Local database mode for airgapped environments
5. **Transparency:** Every data point and scoring input is visible and auditable
6. **Speed:** Command-line is faster than any web dashboard for known-CVE lookups
7. **Composability:** Unix philosophy -- pipe output to jq, grep, awk, other tools

---

## 5. Compliance and Reporting

### 5.1 BOD 22-01 -- CISA KEV Remediation

Binding Operational Directive 22-01 requires all Federal Civilian Executive Branch (FCEB) agencies to remediate KEV-listed vulnerabilities within mandated timelines:

- **CVEs with IDs assigned before 2021:** Remediate within 6 months of KEV addition
- **All other CVEs:** Remediate within 2 weeks of KEV addition
- **Scope:** All internet-facing and internal systems

While BOD 22-01 only legally binds federal agencies, it has become a de facto standard for private sector vulnerability management programs. Many organizations use KEV compliance as a baseline metric.

**CLI support needed:**
```bash
# Show KEV items with due dates
cve search --kev --show due-date --sort due-date-asc

# Filter overdue KEV items (for compliance dashboards)
cve search --kev --due-before today --format csv

# New KEV additions in the last N days
cve search --kev --added-after 2025-02-15

# KEV items by vendor (for vendor risk assessment)
cve search --kev --vendor microsoft --year 2025
```

### 5.2 SBOM/VEX Integration

The software supply chain security landscape is rapidly evolving, and the CLI tool should support integration with SBOM and VEX workflows:

**SBOM Formats to Support:**
- CycloneDX (JSON and XML) -- increasingly dominant, VEX-native
- SPDX (JSON) -- required for NTIA SBOM minimum elements

**VEX Formats to Support:**
- OpenVEX -- lightweight, standalone VEX documents
- CycloneDX VEX -- embedded within SBOM structure
- CSAF VEX -- Common Security Advisory Framework, used by larger enterprises

**Workflow:**
1. Ingest SBOM (from build pipeline or vendor)
2. Extract component identifiers (CPE, PURL)
3. Query vulnerability data for each component
4. Generate VEX document with exploitability status
5. Output for downstream consumption (compliance tools, ticketing)

### 5.3 Export Formats for Ticketing Systems

Real-world vulnerability management requires getting data into ticketing systems:

- **Jira CSV import:** Fields: CVE ID, summary, severity, EPSS, KEV status, affected product, remediation URL
- **ServiceNow:** JSON format compatible with ServiceNow VR (Vulnerability Response) module
- **Generic CSV/JSON:** Flexible field selection for custom integrations

```bash
# Jira-ready export
cve search --kev --severity critical --format csv \
  --fields cve,description,cvss,epss,kev-due-date,vendor,product,reference-url

# ServiceNow-compatible JSON
cve search --severity critical --year 2025 --format servicenow-json
```

---

## 6. Data Freshness, Trust, and the NVD Crisis

### 6.1 The NVD Backlog -- Current State

The NVD is in an unprecedented crisis that directly impacts any tool relying on it:

- **Scale:** 26,800+ CVEs awaiting analysis as of early 2025. 44% of CVEs added in the past year have "awaiting analysis" status.
- **Rate mismatch:** ~136 new CVEs arrive daily, but NVD analysis capacity falls short by ~9,000 CVEs per day against what is needed to clear the backlog.
- **Root cause:** NIST staff shortages, ~12% budget cuts, and CVE submission volumes increasing 32% year-over-year.
- **Deferred CVEs:** All pre-2018 unenriched CVEs have been marked "Deferred" -- NIST will not analyze them.
- **Impact:** Many recent CVEs lack CVSS scores, CPE mappings, and CWE classifications in NVD.

**Implications for CLI tool design:**
- Cannot rely solely on NVD for enrichment data
- Must gracefully handle CVEs with missing CVSS, CPE, or CWE data
- Should clearly indicate when NVD analysis is pending/incomplete
- Should supplement with alternative data sources (VulnCheck, EPSS, OSV.dev)

### 6.2 MITRE CVE Program Funding Uncertainty

In April 2025, DHS allowed MITRE's CVE program funding to lapse, nearly shutting down the entire CVE ecosystem. Key developments:

- **CVE Foundation:** Created as a non-profit to ensure CVE program continuity independent of government funding
- **GCVE:** Global CVE allocation system by CIRCL (Luxembourg) for decentralized vulnerability identification
- **VulnCheck reservations:** Proactively reserved 1,000 CVE IDs as a buffer
- **Resolution:** CISA secured a one-year funding extension, but structural risk remains

**Implications for CLI tool design:**
- Should support multiple CVE data sources, not just MITRE/NVD
- Architecture should be source-agnostic where possible
- Consider supporting GCVE identifiers as a future-proofing measure

### 6.3 Handling Disputed and Rejected CVEs

Not all CVEs are valid. The CLI should handle:

- **DISPUTED:** Vendor contests the vulnerability. Display dispute status prominently.
- **REJECTED:** CVE was assigned but later invalidated. Do not show in search results by default, but allow `--include-rejected` flag.
- **RESERVED:** CVE ID assigned but details not yet published. Show as "reserved" with CNA information.
- **Awaiting Analysis:** CVE published but NVD has not enriched it. Show available data (description, references) and clearly indicate missing enrichment.

### 6.4 Data Reconciliation Between Sources

Different sources may have conflicting information:

- NVD CVSS may differ from vendor-assigned CVSS (CNAs can now assign their own scores)
- CPE mappings in NVD may be incomplete or incorrect
- EPSS scores change daily as the model updates
- KEV entries may lag behind actual exploitation

**Recommendation:** Show data provenance. For CVSS, display both NVD and CNA scores when they differ. Include timestamps showing when data was last updated from each source. Let analysts make informed decisions rather than hiding source conflicts.

---

## 7. Competitive Landscape and Differentiation

### 7.1 Existing CLI Tools

#### cvemap (ProjectDiscovery)
- **What it does:** CLI for exploring CVE data with search, filtering, and analysis
- **Data sources:** NVD, KEV, EPSS, HackerOne, Nuclei templates, GitHub PoCs
- **Strengths:** Multi-source aggregation, exploit mapping, active development community
- **Weaknesses:** Being deprecated in favor of `vulnx`; requires ProjectDiscovery API (cloud-dependent); older API version discontinuing August 2025
- **Gap:** Cloud dependency, vendor lock-in to ProjectDiscovery ecosystem

#### Grype (Anchore)
- **What it does:** Container/filesystem vulnerability scanner
- **Data sources:** NVD, OS advisories, GitHub advisories
- **Strengths:** Excellent SBOM integration (with Syft), composite risk scoring (CVSS + EPSS + KEV), fast scanning
- **Weaknesses:** Focused on scanning containers/packages, not general-purpose CVE lookup. Cannot do ad-hoc CVE research queries.
- **Gap:** Not a CVE research/intelligence tool -- it is a scanner

#### Trivy (Aqua Security)
- **What it does:** All-in-one security scanner (vulnerabilities, misconfigurations, secrets, licenses)
- **Data sources:** NVD, OS advisories, language-specific advisories
- **Strengths:** Broadest scanning scope, IaC scanning, SBOM generation
- **Weaknesses:** No EPSS integration, no KEV awareness, severity-only prioritization
- **Gap:** Same as Grype -- scanner, not CVE intelligence tool

#### VulnCheck CLI
- **What it does:** CLI access to VulnCheck's vulnerability intelligence API
- **Data sources:** VulnCheck's proprietary enriched database (NVD++, extended KEV, exploit intelligence)
- **Strengths:** Best data quality, 142% more KEVs than CISA, fastest enrichment
- **Weaknesses:** Requires VulnCheck API key, free tier has limitations, proprietary data
- **Gap:** Vendor-dependent, API-key-gated

#### Other Tools
- **vulners-scanner:** CLI for Vulners.com database. Limited to their data, requires API key.
- **cve-search (CIRCL):** Self-hosted CVE search tool with local database. Good for airgapped environments but complex to deploy and maintain.

### 7.2 The Gap This Tool Can Fill

After analyzing the competitive landscape, there is a clear gap for:

**An open-source, offline-capable CVE intelligence CLI that combines multi-source vulnerability data with transparent risk prioritization -- independent of any vendor API or cloud service.**

Specific differentiators:

| Feature | cvemap | Grype | Trivy | VulnCheck CLI | **This Tool** |
|---------|--------|-------|-------|---------------|---------------|
| General CVE lookup | Yes | No | No | Yes | **Yes** |
| Offline/local database | No | Partial | Partial | No | **Yes** |
| No vendor API required | No | Yes | Yes | No | **Yes** |
| EPSS integration | Yes | Yes (2025) | No | Yes | **Yes** |
| KEV integration | Yes | Yes (2025) | No | Yes | **Yes** |
| Composite risk scoring | Partial | Yes | No | Partial | **Yes** |
| SBOM/VEX workflow | No | Yes | Yes | No | **Yes** |
| Exploit availability | Yes | No | No | Yes | **Yes** |
| Statistics/trends | No | No | No | No | **Yes** |
| CPE-based search | Yes | N/A | N/A | Yes | **Yes** |
| CWE-based search | Yes | N/A | N/A | Yes | **Yes** |
| Pipe-friendly output | Partial | Yes | Yes | Yes | **Yes** |
| Transparent scoring | No | Partial | No | No | **Yes** |

### 7.3 Why "Yet Another CVE Tool" Is Justified

1. **cvemap is being deprecated.** The most direct competitor is sunsetting in favor of a proprietary replacement.
2. **The NVD crisis demands multi-source tools.** Single-source tools are increasingly unreliable.
3. **No existing tool combines CVE intelligence with transparent prioritization.** Grype/Trivy are scanners. cvemap/VulnCheck require cloud APIs. There is no open, local-first CVE intelligence CLI.
4. **Unix philosophy is underserved.** Security professionals who work in terminals need composable, pipeable tools -- not web dashboards.
5. **Offline environments exist.** Airgapped networks, classified environments, and restricted networks need local CVE databases.

---

## 8. Recommended Feature Prioritization

### Phase 1: Core Intelligence (MVP)

These features address the most common daily workflow for all personas:

1. **Single/batch CVE lookup** with aggregated data (description, CVSS, EPSS, KEV status, references)
2. **Search by vendor, product, severity, year** with flexible filtering
3. **Local database** with efficient sync from NVD API 2.0 and EPSS/KEV downloads
4. **Multiple output formats:** table (human), JSON, CSV, JSONL (machine)
5. **EPSS-based sorting** and KEV filtering
6. **Offline mode** after initial database sync
7. **Pipe-friendly I/O:** Accept CVE IDs from stdin, output to stdout

### Phase 2: Risk Intelligence

Features that differentiate from basic lookup tools:

1. **Composite risk scoring** (CVSS + EPSS + KEV + exploit availability)
2. **Exploit availability tracking** (PoC-in-GitHub, Exploit-DB, Nuclei references)
3. **CPE-based search** for precise software version matching
4. **CWE-based search** for vulnerability class analysis
5. **Disagreement highlighting** (high EPSS / low CVSS and vice versa)
6. **NVD analysis status visibility** (awaiting-analysis, deferred, etc.)

### Phase 3: Integration and Compliance

Features for embedding in organizational workflows:

1. **SBOM ingestion** (CycloneDX, SPDX) with vulnerability matching
2. **VEX generation** (OpenVEX, CycloneDX VEX)
3. **Jira/ServiceNow-friendly exports** with configurable field selection
4. **KEV compliance reporting** (due dates, overdue items)
5. **Statistics and trend analysis** (publication rates, CWE trends, vendor comparisons)
6. **Alerting/watch mode** for monitoring new CVEs matching criteria

### Phase 4: Advanced Features

Features for power users and specialized workflows:

1. **Multi-source data reconciliation** (show NVD vs CNA CVSS differences)
2. **Historical EPSS tracking** (score trends over time)
3. **CNA/vendor advisory aggregation**
4. **Custom scoring profiles** (adjust weight of CVSS vs EPSS vs KEV for organization-specific risk appetite)
5. **GCVE identifier support** (future-proofing)
6. **Plugin/extension architecture** for custom data sources

---

## Appendix A: API Rate Limits and Data Access

| Source | Endpoint | Rate Limit | Auth Required | Data Format |
|--------|----------|------------|---------------|-------------|
| NVD API 2.0 | `services.nvd.nist.gov/rest/json/cves/2.0` | 5 req/30s (public), 50 req/30s (keyed) | Optional API key | JSON |
| CISA KEV | `www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | None | No | JSON |
| EPSS | `api.first.org/data/v1/epss` | Reasonable use | No | JSON/CSV |
| MITRE CVE | `cveawg.mitre.org/api/cve` | Rate limited | No | JSON |
| OSV.dev | `api.osv.dev/v1/query` | Reasonable use | No | JSON |
| VulnCheck | `api.vulncheck.com/v3` | Tier-dependent | Yes (API key) | JSON |

## Appendix B: Key Data Relationships

```
CVE-ID (canonical identifier)
  |
  +-- NVD Enrichment
  |     +-- CVSS Base Score (v3.1 / v4.0)
  |     +-- CPE Matches (affected software/hardware)
  |     +-- CWE Classification (vulnerability type)
  |     +-- References (advisories, patches)
  |     +-- Analysis Status (analyzed, awaiting, deferred)
  |
  +-- EPSS Score
  |     +-- Probability (0.0 - 1.0)
  |     +-- Percentile (relative ranking)
  |     +-- Updated daily
  |
  +-- CISA KEV
  |     +-- Date Added
  |     +-- Due Date (remediation deadline)
  |     +-- Ransomware Usage (known/unknown)
  |     +-- Required Action
  |
  +-- Exploit Intelligence
  |     +-- Exploit-DB entries
  |     +-- GitHub PoCs
  |     +-- Metasploit modules
  |     +-- Nuclei templates
  |
  +-- Vendor Advisories
        +-- Vendor-assigned CVSS
        +-- Fix versions
        +-- Workarounds
```

## Appendix C: Real-World Query Frequency Estimates

Based on practitioner experience, estimated query frequency by type:

| Query Type | Frequency | Example |
|-----------|-----------|---------|
| Single CVE lookup | 50+ per day | Analyst investigating scanner finding |
| Batch CVE enrichment | 5-10 per day | Processing scan reports |
| Vendor/product search | 10-20 per day | "What's new for our tech stack?" |
| KEV check | 5-10 per day | Compliance verification |
| EPSS-based prioritization | 5-10 per day | Triage decisions |
| Statistics/trends | 1-2 per week | Reporting and analysis |
| SBOM check | 1-5 per day | CI/CD pipeline integration |
| Export for ticketing | 2-5 per day | Creating remediation tickets |

This frequency distribution should guide performance optimization: single CVE lookups and batch enrichment must be sub-second from local cache. Search queries should return within 1-2 seconds. Statistics can tolerate slightly longer execution times.
