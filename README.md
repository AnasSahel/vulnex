# vulnex

[![Release](https://img.shields.io/github/v/release/AnasSahel/vulnex)](https://github.com/AnasSahel/vulnex/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/AnasSahel/vulnex)](https://go.dev/)
[![CI](https://github.com/AnasSahel/vulnex/actions/workflows/ci.yml/badge.svg)](https://github.com/AnasSahel/vulnex/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An open-source, offline-capable, multi-source vulnerability intelligence CLI.

vulnex aggregates data from **NVD**, **CISA KEV**, **EPSS**, **GitHub Advisory Database**, and **OSV.dev** into a unified command-line experience with local SQLite caching, composite risk scoring, and pipe-friendly output.

**[Documentation](https://anassahel.github.io/vulnex/docs/)** | **[Getting Started](https://anassahel.github.io/vulnex/docs/getting-started/)**

### Demo

```
$ vulnex cve get CVE-2021-44228

 CVE-2021-44228 — Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints

 Severity    CRITICAL (10.0)
 Vector      NETWORK / LOW / NONE / CHANGED
 Priority    P0 — Critical: actively exploited, high EPSS

 EPSS        0.97185 (97.2%) — percentile: 99.99%
 KEV         Yes — due 2021-12-24
 Published   2021-12-10
 Modified    2023-11-06

 Sources     NVD · KEV · EPSS · GHSA · OSV

 References
  • https://logging.apache.org/log4j/2.x/security.html
  • https://www.cisa.gov/known-exploited-vulnerabilities-catalog
```

## Features

- **Multi-source enrichment** — Combine NVD, KEV, EPSS, GHSA, and OSV data in a single query
- **Composite risk scoring** — P0–P4 priority matrix blending CVSS, EPSS, and KEV signals
- **Configurable scoring profiles** — Choose from built-in profiles (default, exploit-focused, severity-focused) or set custom weights for CVSS, EPSS, and KEV signals
- **Lockfile scanning** — Scan lockfiles directly for vulnerabilities: `go.sum`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `Gemfile.lock`, `requirements.txt`, `poetry.lock`, `composer.lock`
- **Offline mode** — Local SQLite cache with configurable TTLs; work without network access
- **SBOM scanning** — Parse CycloneDX/SPDX SBOMs, find vulnerabilities grouped by component, and generate OpenVEX documents
- **SBOM diffing** — Compare two SBOMs and see which vulnerabilities a dependency change introduces or fixes
- **CI/CD gating** — `sbom check` / `scan` exits 1 on vulns found, `sbom diff` exits 1 on new vulns introduced; filter by `--severity` to control thresholds
- **Suppression file** — `.vulnexignore` lets teams suppress accepted risks with package scoping, expiry dates, and audit trails
- **Pipe-friendly** — stdin support, multiple output formats, and composable commands
- **Zero CGO** — Pure Go with no C dependencies; single static binary

## Installation

### Homebrew

```bash
brew install AnasSahel/tap/vulnex
```

### From source

```bash
go install github.com/trustin-tech/vulnex@latest
```

### Build from source

```bash
git clone https://github.com/AnasSahel/vulnex.git
cd vulnex
make build
```

## Quick Start

```bash
# Enrich a CVE with all data sources
vulnex cve get CVE-2021-44228

# Check if a CVE is in CISA's Known Exploited Vulnerabilities catalog
vulnex kev check CVE-2024-3094

# Get EPSS exploitation probability
vulnex epss score CVE-2024-3094

# Search for CVEs
vulnex cve search "apache log4j" --severity critical

# Scan a lockfile or SBOM for vulnerabilities
vulnex scan go.sum
vulnex scan package-lock.json
vulnex sbom check bom.json

# Diff two SBOMs — what vulns did this change introduce?
vulnex sbom diff old-bom.json new-bom.json

# Fail CI if critical vulnerabilities exist
vulnex sbom check bom.json --severity critical

# View scoring profiles and thresholds
vulnex scoring
```

## Configuration

Initialize a default config file:

```bash
vulnex config init
# Creates ~/.vulnex/config.yaml
```

Manage settings:

```bash
vulnex config show
vulnex config get api_keys.nvd
vulnex config set api_keys.nvd "your-key-here"
```

You can also set the NVD API key via environment variable or flag:

```bash
export VULNEX_API_KEY="your-key-here"
# or
vulnex --api-key "your-key-here" cve get CVE-2021-44228
```

## Global Flags

These flags apply to all commands:

| Flag | Description |
|------|-------------|
| `-o, --output <format>` | Output format: `table`, `json`, `csv`, `markdown`, `yaml`, `sarif` (default: `table`) |
| `-l, --long` | Show full descriptions instead of truncated |
| `--no-color` | Disable colored output |
| `--api-key <key>` | NVD API key |
| `--cache-dir <path>` | Custom cache directory |
| `--no-cache` | Bypass cache for this request |
| `--offline` | Only use locally cached data (no network) |
| `--config <path>` | Path to config file |
| `--timeout <duration>` | HTTP request timeout (e.g., `30s`, `1m`, `2m30s`) |
| `-v, --verbose` | Verbose output |
| `-q, --quiet` | Suppress non-essential output |

## Commands

### `vulnex scan` — Scan lockfiles and SBOMs

Scan a package lockfile or SBOM file for known vulnerabilities. Automatically detects the format and queries OSV. This is the fastest way to check your dependencies.

```bash
vulnex scan go.sum
vulnex scan package-lock.json --severity HIGH
vulnex scan Cargo.lock -o json
vulnex scan bom.json --ecosystem npm
```

Supported lockfiles: `go.sum`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `Gemfile.lock`, `requirements.txt`, `poetry.lock`, `composer.lock`.

Supported SBOMs: CycloneDX (JSON), SPDX (JSON).

| Flag | Description |
|------|-------------|
| `--vex` | Output a VEX document for sharing triage decisions |
| `--enrich` | Add exploit likelihood, known-exploitation status, and severity scores from multiple sources |
| `--ecosystem` | Filter components by ecosystem |
| `--severity` | Filter results by severity (exits 0 if no matches) |
| `--ignore-file` | Path to suppression file (default: `.vulnexignore`) |
| `--strict` | Show all findings, including those suppressed by `.vulnexignore` |

### `vulnex cve` — CVE operations

#### `cve get` — Fetch enriched CVE details

The flagship command. Combines NVD + KEV + EPSS + GitHub Advisory + OSV into a single enriched view.

```bash
vulnex cve get CVE-2021-44228
vulnex cve get CVE-2024-3094 CVE-2023-44228 --output json
echo "CVE-2024-3094" | vulnex cve get --stdin --output table
cat cves.txt | vulnex cve get --stdin --output csv > enriched.csv

# With weighted scoring
vulnex cve get CVE-2024-24790 --scoring-profile default
vulnex cve get CVE-2024-24790 --scoring-profile exploit-focused
vulnex cve get CVE-2024-24790 --cvss-weight 0.5 --epss-weight 0.3 --kev-weight 0.2

# Ignore CVSS entirely, score only on real-world exploitation evidence
vulnex cve get CVE-2024-3094 --cvss-weight 0 --epss-weight 0.7 --kev-weight 0.3
```

| Flag | Description |
|------|-------------|
| `--stdin` | Read CVE IDs from stdin |
| `--scoring-profile` | Preset weight balance for scoring: `default` (balanced), `exploit-focused`, or `severity-focused` |
| `--cvss-weight` | How much severity (CVSS) influences the final score, from 0.0 (ignore) to 1.0 (full weight) |
| `--epss-weight` | How much exploit probability (EPSS) influences the final score, from 0.0 (ignore) to 1.0 (full weight) |
| `--kev-weight` | How much known-exploited status (KEV) influences the final score, from 0.0 (ignore) to 1.0 (full weight) |

#### `cve search` — Search CVEs by keyword

```bash
vulnex cve search "apache log4j"
vulnex cve search "remote code execution" --severity critical --has-kev
vulnex cve search "fortinet" --year 2024 --output json
vulnex cve search "xss" --cwe CWE-79 --limit 50
```

| Flag | Description |
|------|-------------|
| `--severity` | Filter by severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--has-kev` | Only show CVEs in CISA KEV |
| `--year` | Filter by publication year |
| `--cwe` | Filter by CWE ID (e.g. `CWE-79`) |
| `--no-rejected` | Exclude rejected CVEs (default: true) |
| `--limit` | Maximum results (default: 20) |

#### `cve list` — List CVEs with filters

```bash
vulnex cve list --severity critical --limit 50
vulnex cve list --start-date 2024-01-01 --end-date 2024-12-31
vulnex cve list --offset 20 --limit 20
```

| Flag | Description |
|------|-------------|
| `--severity` | Filter by severity |
| `--start-date` | Publication start date (`YYYY-MM-DD`) |
| `--end-date` | Publication end date (`YYYY-MM-DD`) |
| `--limit` | Results per page (default: 20) |
| `--offset` | Starting offset for pagination |

#### `cve history` — Modification history

```bash
vulnex cve history CVE-2021-44228
vulnex cve history CVE-2024-3094 --output json
```

#### `cve watch` — Local watch list

```bash
vulnex cve watch CVE-2024-3094 CVE-2021-44228    # add to watch list
vulnex cve watch --list                           # show watched CVEs
vulnex cve watch --refresh                        # re-fetch all watched CVEs
vulnex cve watch --remove CVE-2024-3094           # remove from list
cat cves.txt | vulnex cve watch --stdin            # add from file
```

### `vulnex kev` — CISA Known Exploited Vulnerabilities

#### `kev list` — List all KEV entries

Browse the CISA KEV catalog with pagination. Defaults to 20 entries per page.

```bash
vulnex kev list                        # first 20 entries
vulnex kev list --limit 50             # 50 entries
vulnex kev list --limit 0              # all entries
vulnex kev list --offset 20            # skip first 20
vulnex kev list --ransomware           # only ransomware-linked entries
vulnex kev list --output json
```

| Flag | Description |
|------|-------------|
| `--limit` | Maximum entries to display (default: 20, 0 = all) |
| `--offset` | Skip first N entries for pagination |
| `--ransomware` | Show only entries with known ransomware campaigns |

#### `kev recent` — Recently added entries

```bash
vulnex kev recent                      # last 7 days
vulnex kev recent --days 30
vulnex kev recent --ransomware         # only ransomware-linked
```

| Flag | Description |
|------|-------------|
| `--days` | Number of days to look back (default: 7) |
| `--ransomware` | Show only entries with known ransomware campaigns |

#### `kev check` — Check if CVEs are in KEV

Displays detailed label-value output for each match. Long fields (description, required action, notes) are truncated by default — use `--long` to show full content.

```bash
vulnex kev check CVE-2021-44228
vulnex kev check CVE-2021-44228 --long
vulnex kev check CVE-2024-3094 CVE-2023-44228
echo "CVE-2024-3094" | vulnex kev check --stdin
```

#### `kev stats` — Catalog statistics

```bash
vulnex kev stats
vulnex kev stats --top 20
```

### `vulnex epss` — Exploit Prediction Scoring System

#### `epss score` — Get EPSS scores

```bash
vulnex epss score CVE-2024-3094
vulnex epss score CVE-2024-3094 CVE-2023-44228 CVE-2021-44228
cat cves.txt | vulnex epss score --stdin --output csv
```

#### `epss top` — Top CVEs by exploitation probability

```bash
vulnex epss top
vulnex epss top 50 --output json
```

#### `epss trend` — EPSS score history over time

```bash
vulnex epss trend CVE-2021-44228
vulnex epss trend CVE-2024-3094 --days 30 --output json
```

### `vulnex advisory` — GitHub Advisory Database & OSV

#### `advisory search` — Search advisories

```bash
vulnex advisory search "log4j"
vulnex advisory search "xss" --ecosystem npm --severity critical
vulnex advisory search "sql injection" --type reviewed --limit 50
```

| Flag | Description |
|------|-------------|
| `--ecosystem` | Filter by ecosystem: `npm`, `pip`, `maven`, `go`, etc. |
| `--severity` | Filter by severity: `critical`, `high`, `medium`, `low` |
| `--type` | Advisory type: `reviewed`, `malware`, `unreviewed` (default: `reviewed`) |
| `--limit` | Maximum results (default: 30) |

#### `advisory get` — Get a specific advisory

```bash
vulnex advisory get GHSA-jfh8-c2jp-5v3q
vulnex advisory get GHSA-jfh8-c2jp-5v3q --output json
```

#### `advisory affected` — Find advisories for a package

```bash
vulnex advisory affected lodash --ecosystem npm
vulnex advisory affected django --ecosystem pip --output json
```

### `vulnex sbom` — SBOM analysis

#### `sbom check` — Scan SBOM or lockfile for vulnerabilities

Parses CycloneDX/SPDX JSON files or package lockfiles and queries each component against OSV. Results are grouped by component showing advisory ID, severity, fixed version, and summary. Exits with code 1 when vulnerabilities are found, making it suitable for CI/CD pipelines.

This is equivalent to `vulnex scan` — both commands accept lockfiles and SBOMs.

```bash
vulnex sbom check bom.json
vulnex sbom check go.sum                              # lockfile support
vulnex sbom check package-lock.json                   # lockfile support
vulnex sbom check bom.json --vex                      # output as OpenVEX document
vulnex sbom check sbom-spdx.json --ecosystem npm      # filter by ecosystem
vulnex sbom check bom.json --severity critical         # only critical findings
vulnex sbom check bom.json --output json               # structured JSON output
```

Example table output:

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

| Flag | Description |
|------|-------------|
| `--vex` | Output a VEX document for sharing triage decisions |
| `--enrich` | Add exploit likelihood, known-exploitation status, and severity scores from multiple sources |
| `--ecosystem` | Filter components by ecosystem |
| `--severity` | Filter results by severity (exits 0 if no matches) |
| `--ignore-file` | Path to suppression file (default: `.vulnexignore`) |
| `--strict` | Show all findings, including those suppressed by `.vulnexignore` |

#### `sbom diff` — Compare two SBOMs for vulnerability changes

Compares two CycloneDX or SPDX JSON SBOM files and reports which vulnerabilities were added, removed, or unchanged. Exits with code 1 when new vulnerabilities are introduced — use it as a CI gate to block risky dependency changes.

```bash
vulnex sbom diff old-bom.json new-bom.json
vulnex sbom diff old.json new.json --severity critical    # only critical changes
vulnex sbom diff old.json new.json --ecosystem npm        # filter by ecosystem
vulnex sbom diff old.json new.json -o json                # structured JSON output
```

Example table output:

```
+ ADDED (2 vulnerabilities)
  flask 0.12.0 (PyPI)
    GHSA-562c-5r94-xh97       HIGH      0.12.3   Flask is vulnerable to Denial of...
    GHSA-5wv5-4vpf-pj6m       HIGH      1.0      Directory traversal in Flask

- REMOVED (1 vulnerability)
  lodash 4.17.20 (npm)
    GHSA-35jh-r3h4-6jhm       HIGH      4.17.21  Command Injection in lodash

= UNCHANGED (55 vulnerabilities)
  django 3.2.0 (PyPI)
    GHSA-2gwj-7jmv-h26r       CRITICAL  2.2.28   SQL Injection in Django

Summary: old=3 components (56 vulns), new=4 components (57 vulns), +2 added, -1 removed
```

| Flag | Description |
|------|-------------|
| `--ecosystem` | Filter components by ecosystem |
| `--severity` | Filter results by severity |
| `--ignore-file` | Path to suppression file (default: `.vulnexignore`) |
| `--strict` | Show all findings, including those suppressed by `.vulnexignore` |

### `.vulnexignore` — Suppressing accepted risks

Create a `.vulnexignore` file in your project root to suppress known false positives or accepted risks. Suppressed findings are excluded from the exit code calculation, allowing your CI gate to stay on while managing noise.

```yaml
suppressions:
  - id: GHSA-2gwj-7jmv-h26r          # required: advisory ID
    package: django                    # optional: scope to package
    reason: "Transitive dep, mitigated at WAF"  # required: justification
    expires: "2026-06-01"              # optional: auto-unsuppress after date
    approved_by: security-team         # optional: who approved
```

**Behavior:**
- `sbom check` and `sbom diff` automatically load `.vulnexignore` from the current directory
- Use `--ignore-file <path>` to specify a different file
- Use `--strict` to skip suppression and report all findings
- Expired entries (past the `expires` date) are automatically ignored — the finding becomes active again
- In `sbom diff`, only **added** findings are eligible for suppression (removed/unchanged don't gate CI)

### `vulnex exploit` — Exploit intelligence

#### `exploit check` — Check exploit availability

Cross-references CVE IDs against four exploit intelligence sources — GitHub PoCs, Nuclei templates, Metasploit modules, and ExploitDB — and presents a unified view.

```bash
vulnex exploit check CVE-2021-44228
vulnex exploit check CVE-2021-44228 CVE-2017-0144 -o json
echo "CVE-2024-3094" | vulnex exploit check --stdin
```

Example output:

```
CVE-2021-44228 — 8 known exploit(s)

  SOURCE       NAME                                          URL
  github       kozmer/log4j-shell-poc (1.2k)                 https://github.com/kozmer/log4j-shell-poc
  github       fullhunt/log4j-scan (3.1k)                    https://github.com/fullhunt/log4j-scan
  metasploit   exploit/multi/http/log4shell_header_injection  https://github.com/rapid7/...
  nuclei       http/cves/2021/cve-2021-44228.yaml            https://github.com/projectdiscovery/...
  exploitdb    50592                                          https://www.exploit-db.com/exploits/50592

Sources: GitHub (5) · Metasploit (2) · Nuclei (1) · ExploitDB (1)
```

| Flag | Description |
|------|-------------|
| `--stdin` | Read CVE IDs from stdin |

### `vulnex scoring` — Scoring profiles and thresholds

Display the built-in scoring profiles and P0–P4 priority threshold matrix. No API calls needed. See the [Scoring & Prioritization Guide](https://vulnex.dev/docs/scoring/) for the full formula, worked examples, and practical guidance on choosing weights.

```bash
vulnex scoring
```

Output:

```
Scoring Profiles
================

  default              CVSS=0.30  EPSS=0.50  KEV=0.20
  exploit-focused      CVSS=0.10  EPSS=0.60  KEV=0.30
  severity-focused     CVSS=0.60  EPSS=0.30  KEV=0.10

Risk Priority Thresholds
========================

  P0-CRITICAL   In CISA KEV (regardless of other scores)
  P1-HIGH       EPSS >= 0.7 OR CVSS >= 9.0
  P2-MEDIUM     EPSS >= 0.3 OR (CVSS >= 7.0 AND EPSS >= 0.1)
  P3-LOW        CVSS >= 7.0 but EPSS < 0.1
  P4-MINIMAL    CVSS < 7.0 AND EPSS < 0.1
```

Use `--scoring-profile` with `cve get` to surface weighted scores:

```bash
vulnex cve get CVE-2024-24790 --scoring-profile default
vulnex cve get CVE-2024-24790 --scoring-profile exploit-focused
vulnex cve get CVE-2024-24790 --scoring-profile severity-focused
```

### `vulnex stats` — Vulnerability statistics

```bash
vulnex stats --year 2024                                  # severity breakdown
vulnex stats --group-by cwe --year 2024 --limit 10        # top CWEs
vulnex stats --group-by month --year 2024                  # monthly trend
vulnex stats --group-by vendor --vendor "apache" --year 2024
```

| Flag | Description |
|------|-------------|
| `--group-by` | Group by: `month`, `cwe`, `vendor` (default: severity) |
| `--year` | Filter by publication year |
| `--vendor` | Filter by vendor keyword |
| `--severity` | Filter by severity |
| `--limit` | Maximum rows (default: 20) |

### `vulnex cache` — Cache management

```bash
vulnex cache stats      # show cache size, entry counts
vulnex cache clear      # delete all cached data
vulnex cache update     # force refresh of cached data
```

### `vulnex completion` — Shell completions

```bash
# Bash
vulnex completion bash > /etc/bash_completion.d/vulnex

# Zsh
vulnex completion zsh > "${fpath[1]}/_vulnex"

# Fish
vulnex completion fish > ~/.config/fish/completions/vulnex.fish

# PowerShell
vulnex completion powershell > vulnex.ps1
```

## Piping & Composition

All commands that accept CVE IDs support `--stdin` for piping:

```bash
# Chain: get recent KEV entries, enrich them
vulnex kev recent --days 7 -o csv | cut -d, -f1 | vulnex cve get --stdin -o json

# Bulk score from a file
cat my-cves.txt | vulnex epss score --stdin -o csv > scores.csv

# Offline mode after warming the cache
vulnex cve get CVE-2021-44228            # fetches and caches
vulnex --offline cve get CVE-2021-44228  # reads from cache only
```

## Output Formats

Use `-o` / `--output` to switch formats:

| Format | Description |
|--------|-------------|
| `table` | Color-coded terminal table (default) |
| `json` | Pretty-printed JSON |
| `csv` | Comma-separated values |
| `markdown` | Markdown tables |
| `yaml` | YAML |
| `sarif` | [SARIF v2.1.0](https://sarifweb.azurewebsites.net/) for GitHub Code Scanning, Azure DevOps, IDE viewers |

### SARIF Output & GitHub Code Scanning

Generate SARIF v2.1.0 output for integration with GitHub Code Scanning, Azure DevOps, and SARIF-compatible IDE viewers:

```bash
vulnex sbom check bom.json -o sarif > results.sarif
```

Upload to GitHub Code Scanning in CI:

```yaml
- run: vulnex sbom check bom.json -o sarif > results.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Data Sources

| Source | Description | API |
|--------|-------------|-----|
| [NVD](https://nvd.nist.gov/) | NIST National Vulnerability Database | NVD API 2.0 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known Exploited Vulnerabilities catalog | JSON feed |
| [EPSS](https://www.first.org/epss/) | Exploit Prediction Scoring System | FIRST.org API |
| [GitHub Advisory](https://github.com/advisories) | GitHub Advisory Database | REST API |
| [OSV](https://osv.dev/) | Open Source Vulnerabilities | OSV.dev API |

## License

MIT

---

> This product uses the NVD API but is not endorsed or certified by the NVD.
