# vulnex

[![Release](https://img.shields.io/github/v/release/AnasSahel/vulnex)](https://github.com/AnasSahel/vulnex/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/AnasSahel/vulnex)](https://go.dev/)
[![CI](https://github.com/AnasSahel/vulnex/actions/workflows/ci.yml/badge.svg)](https://github.com/AnasSahel/vulnex/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An open-source, offline-capable, multi-source vulnerability intelligence CLI.

vulnex aggregates data from **NVD**, **CISA KEV**, **EPSS**, **GitHub Advisory Database**, and **OSV.dev** into a unified command-line experience with local SQLite caching, composite risk scoring, and pipe-friendly output.

### Demo

```
$ vulnex enrich CVE-2021-44228

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
- **Offline mode** — Local SQLite cache with configurable TTLs; work without network access
- **SBOM scanning** — Parse CycloneDX/SPDX SBOMs, find vulnerabilities grouped by component, and generate OpenVEX documents
- **CI/CD gating** — `sbom check` exits with code 1 when vulnerabilities are found; filter by `--severity` to control thresholds
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
vulnex enrich CVE-2021-44228

# Check if a CVE is in CISA's Known Exploited Vulnerabilities catalog
vulnex kev check CVE-2024-3094

# Get EPSS exploitation probability
vulnex epss score CVE-2024-3094

# Search for CVEs
vulnex cve search "apache log4j" --severity critical

# Scan an SBOM for vulnerabilities
vulnex sbom check bom.json

# Fail CI if critical vulnerabilities exist
vulnex sbom check bom.json --severity critical
```

## Configuration

Initialize a default config file:

```bash
vulnex config init
# Creates ~/.config/vulnex/config.yaml
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
| `-o, --output <format>` | Output format: `table`, `json`, `csv`, `markdown`, `yaml` (default: `table`) |
| `-l, --long` | Show full descriptions instead of truncated |
| `--no-color` | Disable colored output |
| `--api-key <key>` | NVD API key |
| `--cache-dir <path>` | Custom cache directory |
| `--no-cache` | Bypass cache for this request |
| `--offline` | Only use locally cached data (no network) |
| `--config <path>` | Path to config file |
| `--timeout <duration>` | HTTP timeout (e.g. `30s`, `1m`) |
| `-v, --verbose` | Verbose output |
| `-q, --quiet` | Suppress non-essential output |

## Commands

### `vulnex enrich` — Multi-source aggregation

The flagship command. Combines NVD + KEV + EPSS + GitHub Advisory + OSV into a single enriched view.

```bash
vulnex enrich CVE-2021-44228
vulnex enrich CVE-2024-3094 CVE-2023-44228 --output json
echo "CVE-2024-3094" | vulnex enrich --stdin --output table
cat cves.txt | vulnex enrich --stdin --output csv > enriched.csv
```

### `vulnex cve` — CVE operations

#### `cve get` — Fetch enriched CVE details

```bash
vulnex cve get CVE-2021-44228
vulnex cve get CVE-2024-3094 CVE-2023-44228 --output json
echo "CVE-2024-3094" | vulnex cve get --stdin
```

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

```bash
vulnex kev list
vulnex kev list --output json
```

#### `kev recent` — Recently added entries

```bash
vulnex kev recent
vulnex kev recent --days 7
```

#### `kev check` — Check if CVEs are in KEV

```bash
vulnex kev check CVE-2021-44228
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

#### `sbom check` — Scan SBOM for vulnerabilities

Parses CycloneDX or SPDX JSON files and queries each component against OSV. Results are grouped by component showing advisory ID, severity, fixed version, and summary. Exits with code 1 when vulnerabilities are found, making it suitable for CI/CD pipelines.

```bash
vulnex sbom check bom.json
vulnex sbom check bom.json --vex                     # output as OpenVEX document
vulnex sbom check sbom-spdx.json --ecosystem npm     # filter by ecosystem
vulnex sbom check bom.json --severity critical        # only critical findings
vulnex sbom check bom.json --output json              # structured JSON output
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
| `--vex` | Output an OpenVEX document instead of a table |
| `--ecosystem` | Filter components by ecosystem |
| `--severity` | Filter results by severity (exits 0 if no matches) |

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
vulnex kev recent --days 7 -o csv | cut -d, -f1 | vulnex enrich --stdin -o json

# Bulk score from a file
cat my-cves.txt | vulnex epss score --stdin -o csv > scores.csv

# Offline mode after warming the cache
vulnex enrich CVE-2021-44228          # fetches and caches
vulnex --offline enrich CVE-2021-44228  # reads from cache only
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
