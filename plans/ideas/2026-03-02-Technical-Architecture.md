---
status: incorporated
type: idea
date: 2026-03-02
title: Technical Architecture
---

# CVE CLI Tool -- Technical Architecture

## 1. Language & Framework Choice

### Recommendation: Go with Cobra

**Go** is the clear winner for this project. Here is the justification:

| Criterion | Go | Rust | Python |
|---|---|---|---|
| Single binary distribution | Yes | Yes | No (requires runtime) |
| Cross-compilation | Trivial (`GOOS`/`GOARCH`) | Requires cross-linker setup | N/A |
| CLI ecosystem maturity | Cobra, Viper, lipgloss, bubbletea | clap is excellent but smaller ecosystem | Click/Typer are good but distribution is painful |
| Concurrency model | Goroutines + channels (built-in) | Tokio async (powerful but complex) | asyncio (GIL limitations) |
| Build speed | Fast | Slow | N/A |
| Ecosystem precedent | cvemap, grype, trivy, syft, kubectl, helm | none in this space | some small tools |
| CGO-free SQLite | modernc.org/sqlite (pure Go) | rusqlite (C binding) | sqlite3 (C binding) |

Every major vulnerability tool in this space (cvemap, grype, trivy, syft) is written in Go. This is not a coincidence -- Go's single-binary output, trivial cross-compilation, and goroutine-based concurrency are ideal for CLI tools that fetch from multiple APIs concurrently.

**Framework stack:**

| Component | Library | Rationale |
|---|---|---|
| CLI framework | `github.com/spf13/cobra` | Industry standard, nested subcommands, auto-generated help/completions |
| Configuration | `github.com/spf13/viper` | Seamless integration with Cobra, supports YAML/TOML/env vars |
| HTTP client | `github.com/hashicorp/go-retryablehttp` | Built-in retry, backoff, rate-limit awareness |
| Table output | `github.com/charmbracelet/lipgloss` + `github.com/charmbracelet/table` | Modern terminal rendering |
| JSON output | `encoding/json` (stdlib) | No dependency needed |
| SQLite cache | `modernc.org/sqlite` | Pure Go, no CGO, cross-compiles cleanly |
| Logging | `log/slog` (stdlib, Go 1.21+) | Structured logging, zero dependencies |
| Testing | `github.com/stretchr/testify` | Assertions and mocks |

---

## 2. Data Sources & APIs

### 2.1 NVD API 2.0 (Primary CVE Data)

| Property | Value |
|---|---|
| Base URL | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| Auth | API key via `apiKey` request header (free, requires registration at https://nvd.nist.gov/developers/request-an-api-key) |
| Rate limit (no key) | 5 requests / 30 seconds |
| Rate limit (with key) | 50 requests / 30 seconds |
| Pagination | `startIndex` (0-based offset) + `resultsPerPage` (max 2000) |
| Response format | JSON (UTF-8, ISO-8601 dates) |

**Key query parameters:**

```
cveId              - Single CVE lookup (e.g., CVE-2024-1234)
cpeName            - Filter by CPE URI
keywordSearch      - Full-text search in descriptions
keywordExactMatch  - Exact phrase matching
cvssV3Severity     - LOW | MEDIUM | HIGH | CRITICAL
cweId              - Filter by CWE identifier
hasKev             - Boolean, in CISA KEV catalog
pubStartDate       - Published date range start (ISO-8601)
pubEndDate         - Published date range end
lastModStartDate   - Modified date range start
lastModEndDate     - Modified date range end
noRejected         - Exclude rejected CVEs
```

**Response structure (simplified):**

```json
{
  "resultsPerPage": 20,
  "startIndex": 0,
  "totalResults": 1,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2024-1234",
        "sourceIdentifier": "cve@mitre.org",
        "published": "2024-01-15T00:00:00.000",
        "lastModified": "2024-01-16T00:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "..."}],
        "metrics": {
          "cvssMetricV31": [{
            "cvssData": {
              "baseScore": 9.8,
              "baseSeverity": "CRITICAL",
              "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }
          }]
        },
        "weaknesses": [{"description": [{"value": "CWE-79"}]}],
        "configurations": [...],
        "references": [{"url": "...", "source": "...", "tags": [...]}]
      }
    }
  ]
}
```

### 2.2 CISA KEV Catalog (Known Exploited Vulnerabilities)

| Property | Value |
|---|---|
| JSON Feed URL | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| GitHub Mirror | `https://github.com/cisagov/kev-data` (raw JSON files) |
| Auth | None required |
| Rate limit | None documented (static file) |
| Update frequency | Updated as new KEVs are added (typically several times per week) |

**Response structure:**

```json
{
  "catalogVersion": "2024.01.15",
  "dateReleased": "2024-01-15T00:00:00.0000Z",
  "count": 1100,
  "vulnerabilities": [
    {
      "cveID": "CVE-2024-1234",
      "vendorProject": "Apache",
      "product": "HTTP Server",
      "vulnerabilityName": "Apache HTTP Server Path Traversal",
      "dateAdded": "2024-01-10",
      "shortDescription": "...",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2024-01-31",
      "knownRansomwareCampaignUse": "Known",
      "notes": ""
    }
  ]
}
```

**Integration strategy:** Download the full JSON on first use, cache locally, and use ETag/If-Modified-Since headers for incremental updates. The file is small (~1.5 MB) so full download on cache miss is acceptable.

### 2.3 FIRST EPSS API (Exploit Prediction Scores)

| Property | Value |
|---|---|
| Base URL | `https://api.first.org/data/v1/epss` |
| Auth | None required |
| Rate limit | Not formally documented; be respectful (1-2 req/sec recommended) |
| Status | BETA |
| Max `cve` param length | 2000 characters |

**Key query parameters:**

```
cve            - Comma-separated CVE IDs (max 2000 chars)
date           - Historical date (YYYY-MM-DD), since 2021-04-14
epss-gt        - EPSS score greater than threshold
epss-lt        - EPSS score less than threshold
percentile-gt  - Percentile greater than threshold
percentile-lt  - Percentile less than threshold
q              - Free text / partial CVE ID search
scope          - "public" (default) | "time-series"
offset         - Pagination offset
limit          - Page size (default 1000)
order          - Sort field, prefix ! for descending (e.g., !epss)
```

**Response structure:**

```json
{
  "status": "OK",
  "status-code": 200,
  "version": "1.0",
  "total": 1,
  "offset": 0,
  "limit": 100,
  "data": [
    {
      "cve": "CVE-2024-1234",
      "epss": "0.93215",
      "percentile": "0.99841",
      "date": "2024-01-15"
    }
  ]
}
```

### 2.4 GitHub Advisory Database (GHSA)

| Property | Value |
|---|---|
| REST endpoint | `https://api.github.com/advisories` |
| Single advisory | `https://api.github.com/advisories/{ghsa_id}` |
| Auth | Optional (public data works unauthenticated); token increases rate limit |
| Rate limit (unauth) | 60 requests/hour |
| Rate limit (auth) | 5000 requests/hour |
| Pagination | `per_page` (max 100, default 30), Link header for cursor |

**Key query parameters:**

```
ghsa_id        - GHSA identifier
cve_id         - CVE identifier
type           - reviewed | malware | unreviewed
ecosystem      - npm, pip, maven, nuget, go, rubygems, rust, etc.
severity       - critical | high | medium | low | unknown
cwes           - CWE identifiers
published      - Date range (YYYY-MM-DD)
updated        - Date range
sort           - updated | published | epss_percentage | epss_percentile
direction      - asc | desc
per_page       - Results per page (max 100)
```

### 2.5 MITRE CVE Services API

| Property | Value |
|---|---|
| Base URL | `https://cveawg.mitre.org/api/` |
| API Docs | `https://cveawg.mitre.org/api-docs/` (Swagger/OpenAPI 3.0) |
| Auth | None for public read operations |
| Version | 2.5.x |

Useful for retrieving the canonical CVE record as published by the CNA (CVE Numbering Authority), including the CVE JSON 5.0 format. Lower priority than NVD which enriches the same data with CVSS scores and CPE configurations.

### 2.6 OSV.dev (Open Source Vulnerabilities)

| Property | Value |
|---|---|
| Query endpoint | `https://api.osv.dev/v1/query` (POST) |
| Single vuln | `https://api.osv.dev/v1/vulns/{id}` (GET) |
| Batch query | `https://api.osv.dev/v1/querybatch` (POST) |
| Auth | None required |
| Rate limit | Not formally documented |
| Response limit | 32 MiB (HTTP/1.1), unlimited (HTTP/2) |

Aggregates from: GitHub Advisory Database, PyPA, RustSec, Go Vulnerability Database, and many more. Excellent for mapping CVEs to affected open-source packages.

### 2.7 VulnCheck NVD++ (Optional, Enhanced NVD Mirror)

| Property | Value |
|---|---|
| API | VulnCheck Community (free tier) |
| Auth | API key required (free registration) |
| Rate limit | None documented (no archaic rate limits) |
| Advantage | 77% CPE coverage vs NVD's 41% for 2024 CVEs; higher availability than NVD |

Consider as a fallback data source or premium integration when the NVD API is unreliable (which has been a persistent issue).

### Data Source Priority Matrix

| Data Point | Primary Source | Fallback |
|---|---|---|
| CVE details + CVSS | NVD API 2.0 | VulnCheck NVD++ |
| KEV status | CISA KEV JSON feed | NVD `hasKev` parameter |
| EPSS scores | FIRST EPSS API | GitHub Advisory `epss_*` fields |
| Package advisories | OSV.dev | GitHub Advisory Database |
| Exploit availability | ExploitDB (via go-exploitdb) | GitHub Advisory + references |
| CWE details | NVD (embedded in CVE) | MITRE CWE website |

---

## 3. CLI Design

### 3.1 Command Structure

```
cve-cli
  |-- cve                    # CVE operations (default command group)
  |   |-- get <CVE-ID>       # Fetch single CVE with all enrichment
  |   |-- search <query>     # Search CVEs by keyword
  |   |-- list               # List CVEs with filters
  |   |-- history <CVE-ID>   # Show CVE modification history
  |   |-- watch <CVE-ID...>  # Watch CVEs for changes (writes to cache)
  |
  |-- kev                    # CISA KEV operations
  |   |-- list               # List all KEV entries
  |   |-- check <CVE-ID...>  # Check if CVE(s) are in KEV
  |   |-- recent             # Show recently added KEVs
  |   |-- stats              # KEV catalog statistics
  |
  |-- epss                   # EPSS operations
  |   |-- score <CVE-ID...>  # Get EPSS score(s)
  |   |-- top [N]            # Top N CVEs by EPSS score
  |   |-- trend <CVE-ID>     # EPSS score time series
  |
  |-- advisory               # Advisory database operations
  |   |-- search <query>     # Search GitHub/OSV advisories
  |   |-- get <GHSA-ID>      # Get specific advisory
  |   |-- affected <package> # Find advisories for a package
  |
  |-- enrich <CVE-ID...>     # Aggregate all data sources for CVE(s)
  |
  |-- cache                  # Cache management
  |   |-- clear              # Clear local cache
  |   |-- stats              # Show cache statistics
  |   |-- update             # Force cache refresh
  |
  |-- config                 # Configuration management
  |   |-- set <key> <value>  # Set config value
  |   |-- get <key>          # Get config value
  |   |-- init               # Interactive config setup
  |   |-- show               # Show current configuration
  |
  |-- completion             # Shell completion (bash, zsh, fish, powershell)
  |-- version                # Version info
```

### 3.2 Global Flags

```
--output, -o        Output format: table (default), json, csv, markdown, yaml
--no-color          Disable colored output
--verbose, -v       Verbose output (show API calls, timing)
--quiet, -q         Suppress non-essential output
--config            Path to config file
--cache-dir         Path to cache directory
--no-cache          Bypass cache for this request
--api-key           NVD API key (overrides config/env)
--timeout           HTTP request timeout (default: 30s)
```

### 3.3 Example Usage

```bash
# Quick CVE lookup with full enrichment
$ cve-cli cve get CVE-2024-3094
CVE-2024-3094 | xz Utils Backdoor
  Severity:    CRITICAL (CVSS 10.0)
  EPSS:        0.9547 (97th percentile)
  KEV:         Yes (added 2024-03-29, due 2024-04-19)
  Ransomware:  Unknown
  Status:      Analyzed
  Published:   2024-03-29
  CWE:         CWE-506 (Embedded Malicious Code)
  Description: Malicious code was discovered in xz Utils...
  References:  5 links (use --verbose to see all)

# Search with filters
$ cve-cli cve search "apache log4j" --severity critical --has-kev --output json

# Multi-CVE EPSS check
$ cve-cli epss score CVE-2024-3094 CVE-2023-44228 CVE-2021-44228

# Enrich: pull from all sources
$ cve-cli enrich CVE-2024-3094 --output json | jq '.epss.score'

# Find advisories affecting a package
$ cve-cli advisory affected lodash --ecosystem npm

# Pipeline-friendly
$ cat cve-list.txt | cve-cli epss score --stdin --output csv > scores.csv

# KEV recent additions
$ cve-cli kev recent --days 7 --output table
```

### 3.4 Output Formats

| Format | Flag | Use Case |
|---|---|---|
| Table | `--output table` | Human-readable terminal display (default) |
| JSON | `--output json` | Machine parsing, jq pipelines |
| CSV | `--output csv` | Spreadsheet import, data analysis |
| Markdown | `--output markdown` | Documentation, reports |
| YAML | `--output yaml` | Configuration integration |
| Template | `--output template --template '...'` | Custom Go templates for advanced users |

### 3.5 Stdin Support

All commands that accept CVE IDs should also accept `--stdin` to read from standard input, one CVE per line. This enables pipeline composition:

```bash
grype my-image:latest -o json | jq -r '.matches[].vulnerability.id' | cve-cli epss score --stdin
```

---

## 4. Architecture Patterns

### 4.1 Project Structure

```
cve-cli/
  cmd/
    root.go              # Root command, global flags, Viper config binding
    cve.go               # cve subcommand group
    cve_get.go           # cve get implementation
    cve_search.go        # cve search implementation
    cve_list.go          # cve list implementation
    kev.go               # kev subcommand group
    kev_list.go          # kev list
    kev_check.go         # kev check
    epss.go              # epss subcommand group
    epss_score.go        # epss score
    advisory.go          # advisory subcommand group
    enrich.go            # enrich command
    cache.go             # cache management
    config.go            # config management
  internal/
    api/
      nvd/
        client.go        # NVD API client
        types.go         # NVD response types
      kev/
        client.go        # KEV feed client
        types.go         # KEV types
      epss/
        client.go        # EPSS API client
        types.go         # EPSS types
      ghsa/
        client.go        # GitHub Advisory client
        types.go         # GHSA types
      osv/
        client.go        # OSV.dev client
        types.go         # OSV types
    cache/
      cache.go           # Cache interface
      sqlite.go          # SQLite cache implementation
      migrations.go      # Schema migrations
    enricher/
      enricher.go        # Multi-source data aggregation
    model/
      cve.go             # Core CVE model
      cvss.go            # CVSS score models
      kev.go             # KEV entry model
      epss.go            # EPSS score model
      advisory.go        # Advisory model
    output/
      formatter.go       # Output format interface
      table.go           # Table formatter
      json.go            # JSON formatter
      csv.go             # CSV formatter
      markdown.go        # Markdown formatter
      template.go        # Go template formatter
    config/
      config.go          # Configuration management
    ratelimit/
      limiter.go         # Per-host rate limiter
  main.go                # Entry point
  go.mod
  go.sum
```

### 4.2 Caching Strategy

**Storage:** SQLite via `modernc.org/sqlite` (pure Go, no CGO).

**Location:** `$XDG_CACHE_HOME/cve-cli/cache.db` (defaults to `~/.cache/cve-cli/cache.db` on Linux, `~/Library/Caches/cve-cli/cache.db` on macOS).

**Schema:**

```sql
CREATE TABLE cve_cache (
    cve_id      TEXT PRIMARY KEY,
    data        BLOB NOT NULL,         -- gzip-compressed JSON
    source      TEXT NOT NULL,          -- 'nvd', 'mitre', etc.
    fetched_at  INTEGER NOT NULL,       -- Unix timestamp
    expires_at  INTEGER NOT NULL        -- Unix timestamp
);

CREATE TABLE kev_cache (
    id              INTEGER PRIMARY KEY,
    catalog_version TEXT NOT NULL,
    data            BLOB NOT NULL,      -- full KEV JSON, gzipped
    fetched_at      INTEGER NOT NULL,
    etag            TEXT                -- HTTP ETag for conditional requests
);

CREATE TABLE epss_cache (
    cve_id      TEXT PRIMARY KEY,
    epss        REAL NOT NULL,
    percentile  REAL NOT NULL,
    date        TEXT NOT NULL,          -- EPSS model date
    fetched_at  INTEGER NOT NULL
);

CREATE TABLE cache_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

**TTL policy:**

| Data type | Default TTL | Rationale |
|---|---|---|
| CVE detail | 2 hours | NVD recommends polling no more than every 2 hours |
| KEV catalog | 6 hours | Updated several times per week |
| EPSS scores | 24 hours | Updated daily |
| Advisory data | 4 hours | Moderate update frequency |

**Cache behavior:**

1. **Cache hit (not expired):** Return cached data, no network request.
2. **Cache hit (expired):** Make conditional request (ETag/If-Modified-Since). If 304, refresh TTL. If 200, update cache.
3. **Cache miss:** Fetch from API, store in cache.
4. **`--no-cache` flag:** Bypass cache entirely, always fetch fresh data.
5. **Offline mode (`--offline`):** Only return cached data, error if cache miss.

### 4.3 Rate Limiting

Implement a per-host token bucket rate limiter:

```go
type RateLimiter struct {
    limiters map[string]*rate.Limiter  // host -> limiter
    mu       sync.RWMutex
}

// Default limits per host
var defaultLimits = map[string]rate.Limit{
    "services.nvd.nist.gov": rate.Every(600 * time.Millisecond),  // ~1.6/sec with key
    "api.first.org":         rate.Every(1 * time.Second),          // 1/sec conservative
    "api.github.com":        rate.Every(720 * time.Millisecond),   // ~5000/hr with token
    "api.osv.dev":           rate.Every(500 * time.Millisecond),   // 2/sec conservative
}
```

### 4.4 Configuration Management

**Config file location:** `$XDG_CONFIG_HOME/cve-cli/config.yaml` (defaults to `~/.config/cve-cli/config.yaml`).

**Config file format:**

```yaml
# API keys
api_keys:
  nvd: "your-nvd-api-key"
  github: "ghp_your-github-token"
  vulncheck: "your-vulncheck-key"

# Default output format
output:
  format: table        # table, json, csv, markdown, yaml
  color: auto          # auto, always, never
  pager: auto          # auto, always, never (pipes to $PAGER)

# Cache settings
cache:
  enabled: true
  directory: ""        # empty = XDG default
  ttl:
    cve: 2h
    kev: 6h
    epss: 24h
    advisory: 4h

# Rate limits (requests per second)
rate_limits:
  nvd: 1.6
  epss: 1.0
  github: 1.4

# Default filters
defaults:
  severity: ""         # empty = all
  no_rejected: true
  results_per_page: 20
```

**Environment variable overrides (Viper convention):**

```
CVE_CLI_API_KEYS_NVD=your-key
CVE_CLI_API_KEYS_GITHUB=ghp_token
CVE_CLI_OUTPUT_FORMAT=json
CVE_CLI_CACHE_ENABLED=false
```

### 4.5 Error Handling Strategy

```
- API errors:     Retry with exponential backoff (max 3 retries), then fallback to cache if available
- Rate limiting:  Automatic wait via token bucket; 429 responses trigger backoff
- Network errors: Graceful degradation; show partial data from cache with warning
- Invalid input:  Validate CVE ID format (CVE-YYYY-NNNNN+), provide clear error messages
- No results:     Distinguish between "CVE not found" and "API error" for user clarity
```

---

## 5. Data Model

### 5.1 Core Entities

```go
// EnrichedCVE is the unified model that aggregates data from all sources.
type EnrichedCVE struct {
    // Core identity
    ID            string        `json:"id"`             // CVE-YYYY-NNNNN
    SourceID      string        `json:"source_id"`      // CNA source identifier
    Status        string        `json:"status"`         // Analyzed, Modified, Rejected, etc.

    // Dates
    Published     time.Time     `json:"published"`
    LastModified  time.Time     `json:"last_modified"`

    // Description
    Descriptions  []LangString  `json:"descriptions"`

    // Scoring
    CVSS          []CVSSScore   `json:"cvss"`
    EPSS          *EPSSScore    `json:"epss,omitempty"`

    // Classification
    CWEs          []CWEEntry    `json:"cwes"`
    Tags          []string      `json:"tags"`          // disputed, unsupported, etc.

    // Affected products
    CPEs          []CPEMatch    `json:"cpes"`
    AffectedPkgs  []AffectedPkg `json:"affected_packages,omitempty"` // from OSV/GHSA

    // Exploitation status
    KEV           *KEVEntry     `json:"kev,omitempty"`

    // References
    References    []Reference   `json:"references"`
    Advisories    []Advisory    `json:"advisories,omitempty"` // GHSA, OSV, etc.

    // Metadata
    DataSources   []string      `json:"data_sources"`   // which APIs contributed
    FetchedAt     time.Time     `json:"fetched_at"`
}

type CVSSScore struct {
    Version      string  `json:"version"`       // "2.0", "3.1", "4.0"
    VectorString string  `json:"vector_string"`
    BaseScore    float64 `json:"base_score"`
    Severity     string  `json:"severity"`      // LOW, MEDIUM, HIGH, CRITICAL
    Source       string  `json:"source"`        // NVD, CNA, etc.
}

type EPSSScore struct {
    Score      float64 `json:"score"`       // 0.0 - 1.0
    Percentile float64 `json:"percentile"`  // 0.0 - 1.0
    Date       string  `json:"date"`        // model date
}

type KEVEntry struct {
    DateAdded              string `json:"date_added"`
    DueDate                string `json:"due_date"`
    RequiredAction         string `json:"required_action"`
    KnownRansomwareCampaign string `json:"known_ransomware_campaign"`
    VendorProject          string `json:"vendor_project"`
    Product                string `json:"product"`
    VulnerabilityName      string `json:"vulnerability_name"`
    ShortDescription       string `json:"short_description"`
}

type CWEEntry struct {
    ID          string `json:"id"`           // CWE-79
    Description string `json:"description"`  // Improper Neutralization of Input...
    Source      string `json:"source"`
}

type CPEMatch struct {
    CPE23URI    string `json:"cpe23_uri"`
    Vulnerable  bool   `json:"vulnerable"`
    VersionStart string `json:"version_start,omitempty"`
    VersionEnd   string `json:"version_end,omitempty"`
}

type AffectedPkg struct {
    Ecosystem string   `json:"ecosystem"`    // npm, pip, maven, go, etc.
    Name      string   `json:"name"`
    Versions  []string `json:"versions,omitempty"`     // specific affected versions
    Ranges    []Range  `json:"ranges,omitempty"`       // version ranges
    Fixed     string   `json:"fixed,omitempty"`        // first fixed version
}

type Range struct {
    Type       string `json:"type"`        // SEMVER, ECOSYSTEM, GIT
    Introduced string `json:"introduced"`
    Fixed      string `json:"fixed,omitempty"`
}

type Reference struct {
    URL    string   `json:"url"`
    Source string   `json:"source"`
    Tags   []string `json:"tags,omitempty"` // Exploit, Patch, Vendor Advisory, etc.
}

type Advisory struct {
    ID        string `json:"id"`         // GHSA-xxxx-xxxx-xxxx or OSV ID
    Source    string `json:"source"`     // ghsa, osv
    URL       string `json:"url"`
    Severity  string `json:"severity"`
    Summary   string `json:"summary"`
}

type LangString struct {
    Lang  string `json:"lang"`
    Value string `json:"value"`
}
```

### 5.2 Entity Relationships

```
EnrichedCVE
  |-- 1:N --> CVSSScore       (v2, v3.1, v4.0 from different sources)
  |-- 1:1 --> EPSSScore       (single current score)
  |-- 1:1 --> KEVEntry        (optional: only if in KEV catalog)
  |-- 1:N --> CWEEntry        (multiple weaknesses possible)
  |-- 1:N --> CPEMatch        (affected product configurations)
  |-- 1:N --> AffectedPkg     (open-source package mappings from OSV/GHSA)
  |-- 1:N --> Reference       (links to patches, exploits, advisories)
  |-- 1:N --> Advisory        (GHSA, OSV advisory records)
```

---

## 6. Distribution

### 6.1 Binary Distribution

| Channel | Implementation |
|---|---|
| GitHub Releases | GoReleaser with cross-compiled binaries for linux/{amd64,arm64}, darwin/{amd64,arm64}, windows/{amd64,arm64} |
| Homebrew | Tap formula in `cve-cli/homebrew-tap` repository, auto-updated by GoReleaser |
| Docker | Multi-arch image (`gcr.io/distroless/static` base), published to GHCR |
| Nix | Nix package in nixpkgs or flake in repository |
| AUR | Arch Linux AUR package |
| go install | `go install github.com/<org>/cve-cli@latest` |

### 6.2 GoReleaser Configuration (Key Parts)

```yaml
builds:
  - main: ./main.go
    binary: cve-cli
    env:
      - CGO_ENABLED=0
    goos:
      - linux
      - darwin
      - windows
    goarch:
      - amd64
      - arm64
    ldflags:
      - -s -w
      - -X main.version={{.Version}}
      - -X main.commit={{.Commit}}
      - -X main.date={{.Date}}

brews:
  - repository:
      owner: <org>
      name: homebrew-tap
    homepage: "https://github.com/<org>/cve-cli"
    description: "CLI tool for exploring CVE, NVD, KEV, and EPSS vulnerability data"
    install: bin.install "cve-cli"

dockers:
  - image_templates:
      - "ghcr.io/<org>/cve-cli:{{ .Tag }}"
      - "ghcr.io/<org>/cve-cli:latest"
    dockerfile: Dockerfile
    build_flag_templates:
      - "--platform=linux/amd64,linux/arm64"
```

### 6.3 Dockerfile

```dockerfile
FROM gcr.io/distroless/static:nonroot
COPY cve-cli /usr/local/bin/cve-cli
ENTRYPOINT ["cve-cli"]
```

---

## 7. Performance

### 7.1 Concurrent API Fetching

The `enrich` command demonstrates the concurrent fetching pattern:

```go
func Enrich(ctx context.Context, cveID string) (*EnrichedCVE, error) {
    g, ctx := errgroup.WithContext(ctx)
    result := &EnrichedCVE{ID: cveID}

    var nvdData *nvd.CVEResponse
    var epssData *epss.Score
    var kevData *kev.Entry
    var ghsaData []*ghsa.Advisory
    var osvData []*osv.Vulnerability

    g.Go(func() error {
        var err error
        nvdData, err = nvdClient.GetCVE(ctx, cveID)
        return err
    })

    g.Go(func() error {
        var err error
        epssData, err = epssClient.GetScore(ctx, cveID)
        return err
    })

    g.Go(func() error {
        var err error
        kevData, err = kevClient.Check(ctx, cveID)
        return err  // nil if not in KEV
    })

    g.Go(func() error {
        var err error
        ghsaData, err = ghsaClient.FindByCVE(ctx, cveID)
        return err
    })

    g.Go(func() error {
        var err error
        osvData, err = osvClient.QueryByCVE(ctx, cveID)
        return err
    })

    if err := g.Wait(); err != nil {
        // Partial failure: log warning, return what we have
        slog.Warn("partial enrichment failure", "cve", cveID, "error", err)
    }

    // Merge results into EnrichedCVE
    result.merge(nvdData, epssData, kevData, ghsaData, osvData)
    return result, nil
}
```

All five API calls execute concurrently via `errgroup`. With cache hits, `enrich` completes in under 50ms. With full API calls, it completes in the time of the slowest API (typically NVD at 200-500ms).

### 7.2 Batch Operations

For commands accepting multiple CVE IDs:

```go
func EnrichBatch(ctx context.Context, cveIDs []string) ([]*EnrichedCVE, error) {
    sem := make(chan struct{}, 10) // concurrency limit
    g, ctx := errgroup.WithContext(ctx)
    results := make([]*EnrichedCVE, len(cveIDs))

    for i, id := range cveIDs {
        i, id := i, id
        g.Go(func() error {
            sem <- struct{}{}
            defer func() { <-sem }()

            enriched, err := Enrich(ctx, id)
            if err != nil {
                return err
            }
            results[i] = enriched
            return nil
        })
    }

    if err := g.Wait(); err != nil {
        return results, err // return partial results
    }
    return results, nil
}
```

### 7.3 Streaming Output

For large result sets (e.g., `cve list` or `kev list`), stream results as they arrive rather than buffering everything in memory:

```go
// Stream results as they are fetched, page by page
func streamResults(ctx context.Context, w io.Writer, formatter output.Formatter) error {
    startIndex := 0
    for {
        page, total, err := nvdClient.ListCVEs(ctx, startIndex, pageSize, filters)
        if err != nil {
            return err
        }
        for _, cve := range page {
            if err := formatter.WriteRow(w, cve); err != nil {
                return err
            }
        }
        startIndex += len(page)
        if startIndex >= total {
            break
        }
    }
    return formatter.Flush(w)
}
```

### 7.4 Performance Targets

| Operation | Target (cache hit) | Target (API call) |
|---|---|---|
| Single CVE lookup | < 50ms | < 1s |
| Enriched CVE (all sources) | < 100ms | < 2s |
| Batch 10 CVEs | < 200ms | < 3s |
| KEV list (full) | < 100ms | < 2s |
| Search (keyword) | < 50ms (if cached) | < 2s |
| CLI startup (no command) | < 50ms | N/A |

### 7.5 Binary Size Target

With `CGO_ENABLED=0` and `-ldflags "-s -w"`, target binary size is **10-15 MB**. Further reduction possible with UPX compression if needed (not recommended due to AV false positives).

---

## 8. Summary of Key Architectural Decisions

| Decision | Choice | Key Rationale |
|---|---|---|
| Language | Go | Single binary, cross-compilation, goroutines, ecosystem precedent |
| CLI framework | Cobra + Viper | Industry standard, auto-completion, config integration |
| HTTP client | go-retryablehttp | Built-in retry/backoff for flaky APIs (NVD) |
| Cache storage | SQLite (modernc.org/sqlite) | Pure Go, no CGO, structured queries, single file |
| Primary data source | NVD API 2.0 | Most comprehensive CVE data with CVSS enrichment |
| Output formatting | Pluggable formatters | table/json/csv/markdown/yaml/template via interface |
| Distribution | GoReleaser | Handles cross-compilation, Homebrew, Docker, checksums |
| Concurrency | errgroup + semaphore | Parallel API fetching with bounded concurrency |
| Rate limiting | Per-host token bucket | Respect API limits, configurable per provider |
| Config location | XDG Base Directory | Cross-platform standard, respects user preferences |
