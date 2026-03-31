---
name: vulnex push CLI Command
description: Go CLI command that authenticates with vulnex.cloud and pushes scan results (CVE list + metadata) to create or update a product.
date: 2026-03-13
status: in progress
---

# vulnex push CLI Command

## Description

Add a `vulnex push` command to the Go CLI that sends local scan results to vulnex.cloud. This is the primary flow for getting CLI data into the cloud dashboard.

### Target design

**CLI usage:**
```
vulnex push --name "my-app" --version "2.1.0"
vulnex push --name "my-app" --file lockfile.json
vulnex push --name "my-app" --sbom sbom.cdx.json
```

**Authentication:**
- `vulnex auth login` opens browser for OAuth flow, stores API token locally
- Or: `VULNEX_API_KEY=...` environment variable (for CI/CD)
- Token stored in `~/.config/vulnex/credentials.json`

**Push flow:**
1. CLI reads the local scan cache (or runs a scan if --file provided)
2. Sends POST to `https://vulnex.cloud/api/push` with:
   - Product name + version
   - List of CVE IDs with scores
   - Optional SBOM file content
3. Cloud API creates/updates the product and links CVEs
4. CLI prints: "Pushed 47 CVEs to product 'my-app' v2.1.0"

**API route:**
- `POST /api/push` — receives push payload, requires auth token
- Creates product if it doesn't exist (matched by name + userId)
- Upserts CVEs into `product_cve`
- Optionally stores SBOM in `product_sbom`

### CRA alignment

`vulnex push` enables automated, CI/CD-integrated vulnerability tracking — a CRA requirement for continuous monitoring during a product's support period.

## User Stories

1. As a developer, I want to push scan results from my terminal to the cloud dashboard.
2. As a CI/CD pipeline, I want to automatically push vulnerability data on each build.

## Acceptance Criteria

- [ ] `vulnex push --name <name>` sends CVE data to the cloud
- [ ] `vulnex auth login` authenticates and stores credentials
- [ ] API token authentication via env var for CI/CD
- [x] Cloud API creates product if it doesn't exist (POST /api/push)
- [x] CVEs are linked to the product
- [x] Optional SBOM upload via `--sbom` flag (server-side)
- [ ] CLI prints confirmation with CVE count
- [ ] Works with `VULNEX_API_KEY` env var (no interactive login needed)

## Priority

**Medium** — Important for the CLI-Cloud bridge but the dashboard is usable without it via manual flows.

## Dependencies

- Rename project → product
- Add CVEs to product (API route reused)
- Product SBOM upload (API route reused)
- Auth system must support API keys

## Implementation Notes

- Go: new `cmd/push.go` command using Cobra
- Auth: new `cmd/auth.go` with `login` subcommand
- API client: `internal/api/cloud/client.go` for HTTP calls to vulnex.cloud
- The push API endpoint should be idempotent — same push twice doesn't duplicate
- Consider `vulnex push --dry-run` to preview what would be sent
- The API key can be generated from the Settings page in the dashboard

## Documentation Updates

- Add `vulnex push` to README.md command list
- Create docs page for CLI-Cloud integration
