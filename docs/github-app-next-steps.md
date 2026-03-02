# GitHub App — Next Steps

What's been built on `feat/github-app` and what remains before this is production-ready.

## What exists today

- **Library extraction**: `sbom.ParseBytes`, `sbom.MapEcosystemToOSV`, `sbom.CheckComponents` — reusable by both CLI and server.
- **Webhook server**: `vulnex serve` receives GitHub `pull_request` events, validates HMAC signatures, creates Check Runs, posts PR comments.
- **SBOM fetching**: Tries the GitHub Dependency Graph API first, falls back to well-known file names in the repo.
- **Reporting**: Check Run conclusions (`success`/`action_required`/`neutral`) and markdown PR comments with severity tables and collapsible findings.

---

## 1. Tests

No tests exist for the new code. This is the highest priority before merging.

### Unit tests

- **`internal/sbom/check_test.go`** — Test `CheckComponents` with a mock OSV client. Verify ecosystem/severity filtering, empty input, components without PURLs, and VulnDetails population. The `osv.Client` currently takes a concrete `*api.Client`; introduce an interface (`sbom.VulnQuerier` or similar) so tests can inject a stub without hitting the network.
- **`internal/sbom/ecosystem_test.go`** — Table-driven tests for every `MapEcosystemToOSV` case plus unknown input passthrough.
- **`internal/sbom/parser_test.go`** — `ParseBytes` with CycloneDX and SPDX fixtures (the existing `testdata/sbom.cdx.json` can be reused; add an SPDX fixture). Test invalid JSON, unknown format, and empty components.
- **`internal/githubapp/reporter_test.go`** — Test `FormatCheckRun` and `FormatPRComment` with zero findings, mixed severities, and content exceeding the 65K truncation limit.
- **`internal/githubapp/config_test.go`** — Test `LoadConfigFromEnv` with valid env, missing required vars, inline key vs. file key.
- **`internal/githubapp/server_test.go`** — Test `verifySignature` with valid/invalid/missing signatures. Use `httptest.NewServer` + `httptest.NewRecorder` for the `/health` and `/webhook` endpoints.

### Integration test

- **`internal/githubapp/handler_test.go`** — Spin up an `httptest.Server` that fakes the GitHub API (Check Runs, Contents, Issues). Send a real-shaped `pull_request` webhook payload through the handler. Assert the correct API calls were made (Check Run created → updated, comment posted). This validates the full flow without needing a real GitHub App.

---

## 2. Interface for OSV client

`sbom.CheckComponents` takes `*osv.Client` directly, making it impossible to test without a network. Extract an interface:

```go
// internal/sbom/check.go
type VulnQuerier interface {
    QueryByPackage(ctx context.Context, ecosystem, name, version string) ([]osv.OSVVulnerability, error)
}
```

`osv.Client` already satisfies this. `CheckComponents` takes `VulnQuerier` instead. Tests inject a stub.

---

## 3. Comment deduplication

The handler posts a new PR comment on every `synchronize` event (each push). This will spam PRs. Fix this:

1. Before posting, list existing comments on the PR (`gh.Issues.ListComments`).
2. Find one that starts with `## vulnex scan` and was authored by the app's bot user.
3. If found, update it (`gh.Issues.EditComment`) instead of creating a new one.

---

## 4. SBOM from the PR's head branch

`fetchRepoFile` currently fetches from the default branch (no `ref` parameter). The SBOM in the PR may differ. Pass `&github.RepositoryContentGetOptions{Ref: headSHA}` to `GetContents` so the scan reflects the PR's actual dependencies.

---

## 5. Concurrency control

`HandlePullRequest` runs in an unbounded goroutine per webhook. Under load (monorepo with many PRs), this could exhaust memory or hit GitHub API rate limits. Add:

- A semaphore (buffered channel or `golang.org/x/sync/semaphore`) to cap concurrent handler goroutines (e.g. 10).
- Per-installation rate limiting to stay within GitHub's 5000 req/hr per installation token.

---

## 6. GitHub App registration & permissions

Create the app at https://github.com/settings/apps/new:

| Setting | Value |
|---------|-------|
| Webhook URL | `https://<domain>/webhook` |
| Webhook secret | Random 40-char hex |
| Permissions | `checks: write`, `pull_requests: write`, `contents: read` |
| Events | `pull_request` |

The `contents: read` permission is needed for fetching SBOM files. `pull_requests: write` for posting comments. `checks: write` for creating Check Runs.

Store the generated private key PEM and app ID as deployment secrets.

---

## 7. Deployment

### Cloud Run (simplest)

```bash
# Build with CGO_ENABLED=0 (already compatible — all deps are pure Go)
CGO_ENABLED=0 GOOS=linux go build -o vulnex .

# Build container
docker build -t gcr.io/<project>/vulnex .

# Deploy
gcloud run deploy vulnex \
  --image gcr.io/<project>/vulnex \
  --set-env-vars VULNEX_APP_ID=...,VULNEX_APP_WEBHOOK_SECRET=... \
  --set-secrets VULNEX_APP_PRIVATE_KEY=vulnex-pk:latest \
  --allow-unauthenticated \
  --port 8080
```

### Fly.io alternative

```toml
# fly.toml
[env]
  VULNEX_APP_ID = "..."

[http_service]
  internal_port = 8080
```

```bash
fly secrets set VULNEX_APP_WEBHOOK_SECRET=... VULNEX_APP_PRIVATE_KEY="$(cat key.pem)"
fly deploy
```

### CI workflow

Add `.github/workflows/deploy.yml` that builds the container image and deploys on push to `main`. Only deploy when files under `internal/githubapp/`, `cmd/serve.go`, or `Dockerfile` change.

---

## 8. Structured logging & observability

The server uses `slog.Info`/`slog.Error` but has no request ID correlation. Add:

- A middleware that generates a request ID (from `X-GitHub-Delivery` header, which is already logged but not propagated to the handler goroutine).
- Pass the delivery ID into `HandlePullRequest` and attach it to the logger context so all log lines for a single webhook delivery can be correlated.
- Add a `/metrics` endpoint (or use OpenTelemetry) for Prometheus-style metrics: webhook count, processing duration, findings count, error rate.

---

## 9. Repo-level configuration

Allow repos to customize behavior via a `.vulnex.yml` file:

```yaml
# .vulnex.yml
severity_threshold: high    # only fail check run for HIGH+
ecosystem_filter: ""        # check all ecosystems
sbom_paths:                 # custom SBOM locations
  - dist/sbom.json
ignore:
  - GHSA-xxxx-xxxx-xxxx    # known accepted risk
```

Fetch this file from the PR head ref before running the check. Fall back to defaults if absent.

---

## 10. Security hardening

- **Webhook replay protection**: Check the `X-GitHub-Delivery` header for uniqueness (store recent delivery IDs in memory with TTL) to prevent replay attacks.
- **Private key in memory**: The PEM bytes are held in the `Handler` struct for the process lifetime. Consider using a secret manager reference instead of raw bytes in env vars for production deployments.
- **TLS**: The server currently listens on plain HTTP. In production, terminate TLS at the load balancer (Cloud Run / Fly do this automatically) or add a `--tls-cert`/`--tls-key` flag.

---

## 11. GitHub Marketplace listing

Prerequisites before listing:

1. The app must be publicly installable (not just for the owner's repos).
2. Add a landing page — the existing GitHub Pages site at `website/` could host an install button.
3. Write a Marketplace description covering: what it does, permissions it needs, pricing tiers.
4. Decide on pricing: free tier (public repos only), paid tier (private repos, higher limits).
5. Marketplace requires a terms of service URL and privacy policy URL.

---

## 12. Multi-SBOM support

Currently the handler picks the first SBOM it finds and stops. Repos may contain multiple SBOMs (e.g. frontend + backend). Extend `fetchSBOM` to return `[][]byte`, parse all of them, merge the components list, and deduplicate findings by advisory ID + component.

---

## 13. Batch OSV queries

`CheckComponents` queries OSV one component at a time. For large SBOMs (hundreds of components), this is slow. The OSV client already has `BatchQuery`. Refactor `CheckComponents` to batch components in groups of 100 using the batch endpoint, then fan out the results.

---

## Priority order

| Priority | Item | Effort |
|----------|------|--------|
| P0 | Tests (#1, #2) | 1 day |
| P0 | Comment deduplication (#3) | Small |
| P0 | Fetch SBOM from PR head (#4) | Small |
| P1 | Concurrency control (#5) | Small |
| P1 | App registration + first deployment (#6, #7) | Half day |
| P1 | Structured logging (#8) | Small |
| P2 | Repo config file (#9) | Medium |
| P2 | Security hardening (#10) | Small |
| P2 | Batch OSV queries (#13) | Medium |
| P3 | Multi-SBOM support (#12) | Medium |
| P3 | Marketplace listing (#11) | Documentation |
