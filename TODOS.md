# TODOS

## cra report — deferred work

### Token scope: separate GHSA token from repo token
**What:** The config currently stores one GitHub token (`api_keys.github`) shared between GHSA advisory lookups and the new repo-level REST calls. Branch protection requires `repo` scope; GHSA reads only need `security_events` or public access. A fine-grained GHSA-only token will fail silently on `GET /branches/{branch}/protection`.
**Why:** Users who follow least-privilege token practices will configure narrow tokens. Silent 403 on branch protection is confusing.
**Pros:** Better security hygiene, clearer error messages.
**Cons:** Breaking change to config schema (adds `api_keys.github_repo`).
**Context:** For v1, the 403 on branch protection already prints a hint. Full token separation is a config migration. Start by adding `api_keys.github_repo` as an optional override; fall back to `api_keys.github`.
**Depends on:** Nothing.

### PDF output for cra report
**What:** `vulnex cra report --format pdf` — render the evidence pack as PDF.
**Why:** Auditors and lawyers often require PDF format for compliance documentation.
**Pros:** More useful as a formal compliance artifact.
**Cons:** Requires a PDF rendering dependency (chromedp, wkhtmltopdf, or a Go PDF lib). Breaks zero-CGO build guarantee unless a pure-Go PDF library is used.
**Context:** HTML is v1. PDF is Approach B scope. Evaluate go-pdf or go-wkhtmltopdf once there's buyer demand for it.
**Depends on:** Buyer feedback from CRA Readiness Assessment engagements.

### GitLab and Bitbucket support for cra report
**What:** Support `--repo` pointing to GitLab or Bitbucket repos.
**Why:** Not all EU B2B SaaS teams use GitHub.
**Pros:** Broader market coverage.
**Cons:** Three separate API clients with different auth and branch protection models.
**Context:** GitHub-only for v1 (explicit scope decision). Add GitLab first if buyers request it.
**Depends on:** Buyer feedback.

### SBOM auto-generation
**What:** Auto-generate the SBOM from lockfiles in the repo rather than requiring `--sbom <file>`.
**Why:** Reduces friction — one fewer file for the user to provide.
**Cons:** Lockfiles ≠ complete SBOM in all ecosystems. Adds GitHub API calls to fetch the file tree.
**Context:** Optional --sbom flag covers v1. Auto-detect is a quality-of-life improvement once the basic flow is validated.
**Depends on:** User feedback on friction.
