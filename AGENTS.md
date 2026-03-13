# AGENTS.md — Rules for AI Agents

## Project
- **Repo**: `github.com/AnasSahel/vulnex` (Go 1.24)
- **Description**: Multi-source vulnerability intelligence CLI
- **Current version**: v1.0.0
- **Homebrew tap**: `AnasSahel/homebrew-tap`

## GitHub Secrets
- `DISCORD_WEBHOOK` — Discord channel webhook
- `HOMEBREW_TAP_TOKEN` — Fine-grained PAT scoped to `AnasSahel/homebrew-tap` (Contents: R/W)

## Key Rules
- Owner is `AnasSahel` (personal account), NOT `trustin-tech` (org not owned)
- Conventional commits enforced (release-please depends on them)
- Do NOT manually create tags or edit CHANGELOG.md — release-please owns both
- Do NOT commit the `vulnex` binary

## Commit Conventions

This project uses **Conventional Commits** (enforced by release-please):

```
<type>[optional scope][!]: <description>

[optional body]

[optional footer(s)]
```

Allowed types: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `ci`, `chore`

Breaking changes: use `!` suffix (e.g. `feat!: remove flag`) or a `BREAKING CHANGE:` footer.

## Project Structure

```
.
├── main.go                  # Entry point
├── cmd/                     # Cobra commands (root, search, db, etc.)
├── internal/
│   ├── api/                 # API clients, one sub-package per source
│   │   ├── nvd/
│   │   ├── osv/
│   │   ├── github/
│   │   └── epss/
│   ├── db/                  # Local SQLite cache
│   ├── models/              # Shared data types
│   └── output/              # Formatters (table, JSON, detail)
├── app/                     # SaaS web app (Next.js + Tailwind + Shadcn UI)
├── website/                 # Marketing & docs site (Astro)
├── .github/workflows/       # CI/CD pipelines
├── .goreleaser.yaml         # GoReleaser config
├── release-please-config.json
└── .release-please-manifest.json
```

## Dev Commands

```bash
make build     # Build the binary
make test      # Run tests
make lint      # Run linter (go vet)
go run .       # Run directly
```

## Code Style

- Standard Go conventions (`gofmt`, `go vet`)
- Error messages start lowercase, no trailing punctuation
- API clients go in `internal/api/<source>/`
- Output formatters go in `internal/output/`
- Use `context.Context` for cancellation and timeouts

## CI/CD Pipeline

```
Push to main → release-please scans commits → creates/updates Release PR
  ↓ (PR merged)
release-please creates tag + GitHub Release → GoReleaser job runs in same workflow
  ↓
Builds 6 binaries (linux/darwin/windows × amd64/arm64)
Attaches to existing GitHub Release (keep-existing mode)
Pushes Homebrew formula to AnasSahel/homebrew-tap (Formula/vulnex.rb)
```

### Workflows

| File | Trigger | Purpose |
|------|---------|---------|
| `ci.yml` | push/PR to main | Tests, vet, build, Discord on failure |
| `release-please.yml` | push to main | Version bump PR + GoReleaser (same workflow) |
| `release.yml` | workflow_dispatch (manual) | Fallback manual release with tag input |

### Important CI/CD Notes
- **GITHUB_TOKEN cannot trigger cross-workflow events** — GoReleaser runs as a dependent job inside `release-please.yml`, not a separate tag-triggered workflow
- **GITHUB_TOKEN is repo-scoped only** — `HOMEBREW_TAP_TOKEN` PAT is needed to push the formula to the homebrew-tap repo
- **GoReleaser needs tag checkout** — checkout uses `ref: ${{ needs.release-please.outputs.tag_name }}`
- **GoReleaser won't overwrite existing assets** — delete assets via `gh release delete-asset` before re-running
- **Homebrew formula directory** — `directory: Formula` in `.goreleaser.yaml` so Homebrew finds it

### Repo Settings Required
- **Actions → General → Workflow permissions**: Read and write
- **Allow GitHub Actions to create and approve pull requests**: Checked

## Discord Webhook Setup

1. In your Discord server, go to **Channel Settings → Integrations → Webhooks**
2. Create a new webhook, copy the URL
3. In the GitHub repo, go to **Settings → Secrets and variables → Actions**
4. Add a new secret: `DISCORD_WEBHOOK` with the webhook URL
