# AGENTS.md — Rules for AI Agents

## Commit Conventions

This project uses **Conventional Commits** (enforced by release-please):

```
<type>[optional scope][!]: <description>

[optional body]

[optional footer(s)]
```

Allowed types: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `ci`, `chore`

Breaking changes: use `!` suffix (e.g. `feat!: remove flag`) or a `BREAKING CHANGE:` footer.

## Things You Must NOT Do

- **Do NOT** manually create git tags — release-please owns version tags
- **Do NOT** manually edit `CHANGELOG.md` — release-please generates it from commits
- **Do NOT** commit the `vulnex` binary

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

## CI/CD Pipeline

1. **CI** (`ci.yml`) — runs on push/PR to `main`: tests, vet, build, Discord notification on failure
2. **Release Please** (`release-please.yml`) — runs on push to `main`: creates/updates a Release PR with version bump + changelog; on merge, creates git tag + GitHub Release
3. **Release** (`release.yml`) — triggered by `v*` tags: GoReleaser builds binaries, attaches to existing GitHub Release, updates Homebrew tap

## Discord Webhook Setup

1. In your Discord server, go to **Channel Settings → Integrations → Webhooks**
2. Create a new webhook, copy the URL
3. In the GitHub repo, go to **Settings → Secrets and variables → Actions**
4. Add a new secret: `DISCORD_WEBHOOK` with the webhook URL

## Code Style

- Standard Go conventions (`gofmt`, `go vet`)
- Error messages start lowercase, no trailing punctuation
- API clients go in `internal/api/<source>/`
- Output formatters go in `internal/output/`
- Use `context.Context` for cancellation and timeouts
