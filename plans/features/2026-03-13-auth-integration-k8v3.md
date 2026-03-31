---
name: Authentication Integration
description: Wire up better-auth with Drizzle ORM and PostgreSQL for real login/signup/session management.
date: 2026-03-13
status: completed
---

# Authentication Integration

## Description

The app has UI-only login/signup pages with no backend. This feature wires up real authentication using better-auth, Drizzle ORM, and the existing Neon PostgreSQL database.

### Current problems

1. Login and signup forms submit to nowhere — `type="button"` with no handler.
2. No session management — `/dashboard` is accessible without authentication.
3. No database schema or ORM — the `DATABASE_URL` in `.env.local` is unused.
4. `/` redirects to `/dashboard` unconditionally instead of checking auth state.

### Target design

**Database layer (Drizzle ORM):**
- Drizzle ORM configured with `drizzle-kit` for migrations
- PostgreSQL via `@neondatabase/serverless` driver (Neon's serverless adapter)
- Schema file at `src/lib/db/schema.ts` with better-auth's required tables
- `drizzle.config.ts` at app root

**Auth layer (better-auth):**
- Server-side auth instance at `src/lib/auth.ts` using Drizzle adapter
- Client-side auth hooks at `src/lib/auth-client.ts`
- API route at `src/app/api/auth/[...all]/route.ts` handling all auth endpoints
- `BETTER_AUTH_SECRET` env var for signing (generate with `openssl rand -base64 32`)
- `BETTER_AUTH_URL` env var set to `http://localhost:3000` (dev)

**Auth flow:**
- Login page: email/password sign-in via `authClient.signIn.email()`
- Signup page: email/password sign-up via `authClient.signUp.email()`
- On success: redirect to `/dashboard`
- On error: show inline error message below the form
- Sign out: `authClient.signOut()` from sidebar user dropdown

**Route protection:**
- Middleware at `src/middleware.ts` checking session for `/dashboard/*` routes
- Unauthenticated users redirected to `/login`
- `/` redirects to `/dashboard` if authenticated, `/login` if not
- `/login` and `/signup` redirect to `/dashboard` if already authenticated

**Sidebar user info:**
- Sidebar footer shows the authenticated user's name and email (from session)
- "Sign out" in dropdown actually signs out

## User Stories

1. As a visitor, I want to create an account so I can access the dashboard.
2. As a user, I want to sign in with my credentials so I can see my data.
3. As a user, I want the dashboard protected so only I can access it.
4. As a user, I want to sign out from the sidebar dropdown.

## Acceptance Criteria

- [x] `better-auth`, `drizzle-orm`, `drizzle-kit`, and `@neondatabase/serverless` are installed
- [x] Drizzle schema exists with better-auth required tables (user, session, account, verification)
- [x] `bun run db:push` applies the schema to the Neon database without errors
- [x] Signup form creates a real user in the database
- [x] Login form authenticates against the database and creates a session
- [x] Invalid credentials show an error message on the login form
- [x] Duplicate email on signup shows an error message
- [x] Authenticated users are redirected from `/login` and `/signup` to `/dashboard`
- [x] Unauthenticated users are redirected from `/dashboard` to `/login`
- [x] `/` redirects based on auth state
- [x] Sidebar footer displays authenticated user's name and email
- [x] "Sign out" in sidebar dropdown ends the session and redirects to `/login`
- [x] `BETTER_AUTH_SECRET` is documented in `.env.local` (not committed)
- [x] `bun run build` completes without errors

## Priority

**High** — Authentication is the foundation for all user-facing features.

## Dependencies

- `2026-03-13-shadcn-refactor-p4r7` (completed) — clean component structure
- `2026-03-13-theme-toggle-w5k8` (completed) — theme system stable

## Implementation Notes

- Install: `bun add better-auth drizzle-orm @neondatabase/serverless` and `bun add -d drizzle-kit`
- Add scripts to `package.json`: `"db:push": "drizzle-kit push"`, `"db:studio": "drizzle-kit studio"`
- Create `drizzle.config.ts` using `DATABASE_URL` from env
- Create `src/lib/db/index.ts` — Drizzle client instance with Neon serverless driver
- Create `src/lib/db/schema.ts` — export better-auth tables via `drizzle-orm/pg-core`
- Create `src/lib/auth.ts` — better-auth server instance with Drizzle adapter
- Create `src/lib/auth-client.ts` — `createAuthClient()` for client components
- Create `src/app/api/auth/[...all]/route.ts` — catch-all route handler
- Convert login/signup pages to client components with form state and error handling
- Update `src/components/app-sidebar.tsx` to use session data for user info
- Add `src/middleware.ts` for route protection
- Add `BETTER_AUTH_SECRET` and `BETTER_AUTH_URL` to `.env.local`
- The `.env.local` file is already gitignored

## Documentation Updates

No changes needed — internal feature, app not public yet.
