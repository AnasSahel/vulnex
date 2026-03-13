---
name: VulneX SaaS App Scaffold
description: Bootstrap the monetization SaaS web application in app/ using Next.js, Tailwind CSS, and Shadcn UI.
date: 2026-03-12
status: completed
---

# VulneX SaaS App Scaffold

## Description

VulneX is currently a free, open-source CLI tool. To monetize the project, we need a SaaS web application that will serve as the commercial layer — offering hosted dashboards, team features, and premium capabilities beyond the CLI.

This feature bootstraps the SaaS application in a new `app/` directory at the project root.

### Current problems

1. No monetization path exists for vulnex — the CLI is fully open source with no commercial offering.
2. There is no web application to deliver hosted features, team management, or premium integrations.

### Target design

A clean Next.js application scaffolded in `app/` with:
- **Next.js 15** (App Router) as the framework
- **Tailwind CSS v4** for styling
- **Shadcn UI** as the component library
- Pages will be added incrementally as specified by the user

The app should be production-ready in structure from day one — proper project organization, linting, and configuration.

## User Stories

1. As the project owner, I want a SaaS web application scaffold so that I can incrementally build monetization features.
2. As a developer, I want the app to use Next.js + Tailwind + Shadcn so that I can build UI quickly with a modern, consistent stack.

## Acceptance Criteria

- [x] `app/` directory exists at the project root with a working Next.js application
- [x] Tailwind CSS is configured and functional
- [x] Shadcn UI is initialized and at least one component can be imported
- [x] `npm run dev` starts the development server without errors
- [x] `npm run build` completes without errors
- [x] The app uses the Next.js App Router (not Pages Router)
- [x] A minimal landing/home page renders successfully

## Priority

**High** — This is the foundation for all monetization work. Nothing else can be built until the scaffold exists.

## Dependencies

None — this is a greenfield addition to the repo.

## Implementation Notes

- Create the app using `npx create-next-app@latest app` with TypeScript, Tailwind CSS, App Router, and src/ directory options
- Initialize Shadcn UI with `npx shadcn@latest init` inside `app/`
- Keep the app self-contained in `app/` — it should not interfere with the existing Go CLI or the `website/` Astro site
- Add `app/` to the project structure documentation in AGENTS.md once complete

## Documentation Updates

- **AGENTS.md**: Add `app/` to the project structure section with a brief description
- **README.md**: No changes needed yet — the SaaS app is not public-facing at this stage
