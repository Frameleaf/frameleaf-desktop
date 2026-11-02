# Desktop Release Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline.

**Goal:** Restore three-platform checks and stage verified signed installers in GitHub.
**Architecture:** Reuse factory runtime verification, separate read-only build jobs from draft release writes, and keep platform credentials in a main-only environment.
**Tech Stack:** GitHub Actions, Tauri 2, Node 22, platform signing tools.
**Spec:** ../specs/2026-11-01-desktop-release-design.md

## Global Constraints

Current main only; preserve CodeRabbit; no public release or unsigned fallback.
The Ed25519 authoring key stays in Infisical; runtime factory uploads and installed
qualification remain separate prerequisites. No known target version is assigned.

## Review Focus

Version/tag drift, malicious artifact paths, wrong runtime authority/OS, missing
signing credentials, and partial target failure must all prevent release staging.

## Implementation

- [x] Restore existing workflows and dispatch main's three-platform candidate.
- [x] Add release version/matrix tests, observe missing implementation failure, then implement validation.
- [x] Add workflow with exact-main tag check, safe archive extraction, existing runtime verification, OS signing and verification, cleanup, checksums and draft-only staging.
- [x] Document credential/artifact prerequisites, platform limits and manual dispatch.
- [x] Reproduce Windows CRLF failures and enforce LF while retaining binary fixture exceptions.
- [x] Run workflow lint, Node checks and relevant tests; obtain independent review.
- [ ] Open a ready-for-review PR with FD-2 in its title and report live CI separately from signing readiness.

Developer ID Application certificate JZTDNMWT8T is issued, backed up in Infisical
and provisioned to the main-only GitHub environment. App-specific notarization
password and Windows signing remain pending. Do not commit key material.
