# githubapptest

Intentionally vulnerable demo repository used to validate end-to-end CodeFence local (GitHub Action) scanning pipeline.

## Purpose

- Exercise local scanner execution in GitHub Actions
- Upload findings back to CodeFence backend
- Validate processor pipeline enrichment and reporting

## Structure

- `.github/workflows/codefence.yml` GitHub Action scanner workflow
- `package.json` minimal Node app manifest
- `src/server.js` intentionally insecure application code
- `.env.example` sample configuration with intentionally unsafe defaults

## Warning

This repository contains deliberately insecure code for security testing only.

CodeFence GitHub App integration test repository.

This repo contains intentionally vulnerable code samples for validating
the CodeFence security scanner across all 11 scanning tools.

**⚠️ Do NOT use any code from this repository in production.**
