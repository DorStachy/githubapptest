#!/usr/bin/env bash
set -euo pipefail

SCANNER_NAME="ci-agent-guardrails"
# shellcheck disable=SC1091
source "$(cd "$(dirname "$0")" && pwd)/common.sh"

workspace="$(resolve_workspace "$@")"
output_file="$(result_json_path "ci-agent-guardrails")"

if [[ ! -d "${workspace}/.github/workflows" ]]; then
  log "No workflow directory found. Skipping ci-agent-guardrails."
  write_empty_json_array "${output_file}"
  exit 0
fi

# Resolve compiled scanner script (TypeScript compiles to dist/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPILED_SCANNER="${SCRIPT_DIR}/../../dist/scripts/scanners/ci-agent-guardrails.js"

if [[ ! -f "${COMPILED_SCANNER}" ]]; then
  # Fallback: try ts-node or npx tsx for development
  TS_SCANNER="${SCRIPT_DIR}/ci-agent-guardrails.ts"
  if [[ -f "${TS_SCANNER}" ]]; then
    if command -v npx >/dev/null 2>&1; then
      log "Running TypeScript scanner via npx tsx"
      npx --yes tsx "${TS_SCANNER}" "${workspace}" "${output_file}"
      exit $?
    fi
  fi
  warn "Compiled scanner not found at ${COMPILED_SCANNER}. Writing empty result."
  write_empty_json_array "${output_file}"
  exit 0
fi

node "${COMPILED_SCANNER}" "${workspace}" "${output_file}"
log "Wrote JSON to ${output_file}"
