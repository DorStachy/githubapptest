#!/usr/bin/env bash
set -euo pipefail

SCANNER_NAME="bandit"
# shellcheck disable=SC1091
source "$(cd "$(dirname "$0")" && pwd)/common.sh"

workspace="$(resolve_workspace "$@")"
output_file="$(result_json_path "bandit")"
bandit_version="${BANDIT_VERSION:-1.7.10}"

if ! find_any_file "${workspace}" "*.py"; then
  log "No Python files found. Skipping Bandit."
  exit 0
fi

if ! ensure_python_tool "bandit" "bandit" "${bandit_version}"; then
  warn "Bandit is unavailable. Writing empty result."
  write_empty_json_array "${output_file}"
  exit 0
fi

tmp_output="$(mktemp)"
set +e
bandit -r "${workspace}" \
  --severity-level medium \
  --confidence-level medium \
  --skip B101 \
  --format json \
  --output "${tmp_output}"
rc=$?
set -e

if [[ "${rc}" -ne 0 && "${rc}" -ne 1 ]]; then
  warn "Bandit execution failed (exit ${rc}). Writing empty result."
  rm -f "${tmp_output}"
  write_empty_json_array "${output_file}"
  exit 0
fi

mv "${tmp_output}" "${output_file}"
log "Wrote JSON to ${output_file}"
