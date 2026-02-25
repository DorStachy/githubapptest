#!/usr/bin/env bash
set -euo pipefail

SCANNER_NAME="zizmor"
# shellcheck disable=SC1091
source "$(cd "$(dirname "$0")" && pwd)/common.sh"

workspace="$(resolve_workspace "$@")"
output_file="$(result_json_path "zizmor")"
zizmor_version="${ZIZMOR_VERSION:-1.5.1}"

if [[ ! -d "${workspace}/.github/workflows" ]]; then
  log "No workflow directory found. Skipping zizmor."
  exit 0
fi

if ! ensure_python_tool "zizmor" "zizmor" "${zizmor_version}"; then
  warn "zizmor is unavailable. Writing empty result."
  printf '{"findings":[]}\n' > "${output_file}"
  exit 0
fi

tmp_output="$(mktemp)"
success=false

set +e
zizmor --format json "${workspace}/.github/workflows" > "${tmp_output}" 2>/dev/null
rc=$?
set -e
if [[ "${rc}" -eq 0 || "${rc}" -eq 1 ]]; then
  success=true
fi

if [[ "${success}" != "true" ]]; then
  warn "zizmor execution failed (exit ${rc}). Writing empty result."
  rm -f "${tmp_output}"
  printf '{"findings":[]}\n' > "${output_file}"
  # Exit non-zero so orchestrator records status:"failed" instead of status:"ok"
  exit 2
fi

if [[ ! -s "${tmp_output}" ]]; then
  printf '{"findings":[]}\n' > "${output_file}"
else
  mv "${tmp_output}" "${output_file}"
fi

rm -f "${tmp_output}"
log "Wrote JSON to ${output_file}"
