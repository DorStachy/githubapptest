#!/usr/bin/env bash
set -euo pipefail

SCANNER_NAME="semgrep"
# shellcheck disable=SC1091
source "$(cd "$(dirname "$0")" && pwd)/common.sh"

workspace="$(resolve_workspace "$@")"
output_file="$(result_sarif_path "semgrep")"
config_file="${CONFIG_ROOT}/semgrep-rules.yml"
semgrep_version="${SEMGREP_VERSION:-1.89.0}"

if [[ ! -f "${config_file}" ]]; then
  warn "Semgrep config file missing: ${config_file}. Writing empty result."
  write_empty_sarif "${output_file}"
  exit 0
fi

if ! ensure_python_tool "semgrep" "semgrep" "${semgrep_version}"; then
  warn "Semgrep is unavailable. Writing empty result."
  write_empty_sarif "${output_file}"
  exit 0
fi

args=(
  scan
  "--config=${config_file}"
  "--sarif"
  "--output=${output_file}"
  "--disable-version-check"
  "${workspace}"
)

semgrep_stderr_log="${CODEFENCE_RESULTS_DIR:-/tmp/codefence-results}/raw/semgrep-internal.stderr.log"

if is_strict_mode; then
  args+=("--no-autofix" "--offline")
else
  args+=(
    "--config=p/security-audit"
    "--config=p/owasp-top-ten"
    "--config=p/javascript"
    "--config=p/python"
  )
fi

set +e
semgrep "${args[@]}" 2>"${semgrep_stderr_log}"
rc=$?
set -e

# If semgrep failed with remote rulesets, fall back to local rules only
if [[ "${rc}" -ne 0 && "${rc}" -ne 1 ]]; then
  if ! is_strict_mode; then
    warn "Semgrep with remote rulesets failed (exit ${rc}). Retrying with local rules only."
    fallback_args=(
      scan
      "--config=${config_file}"
      "--sarif"
      "--output=${output_file}"
      "--disable-version-check"
      "${workspace}"
    )
    set +e
    semgrep "${fallback_args[@]}" 2>>"${semgrep_stderr_log}"
    rc=$?
    set -e
  fi
fi

if [[ "${rc}" -ne 0 && "${rc}" -ne 1 ]]; then
  warn "Semgrep execution failed (exit ${rc})."
  write_empty_sarif "${output_file}"
  exit 0
fi

if [[ ! -f "${output_file}" ]]; then
  write_empty_sarif "${output_file}"
fi

# Check stderr for partial scan indication and exit with code 2 to signal partial status
if [[ -f "${semgrep_stderr_log}" ]] && grep -qi 'Partially scanned' "${semgrep_stderr_log}"; then
  warn "Semgrep reported partial scan. Signaling partial status."
  exit 2
fi

log "Wrote SARIF to ${output_file}"
