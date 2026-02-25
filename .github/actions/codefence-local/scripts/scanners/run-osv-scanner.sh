#!/usr/bin/env bash
set -euo pipefail

SCANNER_NAME="osv-scanner"
# shellcheck disable=SC1091
source "$(cd "$(dirname "$0")" && pwd)/common.sh"

workspace="$(resolve_workspace "$@")"
output_file="$(result_json_path "osv-scanner")"
osv_version="${OSV_SCANNER_VERSION:-1.8.2}"
strict_local_db="${CODEFENCE_OSV_DB_PATH:-/opt/advisory-db/osv}"

mapfile -t lockfiles < <(
  collect_files "${workspace}" \
    "package-lock.json" \
    "yarn.lock" \
    "pnpm-lock.yaml" \
    "requirements.txt" \
    "requirements-*.txt" \
    "Pipfile.lock" \
    "poetry.lock" \
    "Cargo.lock" \
    "go.sum" \
    "Gemfile.lock" \
    "composer.lock"
)

if [[ "${#lockfiles[@]}" -eq 0 ]]; then
  log "No dependency lockfiles found. Skipping OSV-Scanner."
  exit 0
fi

resolve_osv_binary() {
  # Prefer pre-installed binary (e.g., Docker image)
  if command -v osv-scanner >/dev/null 2>&1; then
    log "osv-scanner found at $(command -v osv-scanner) (pre-installed)" >&2
    command -v osv-scanner
    return 0
  fi

  if is_strict_mode; then
    error "osv-scanner is not prebundled in strict mode."
    return 1
  fi

  local asset_name="osv-scanner_linux_amd64"
  local binary_path="${TOOL_CACHE_DIR}/${asset_name}"

  if [[ ! -x "${binary_path}" ]]; then
    if [[ ! -f "${binary_path}" ]]; then
      if ! download_release_asset "${binary_path}" \
        "https://github.com/google/osv-scanner/releases/download/v${osv_version}/osv-scanner_linux_amd64"; then
        error "Failed to download osv-scanner binary."
        return 1
      fi
    fi

    verify_download "${binary_path}" "${asset_name}"
    chmod +x "${binary_path}"
  fi

  echo "${binary_path}"
}

if ! osv_bin="$(resolve_osv_binary)"; then
  warn "OSV-Scanner unavailable. Writing empty result."
  printf '{"results":[]}\n' > "${output_file}"
  exit 0
fi

tmp_output="$(mktemp)"
success=false

if "${osv_bin}" --help 2>/dev/null | grep -q "scan"; then
  # Use --recursive to let osv-scanner discover lockfiles itself.
  # Flags MUST come before the positional --recursive DIR, because
  # osv-scanner v1.x treats everything after --recursive as paths.
  cmd=("${osv_bin}" "scan" "--format" "json" "--output" "${tmp_output}")
  if is_strict_mode; then
    cmd+=("--offline")
    if [[ -d "${strict_local_db}" ]]; then
      cmd+=("--local-db" "${strict_local_db}")
    fi
  fi
  cmd+=("--recursive" "${workspace}")

  set +e
  "${cmd[@]}" 2>&1
  scan_rc=$?
  set -e

  if [[ "${scan_rc}" -eq 0 || "${scan_rc}" -eq 1 ]]; then
    success=true
  else
    warn "OSV-Scanner scan mode failed (exit ${scan_rc}). Command: ${cmd[*]}"
  fi
fi

if [[ "${success}" != "true" ]]; then
  # Legacy (pre-v1.7) invocation; --json MUST precede --recursive
  # because osv-scanner treats everything after --recursive as paths.
  legacy_cmd=("${osv_bin}" "--json" "--recursive" "${workspace}")
  if is_strict_mode; then
    legacy_cmd+=("--offline")
    if [[ -d "${strict_local_db}" ]]; then
      legacy_cmd+=("--local-db" "${strict_local_db}")
    fi
  fi

  set +e
  "${legacy_cmd[@]}" > "${tmp_output}" 2>&1
  legacy_rc=$?
  set -e

  if [[ "${legacy_rc}" -eq 0 || "${legacy_rc}" -eq 1 ]]; then
    success=true
  else
    warn "OSV-Scanner legacy mode failed (exit ${legacy_rc}). Command: ${legacy_cmd[*]}"
  fi
fi

if [[ "${success}" != "true" ]]; then
  warn "OSV-Scanner execution failed. Writing empty result."
  rm -f "${tmp_output}"
  printf '{"results":[]}\n' > "${output_file}"
  exit 0
fi

if [[ ! -s "${tmp_output}" ]]; then
  printf '{"results":[]}\n' > "${tmp_output}"
fi

mv "${tmp_output}" "${output_file}"
log "Wrote JSON to ${output_file}"
