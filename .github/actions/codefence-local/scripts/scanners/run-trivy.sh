#!/usr/bin/env bash
set -euo pipefail

SCANNER_NAME="trivy"
# shellcheck disable=SC1091
source "$(cd "$(dirname "$0")" && pwd)/common.sh"

workspace="$(resolve_workspace "$@")"
output_file="$(result_json_path "trivy")"
trivy_version="${TRIVY_VERSION:-0.55.0}"

resolve_trivy_binary() {
  # Prefer pre-installed binary (e.g., Docker image)
  if command -v trivy >/dev/null 2>&1; then
    log "trivy found at $(command -v trivy) (pre-installed)" >&2
    command -v trivy
    return 0
  fi

  if is_strict_mode; then
    error "trivy is not prebundled in strict mode."
    return 1
  fi

  local archive_name="trivy_${trivy_version}_Linux-64bit.tar.gz"
  local archive_path="${TOOL_CACHE_DIR}/${archive_name}"
  local install_dir="${TOOL_CACHE_DIR}/trivy-${trivy_version}"
  local binary_path="${install_dir}/trivy"

  if [[ ! -x "${binary_path}" ]]; then
    mkdir -p "${install_dir}"
    if [[ ! -f "${archive_path}" ]]; then
      if ! download_release_asset "${archive_path}" \
        "https://github.com/aquasecurity/trivy/releases/download/v${trivy_version}/trivy_${trivy_version}_Linux-64bit.tar.gz"; then
        error "Failed to download trivy release archive."
        return 1
      fi
    fi

    verify_download "${archive_path}" "${archive_name}"

    rm -rf "${install_dir:?}"/*
    tar -xzf "${archive_path}" -C "${install_dir}"
    chmod +x "${binary_path}" || true
  fi

  if [[ ! -x "${binary_path}" ]]; then
    error "trivy binary not found after extraction."
    return 1
  fi

  echo "${binary_path}"
}

if ! trivy_bin="$(resolve_trivy_binary)"; then
  warn "Trivy unavailable. Writing empty result."
  printf '{"Results":[]}\n' > "${output_file}"
  exit 0
fi

cmd=(
  "${trivy_bin}"
  fs
  "--scanners" "vuln,secret,misconfig"
  "--severity" "MEDIUM,HIGH,CRITICAL"
  "--format" "json"
  "--output" "${output_file}"
  "${workspace}"
)

if is_strict_mode; then
  cmd+=("--skip-db-update" "--skip-java-db-update" "--offline-scan")
  if [[ -d "/opt/advisory-db/trivy" ]]; then
    cmd+=("--cache-dir" "/opt/advisory-db/trivy")
  fi
else
  # In standard mode with read-only root FS (Fargate), ensure trivy can
  # write its DB cache.  TRIVY_CACHE_DIR env var is preferred, fallback to /tmp.
  trivy_cache="${TRIVY_CACHE_DIR:-/tmp/trivy-cache}"
  mkdir -p "${trivy_cache}" 2>/dev/null || true
  cmd+=("--cache-dir" "${trivy_cache}")
fi

set +e
"${cmd[@]}"
rc=$?
set -e

if [[ "${rc}" -ne 0 && "${rc}" -ne 1 ]]; then
  warn "Trivy execution failed (exit ${rc}). Writing empty result."
  printf '{"Results":[]}\n' > "${output_file}"
  exit 0
fi

if [[ ! -f "${output_file}" ]]; then
  printf '{"Results":[]}\n' > "${output_file}"
fi

log "Wrote JSON to ${output_file}"
