#!/usr/bin/env bash
set -euo pipefail

SCANNER_NAME="gitleaks"
# shellcheck disable=SC1091
source "$(cd "$(dirname "$0")" && pwd)/common.sh"

workspace="$(resolve_workspace "$@")"
output_file="$(result_json_path "gitleaks")"
gitleaks_version="${GITLEAKS_VERSION:-8.18.4}"
config_file="${CONFIG_ROOT}/gitleaks-extensions.toml"

resolve_gitleaks_binary() {
  # Prefer pre-installed binary (e.g., Docker image)
  if command -v gitleaks >/dev/null 2>&1; then
    log "gitleaks found at $(command -v gitleaks) (pre-installed)" >&2
    command -v gitleaks
    return 0
  fi

  if is_strict_mode; then
    error "gitleaks is not prebundled in strict mode."
    return 1
  fi

  local archive_name="gitleaks_${gitleaks_version}_linux_x64.tar.gz"
  local archive_path="${TOOL_CACHE_DIR}/${archive_name}"
  local install_dir="${TOOL_CACHE_DIR}/gitleaks-${gitleaks_version}"
  local binary_path="${install_dir}/gitleaks"

  if [[ ! -x "${binary_path}" ]]; then
    mkdir -p "${install_dir}"
    if [[ ! -f "${archive_path}" ]]; then
      if ! download_release_asset "${archive_path}" \
        "https://github.com/gitleaks/gitleaks/releases/download/v${gitleaks_version}/gitleaks_${gitleaks_version}_linux_x64.tar.gz"; then
        error "Failed to download gitleaks release archive."
        return 1
      fi
    fi

    verify_download "${archive_path}" "${archive_name}"

    rm -rf "${install_dir:?}"/*
    tar -xzf "${archive_path}" -C "${install_dir}"
    chmod +x "${binary_path}" || true
  fi

  if [[ ! -x "${binary_path}" ]]; then
    error "gitleaks binary not found after extraction."
    return 1
  fi

  echo "${binary_path}"
}

if [[ ! -f "${config_file}" ]]; then
  warn "Gitleaks config file missing: ${config_file}. Writing empty result."
  write_empty_json_array "${output_file}"
  exit 0
fi

if ! gitleaks_bin="$(resolve_gitleaks_binary)"; then
  warn "Gitleaks binary unavailable. Writing empty result."
  write_empty_json_array "${output_file}"
  exit 0
fi

set +e
"${gitleaks_bin}" detect \
  --source "${workspace}" \
  --report-format json \
  --report-path "${output_file}" \
  --config "${config_file}" \
  --redact \
  --no-git
rc=$?
set -e

# gitleaks exits 1 when findings are present.
if [[ "${rc}" -ne 0 && "${rc}" -ne 1 ]]; then
  warn "gitleaks execution failed (exit ${rc}). Writing empty result."
  write_empty_json_array "${output_file}"
  exit 0
fi

if [[ ! -f "${output_file}" ]]; then
  write_empty_json_array "${output_file}"
fi

log "Wrote JSON to ${output_file}"
