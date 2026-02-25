#!/usr/bin/env bash
set -euo pipefail

SCANNER_NAME="scorecard"
# shellcheck disable=SC1091
source "$(cd "$(dirname "$0")" && pwd)/common.sh"

workspace="$(resolve_workspace "$@")"
output_file="$(result_json_path "scorecard")"
scorecard_version="${SCORECARD_VERSION:-5.1.1}"

if is_strict_mode; then
  warn "Scorecard is skipped in strict mode (POSTURE-UNAVAILABLE)."
  printf '{"checks":[],"metadata":{"status":"POSTURE-UNAVAILABLE","reason":"strict-mode"}}\n' > "${output_file}"
  exit 0
fi

resolve_scorecard_binary() {
  # Prefer pre-installed binary (e.g., Docker image)
  if command -v scorecard >/dev/null 2>&1; then
    log "scorecard found at $(command -v scorecard) (pre-installed)" >&2
    command -v scorecard
    return 0
  fi

  if is_strict_mode; then
    error "scorecard is not prebundled in strict mode."
    return 1
  fi

  local archive_name="scorecard_${scorecard_version}_linux_amd64.tar.gz"
  local archive_path="${TOOL_CACHE_DIR}/${archive_name}"
  local install_dir="${TOOL_CACHE_DIR}/scorecard-${scorecard_version}"
  local binary_path="${install_dir}/scorecard"

  if [[ ! -x "${binary_path}" ]]; then
    mkdir -p "${install_dir}"
    if [[ ! -f "${archive_path}" ]]; then
      if ! download_release_asset "${archive_path}" \
        "https://github.com/ossf/scorecard/releases/download/v${scorecard_version}/scorecard_${scorecard_version}_linux_amd64.tar.gz"; then
        error "Failed to download scorecard release archive."
        return 1
      fi
    fi

    verify_download "${archive_path}" "${archive_name}"

    rm -rf "${install_dir:?}"/*
    tar -xzf "${archive_path}" -C "${install_dir}"
    chmod +x "${binary_path}" || true
  fi

  if [[ ! -x "${binary_path}" ]]; then
    error "scorecard binary not found after extraction."
    return 1
  fi

  echo "${binary_path}"
}

if ! scorecard_bin="$(resolve_scorecard_binary)"; then
  warn "Scorecard binary unavailable. Marking posture as unavailable."
  printf '{"checks":[],"metadata":{"status":"POSTURE-UNAVAILABLE","reason":"scorecard-unavailable"}}\n' > "${output_file}"
  exit 0
fi

repo_name="${GITHUB_REPOSITORY:-}"

if [[ -z "${repo_name}" ]]; then
  warn "GITHUB_REPOSITORY is empty. Skipping scorecard run."
  printf '{"checks":[],"metadata":{"status":"POSTURE-UNAVAILABLE","reason":"missing-github-repository"}}\n' > "${output_file}"
  exit 0
else
  # Scorecard uses GITHUB_AUTH_TOKEN or GITHUB_TOKEN for API auth
  export GITHUB_AUTH_TOKEN="${GITHUB_TOKEN:-}"

  set +e
  "${scorecard_bin}" --format json --repo "github.com/${repo_name}" > "${output_file}"
  rc=$?
  set -e

  if [[ "${rc}" -ne 0 ]]; then
    warn "Scorecard execution failed (exit ${rc}). Marking posture as unavailable."
    printf '{"checks":[],"metadata":{"status":"POSTURE-UNAVAILABLE","reason":"scorecard-run-failed"}}\n' > "${output_file}"
    exit 0
  fi
fi

log "Wrote JSON to ${output_file}"
