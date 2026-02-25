#!/usr/bin/env bash
set -euo pipefail

SCANNER_NAME="actionlint"
# shellcheck disable=SC1091
source "$(cd "$(dirname "$0")" && pwd)/common.sh"

workspace="$(resolve_workspace "$@")"
output_file="$(result_json_path "actionlint")"
actionlint_version="${ACTIONLINT_VERSION:-1.7.4}"

if [[ ! -d "${workspace}/.github/workflows" ]]; then
  log "No workflow directory found. Skipping actionlint."
  exit 0
fi

resolve_actionlint_binary() {
  # Prefer pre-installed binary (e.g., Docker image)
  if command -v actionlint >/dev/null 2>&1; then
    log "actionlint found at $(command -v actionlint) (pre-installed)" >&2
    command -v actionlint
    return 0
  fi

  if is_strict_mode; then
    error "actionlint is not prebundled in strict mode."
    return 1
  fi

  local archive_name="actionlint_${actionlint_version}_linux_amd64.tar.gz"
  local archive_path="${TOOL_CACHE_DIR}/${archive_name}"
  local install_dir="${TOOL_CACHE_DIR}/actionlint-${actionlint_version}"
  local binary_path="${install_dir}/actionlint"

  if [[ ! -x "${binary_path}" ]]; then
    mkdir -p "${install_dir}"
    if [[ ! -f "${archive_path}" ]]; then
      if ! download_release_asset "${archive_path}" \
        "https://github.com/rhysd/actionlint/releases/download/v${actionlint_version}/actionlint_${actionlint_version}_linux_amd64.tar.gz"; then
        error "Failed to download actionlint release archive."
        return 1
      fi
    fi

    verify_download "${archive_path}" "${archive_name}"

    rm -rf "${install_dir:?}"/*
    tar -xzf "${archive_path}" -C "${install_dir}"
    chmod +x "${binary_path}" || true
  fi

  if [[ ! -x "${binary_path}" ]]; then
    error "actionlint binary not found after extraction."
    return 1
  fi

  echo "${binary_path}"
}

if ! actionlint_bin="$(resolve_actionlint_binary)"; then
  warn "actionlint binary unavailable. Writing empty result."
  write_empty_json_array "${output_file}"
  exit 0
fi

tmp_output="$(mktemp)"

# actionlint expects individual files or to be run from the repo root
# where it auto-discovers .github/workflows/*.{yml,yaml}.
# Passing a directory path directly causes "is a directory" errors.
set +e
(cd "${workspace}" && "${actionlint_bin}" -format '{{json .}}') > "${tmp_output}"
rc=$?
set -e

# actionlint exits 1 when findings are present.
if [[ "${rc}" -ne 0 && "${rc}" -ne 1 ]]; then
  warn "actionlint execution failed (exit ${rc}). Writing empty result."
  rm -f "${tmp_output}"
  write_empty_json_array "${output_file}"
  exit 0
fi

node - "${tmp_output}" "${output_file}" <<'NODE'
const fs = require('fs');
const source = process.argv[2];
const destination = process.argv[3];

const lines = fs
  .readFileSync(source, 'utf8')
  .split(/\r?\n/)
  .map((line) => line.trim())
  .filter(Boolean);

const parsed = [];
for (const line of lines) {
  try {
    parsed.push(JSON.parse(line));
  } catch {
    // Ignore non-JSON log lines from tool wrappers.
  }
}
fs.writeFileSync(destination, `${JSON.stringify(parsed, null, 2)}\n`, 'utf8');
NODE

rm -f "${tmp_output}"
log "Wrote JSON to ${output_file}"
