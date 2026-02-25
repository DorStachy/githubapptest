#!/usr/bin/env bash
set -euo pipefail

SCANNER_NAME="codeql"
# shellcheck disable=SC1091
source "$(cd "$(dirname "$0")" && pwd)/common.sh"

workspace="$(resolve_workspace "$@")"
output_file="$(result_sarif_path "codeql")"
codeql_version="${CODEQL_VERSION:-2.16.1}"

merge_sarif_files() {
  local destination="$1"
  shift
  node - "${destination}" "$@" <<'NODE'
const fs = require('fs');
const destination = process.argv[2];
const inputs = process.argv.slice(3);

const merged = { version: '2.1.0', runs: [] };
for (const filePath of inputs) {
  const raw = fs.readFileSync(filePath, 'utf8');
  const parsed = JSON.parse(raw);
  if (Array.isArray(parsed.runs)) {
    merged.runs.push(...parsed.runs);
  }
}
fs.writeFileSync(destination, `${JSON.stringify(merged, null, 2)}\n`, 'utf8');
NODE
}

find_upstream_sarif() {
  local runner_temp="${RUNNER_TEMP:-}"
  if [[ -z "${runner_temp}" || ! -d "${runner_temp}" ]]; then
    return 0
  fi

  find "${runner_temp}" -type f -path "*/codeql-results/*.sarif" 2>/dev/null || true
}

resolve_codeql_binary() {
  if is_strict_mode; then
    if command -v codeql >/dev/null 2>&1; then
      command -v codeql
      return 0
    fi
    warn "CodeQL binary not prebundled in strict mode. Falling back to Semgrep + Bandit."
    return 1
  fi

  local archive_name="codeql-linux64.zip"
  local archive_path="${TOOL_CACHE_DIR}/${archive_name}"
  local install_dir="${TOOL_CACHE_DIR}/codeql-${codeql_version}"
  local codeql_bin="${install_dir}/codeql/codeql"

  if [[ ! -x "${codeql_bin}" ]]; then
    mkdir -p "${install_dir}"
    if [[ ! -f "${archive_path}" ]]; then
      if ! download_release_asset "${archive_path}" \
        "https://github.com/github/codeql-cli-binaries/releases/download/v${codeql_version}/codeql-linux64.zip"; then
        warn "Failed to download CodeQL CLI bundle. Falling back to Semgrep + Bandit."
        return 1
      fi
    fi

    if ! verify_download "${archive_path}" "${archive_name}"; then
      warn "CodeQL checksum verification failed. Falling back to Semgrep + Bandit."
      return 1
    fi

    rm -rf "${install_dir:?}"/*
    unzip -q "${archive_path}" -d "${install_dir}"
    chmod +x "${codeql_bin}" || true
  fi

  if [[ ! -x "${codeql_bin}" ]]; then
    warn "CodeQL binary not found after extraction. Falling back to Semgrep + Bandit."
    return 1
  fi

  echo "${codeql_bin}"
}

mapfile -t upstream_results < <(find_upstream_sarif)
if [[ "${#upstream_results[@]}" -gt 0 ]]; then
  merge_sarif_files "${output_file}" "${upstream_results[@]}"
  log "Ingested upstream CodeQL SARIF (${#upstream_results[@]} file(s))."
  exit 0
fi

has_js=false
has_python=false
if find_any_file "${workspace}" "*.js" "*.jsx" "*.ts" "*.tsx"; then
  has_js=true
fi
if find_any_file "${workspace}" "*.py"; then
  has_python=true
fi

if [[ "${has_js}" != "true" && "${has_python}" != "true" ]]; then
  log "No JavaScript/TypeScript/Python files found. Skipping CodeQL."
  exit 0
fi

if ! codeql_bin="$(resolve_codeql_binary)"; then
  exit 0
fi

languages=()
query_suites=()

if [[ "${has_js}" == "true" ]]; then
  languages+=("javascript")
  query_suites+=("codeql/javascript-queries:codeql-suites/javascript-security-extended.qls")
fi
if [[ "${has_python}" == "true" ]]; then
  languages+=("python")
  query_suites+=("codeql/python-queries:codeql-suites/python-security-extended.qls")
fi

language_csv="$(IFS=,; echo "${languages[*]}")"
database_dir="$(mktemp -d "${TOOL_CACHE_DIR}/codeql-db-XXXXXX")"

set +e
"${codeql_bin}" database create "${database_dir}" \
  --source-root "${workspace}" \
  --language "${language_csv}" \
  --quiet
create_rc=$?
set -e

if [[ "${create_rc}" -ne 0 ]]; then
  warn "CodeQL database creation failed (exit ${create_rc}). Falling back to Semgrep + Bandit."
  rm -rf "${database_dir}"
  exit 0
fi

set +e
"${codeql_bin}" database analyze "${database_dir}" \
  --format sarifv2.1.0 \
  --output "${output_file}" \
  --threads 0 \
  "${query_suites[@]}"
analyze_rc=$?
set -e

rm -rf "${database_dir}"

if [[ "${analyze_rc}" -ne 0 ]]; then
  warn "CodeQL analysis failed (exit ${analyze_rc}). Falling back to Semgrep + Bandit."
  rm -f "${output_file}"
  exit 0
fi

log "Wrote SARIF to ${output_file}"
