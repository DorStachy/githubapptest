#!/usr/bin/env bash
set -euo pipefail

SCANNER_NAME="pip-audit"
# shellcheck disable=SC1091
source "$(cd "$(dirname "$0")" && pwd)/common.sh"

workspace="$(resolve_workspace "$@")"
output_file="$(result_json_path "pip-audit")"
pip_audit_version="${PIP_AUDIT_VERSION:-2.7.3}"
strict_cache_dir="${CODEFENCE_PIP_AUDIT_CACHE_DIR:-/opt/advisory-db/pip-audit}"

mapfile -t requirement_files < <(
  collect_files "${workspace}" \
    "requirements.txt" \
    "requirements-*.txt" \
    "Pipfile.lock" \
    "poetry.lock"
)

if [[ "${#requirement_files[@]}" -eq 0 ]] && ! find_any_file "${workspace}" "pyproject.toml"; then
  log "No Python dependency manifests found. Skipping pip-audit."
  exit 0
fi

if ! ensure_python_tool "pip-audit" "pip-audit" "${pip_audit_version}"; then
  warn "pip-audit is unavailable. Writing empty result."
  printf '{"dependencies":[]}\n' > "${output_file}"
  exit 0
fi

tmp_dir="$(mktemp -d)"
outputs=()

run_pip_audit() {
  local target="$1"
  local mode="$2"
  local destination="$3"
  local stderr_log="${destination}.stderr"

  cmd=(pip-audit "--format=json" "--desc")
  if [[ "${mode}" == "requirements" ]]; then
    cmd+=("-r" "${target}")
  fi

  if is_strict_mode; then
    cmd+=("--offline")
    if [[ -d "${strict_cache_dir}" ]]; then
      cmd+=("--cache-dir" "${strict_cache_dir}")
    fi
  fi

  set +e
  "${cmd[@]}" > "${destination}" 2>"${stderr_log}"
  rc=$?
  set -e

  # pip-audit exits 1 when vulnerabilities are found.
  if [[ "${rc}" -ne 0 && "${rc}" -ne 1 ]]; then
    return "${rc}"
  fi

  # Check stderr for subprocess-exited-with-error indicating partial failure
  if [[ -f "${stderr_log}" ]] && grep -qi 'subprocess-exited-with-error' "${stderr_log}"; then
    warn "pip-audit reported subprocess-exited-with-error (partial failure)"
    return 2
  fi

  return 0
}

for requirements_file in "${requirement_files[@]}"; do
  out="${tmp_dir}/$(basename "${requirements_file}").json"
  if ! run_pip_audit "${requirements_file}" "requirements" "${out}"; then
    warn "pip-audit failed for ${requirements_file}"
    continue
  fi
  outputs+=("${out}")
done

if [[ "${#outputs[@]}" -eq 0 ]] && find_any_file "${workspace}" "pyproject.toml"; then
  out="${tmp_dir}/project.json"
  if run_pip_audit "${workspace}" "project" "${out}"; then
    outputs+=("${out}")
  else
    warn "pip-audit failed for pyproject.toml based project scan."
  fi
fi

if [[ "${#outputs[@]}" -eq 0 ]]; then
  warn "pip-audit did not produce findings output. Writing empty result."
  printf '{"dependencies":[]}\n' > "${output_file}"
  rm -rf "${tmp_dir}"
  exit 0
fi

node - "${output_file}" "${outputs[@]}" <<'NODE'
const fs = require('fs');
const destination = process.argv[2];
const files = process.argv.slice(3);

const merged = { dependencies: [] };
for (const filePath of files) {
  const raw = fs.readFileSync(filePath, 'utf8').trim();
  if (!raw) continue;
  const parsed = JSON.parse(raw);
  if (Array.isArray(parsed.dependencies)) {
    merged.dependencies.push(...parsed.dependencies);
  }
}

fs.writeFileSync(destination, `${JSON.stringify(merged, null, 2)}\n`, 'utf8');
NODE

rm -rf "${tmp_dir}"
log "Wrote JSON to ${output_file}"
