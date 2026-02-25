#!/usr/bin/env bash
set -euo pipefail

SCANNER_NAME="checkov"
# shellcheck disable=SC1091
source "$(cd "$(dirname "$0")" && pwd)/common.sh"

workspace="$(resolve_workspace "$@")"
output_file="$(result_sarif_path "checkov")"
checkov_version="${CHECKOV_VERSION:-3.2.312}"

if ! find_any_file "${workspace}" "*.tf" "*.tf.json" "Dockerfile*" "*.yaml" "*.yml"; then
  log "No IaC/docker/workflow files found. Skipping Checkov."
  exit 0
fi

if ! ensure_python_tool "checkov" "checkov" "${checkov_version}"; then
  warn "Checkov is unavailable. Writing empty result."
  write_empty_sarif "${output_file}"
  exit 0
fi

cmd=(
  checkov
  -d "${workspace}"
  "--framework" "terraform,kubernetes,dockerfile,github_actions"
  "--skip-check" "CKV2_*"
  "--quiet"
  "--soft-fail"
  "--output" "sarif"
  "--output-file-path" "${output_file}"
)

if [[ -f "${CONFIG_ROOT}/checkov-security.yml" ]]; then
  cmd+=("--config-file" "${CONFIG_ROOT}/checkov-security.yml")
fi

if is_strict_mode; then
  if [[ -d "/opt/codefence/configs/checkov" ]]; then
    cmd+=("--external-checks-dir" "/opt/codefence/configs/checkov")
  fi
  cmd+=("--skip-download")
fi

# Checkov's --output-file-path creates a DIRECTORY and writes
# results_sarif.sarif inside it. We use a temp directory and then
# move the actual SARIF file to the expected output path.
checkov_out_dir="$(mktemp -d)"

# Replace --output-file-path with the temp directory
cmd_final=()
for arg in "${cmd[@]}"; do
  if [[ "${prev_arg:-}" == "--output-file-path" ]]; then
    cmd_final+=("${checkov_out_dir}")
  else
    cmd_final+=("${arg}")
  fi
  prev_arg="${arg}"
done

set +e
"${cmd_final[@]}"
rc=$?
set -e

# Look for the SARIF file Checkov actually writes
checkov_sarif="${checkov_out_dir}/results_sarif.sarif"
if [[ -f "${checkov_sarif}" ]]; then
  mv "${checkov_sarif}" "${output_file}"
elif [[ "${rc}" -ne 0 || ! -f "${output_file}" ]]; then
  warn "Checkov primary SARIF command failed (exit ${rc}). Retrying with stdout redirection."
  fallback_cmd=(
    checkov
    -d "${workspace}"
    "--framework" "terraform,kubernetes,dockerfile,github_actions"
    "--skip-check" "CKV2_*"
    "--quiet"
    "--soft-fail"
    "--output" "sarif"
  )
  if [[ -f "${CONFIG_ROOT}/checkov-security.yml" ]]; then
    fallback_cmd+=("--config-file" "${CONFIG_ROOT}/checkov-security.yml")
  fi
  if is_strict_mode; then
    if [[ -d "/opt/codefence/configs/checkov" ]]; then
      fallback_cmd+=("--external-checks-dir" "/opt/codefence/configs/checkov")
    fi
    fallback_cmd+=("--skip-download")
  fi

  set +e
  "${fallback_cmd[@]}" > "${output_file}"
  fallback_rc=$?
  set -e
  if [[ "${fallback_rc}" -ne 0 ]]; then
    warn "Checkov fallback command failed (exit ${fallback_rc}). Writing empty result."
    write_empty_sarif "${output_file}"
    exit 0
  fi
fi
rm -rf "${checkov_out_dir}"

if [[ ! -f "${output_file}" ]]; then
  write_empty_sarif "${output_file}"
fi

log "Wrote SARIF to ${output_file}"
