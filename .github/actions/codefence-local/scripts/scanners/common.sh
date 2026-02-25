#!/usr/bin/env bash
set -euo pipefail

SCANNER_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACTION_ROOT="$(cd "${SCANNER_SCRIPT_DIR}/../.." && pwd)"
SCRIPTS_ROOT="${ACTION_ROOT}/scripts"
CONFIG_ROOT="${ACTION_ROOT}/configs"
VERIFY_BINARY_SCRIPT="${SCRIPTS_ROOT}/verify-binary.sh"
VERSIONS_FILE="${SCRIPTS_ROOT}/versions.env"

if [[ -f "${VERSIONS_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${VERSIONS_FILE}"
fi

CODEFENCE_RESULTS_DIR="${CODEFENCE_RESULTS_DIR:-/tmp/codefence-results}"
RAW_RESULTS_DIR="${CODEFENCE_RESULTS_DIR}/raw"
TOOL_CACHE_DIR="${CODEFENCE_TOOL_CACHE_DIR:-${RUNNER_TEMP:-/tmp}/codefence-tools}"
STRICT_MODE="${EGRESS_MODE:-${INPUT_EGRESS_MODE:-standard}}"

mkdir -p "${RAW_RESULTS_DIR}" "${TOOL_CACHE_DIR}"
export PATH="${HOME}/.local/bin:${PATH}"

if [[ -z "${SCANNER_NAME:-}" ]]; then
  SCANNER_NAME="$(basename "${BASH_SOURCE[1]:-${0}}" | sed -E 's/^run-//; s/\.sh$//')"
fi

log() {
  echo "[${SCANNER_NAME}] $*"
}

warn() {
  echo "::warning::[${SCANNER_NAME}] $*" >&2
}

error() {
  echo "::error::[${SCANNER_NAME}] $*" >&2
}

is_strict_mode() {
  [[ "$(echo "${STRICT_MODE}" | tr '[:upper:]' '[:lower:]')" == "strict" ]]
}

resolve_workspace() {
  local workspace="${GITHUB_WORKSPACE:-$(pwd)}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --workspace=*)
        workspace="${1#*=}"
        ;;
      --workspace)
        shift
        if [[ $# -gt 0 ]]; then
          workspace="$1"
        fi
        ;;
    esac
    shift || true
  done

  if [[ ! -d "${workspace}" ]]; then
    error "Workspace not found: ${workspace}"
    return 1
  fi

  (cd "${workspace}" && pwd)
}

result_json_path() {
  local scanner="$1"
  echo "${RAW_RESULTS_DIR}/${scanner}.json"
}

result_sarif_path() {
  local scanner="$1"
  echo "${RAW_RESULTS_DIR}/${scanner}.sarif"
}

write_empty_json_array() {
  local output_file="$1"
  printf '[]\n' > "${output_file}"
}

write_empty_sarif() {
  local output_file="$1"
  cat > "${output_file}" <<'EOF'
{
  "version": "2.1.0",
  "runs": []
}
EOF
}

download_release_asset() {
  local destination="$1"
  shift

  local url
  for url in "$@"; do
    if [[ -z "${url}" ]]; then
      continue
    fi
    if curl -fsSL --retry 3 --retry-delay 1 --connect-timeout 20 "${url}" -o "${destination}"; then
      return 0
    fi
  done

  return 1
}

verify_download() {
  local file_path="$1"
  local artifact_name="$2"
  "${VERIFY_BINARY_SCRIPT}" "${file_path}" "${artifact_name}"
}

ensure_python_tool() {
  local command_name="$1"
  local package_name="$2"
  local version="$3"

  # Use pre-installed tool if available (e.g., Docker image with tools baked in)
  if command -v "${command_name}" >/dev/null 2>&1; then
    log "${command_name} found at $(command -v "${command_name}") (pre-installed)" >&2
    return 0
  fi

  if is_strict_mode; then
    warn "${command_name} is not prebundled in strict mode; runtime install is blocked."
    return 1
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    error "python3 is required to install ${package_name}."
    return 1
  fi

  python3 -m pip install --disable-pip-version-check --no-input --user "${package_name}==${version}" >/dev/null

  if ! command -v "${command_name}" >/dev/null 2>&1; then
    error "Installed ${package_name} but ${command_name} is still unavailable in PATH."
    return 1
  fi

  return 0
}

find_any_file() {
  local workspace="$1"
  shift

  local pattern
  for pattern in "$@"; do
    if find "${workspace}" -type f -name "${pattern}" \
      -not -path '*/.git/*' \
      -not -path '*/node_modules/*' \
      -print -quit | grep -q .; then
      return 0
    fi
  done

  return 1
}

collect_files() {
  local workspace="$1"
  shift

  local pattern
  for pattern in "$@"; do
    find "${workspace}" -type f -name "${pattern}" \
      -not -path '*/.git/*' \
      -not -path '*/node_modules/*'
  done | sort -u
}
