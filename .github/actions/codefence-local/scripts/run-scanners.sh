#!/usr/bin/env bash
set -euo pipefail

results_dir="${CODEFENCE_RESULTS_DIR:-/tmp/codefence-results}"
scanner_timeout="${CODEFENCE_SCANNER_TIMEOUT_SECONDS:-600}"
codeql_timeout="${CODEFENCE_CODEQL_TIMEOUT_SECONDS:-1800}"
scanners_raw="${CODEFENCE_SCANNERS:-all}"
workspace="${GITHUB_WORKSPACE:-$(pwd)}"

mkdir -p "$results_dir/raw"
status_file="$results_dir/scanner-status.json"

if [[ "$scanners_raw" == "all" || -z "$scanners_raw" ]]; then
  scanners=(
    "codeql"
    "semgrep"
    "bandit"
    "gitleaks"
    "osv-scanner"
    "pip-audit"
    "actionlint"
    "zizmor"
    "checkov"
    "trivy"
    "scorecard"
  )
else
  IFS=',' read -r -a scanners <<< "$scanners_raw"
fi

pids=()
scanner_names=()

run_with_timeout() {
  local timeout_seconds="$1"
  shift

  if command -v timeout >/dev/null 2>&1; then
    timeout --signal=TERM "${timeout_seconds}" "$@"
    return $?
  fi

  local timeout_marker
  timeout_marker="$(mktemp)"
  trap "rm -f '${timeout_marker}'" EXIT

  "$@" &
  local cmd_pid=$!

  (
    sleep "${timeout_seconds}"
    if kill -0 "${cmd_pid}" >/dev/null 2>&1; then
      echo "timeout" > "${timeout_marker}"
      kill -TERM "${cmd_pid}" >/dev/null 2>&1 || true
    fi
  ) &
  local timer_pid=$!

  wait "${cmd_pid}"
  local cmd_rc=$?

  kill "${timer_pid}" >/dev/null 2>&1 || true
  wait "${timer_pid}" 2>/dev/null || true

  if [[ -s "${timeout_marker}" ]]; then
    trap - EXIT
    rm -f "${timeout_marker}"
    return 124
  fi

  trap - EXIT
  rm -f "${timeout_marker}"
  return "${cmd_rc}"
}

run_scanner() {
  local scanner="$1"
  local script_path="$(dirname "$0")/scanners/run-${scanner}.sh"
  local timeout_seconds="${scanner_timeout}"

  if [[ "$scanner" == "codeql" ]]; then
    timeout_seconds="${codeql_timeout}"
  fi

  if [[ ! -f "$script_path" ]]; then
    echo "::warning::Scanner wrapper missing for ${scanner} (${script_path}). Skipping."
    echo "{\"scanner\":\"${scanner}\",\"status\":\"missing-wrapper\"}" >"$results_dir/raw/${scanner}.status.json"
    return 0
  fi

  (
    set +e
    if ! command -v timeout >/dev/null 2>&1; then
      echo "::warning::timeout command not found; using shell timeout fallback for ${scanner} (${timeout_seconds}s)." \
        >"$results_dir/raw/${scanner}.stderr.log"
    fi

    run_with_timeout "${timeout_seconds}" bash "$script_path" --workspace "$workspace" \
      >"$results_dir/raw/${scanner}.stdout.log" \
      2>>"$results_dir/raw/${scanner}.stderr.log"
    rc=$?
    set -e

    if [[ $rc -eq 0 ]]; then
      echo "{\"scanner\":\"${scanner}\",\"status\":\"ok\"}" >"$results_dir/raw/${scanner}.status.json"
      exit 0
    elif [[ $rc -eq 124 ]]; then
      echo "{\"scanner\":\"${scanner}\",\"status\":\"timeout\"}" >"$results_dir/raw/${scanner}.status.json"
      exit 0
    elif [[ $rc -eq 2 ]]; then
      echo "{\"scanner\":\"${scanner}\",\"status\":\"partial\"}" >"$results_dir/raw/${scanner}.status.json"
      exit 0
    else
      echo "{\"scanner\":\"${scanner}\",\"status\":\"failed\",\"exitCode\":${rc}}" >"$results_dir/raw/${scanner}.status.json"
      exit 0
    fi
  ) &

  pids+=("$!")
  scanner_names+=("$scanner")
}

for scanner in "${scanners[@]}"; do
  scanner="$(echo "$scanner" | xargs)"
  [[ -z "$scanner" ]] && continue
  run_scanner "$scanner"
done

for pid in "${pids[@]}"; do
  wait "$pid"
done

# Post-hoc: check stderr logs for known soft-failure patterns and override status to "partial"
for scanner in "${scanner_names[@]}"; do
  stderr_log="$results_dir/raw/${scanner}.stderr.log"
  status_json="$results_dir/raw/${scanner}.status.json"
  if [[ -f "${stderr_log}" && -f "${status_json}" ]]; then
    if grep -qiE 'partially scanned|subprocess-exited-with-error' "${stderr_log}"; then
      current_status=$(cat "${status_json}" 2>/dev/null || echo "")
      if echo "${current_status}" | grep -q '"status":"ok"'; then
        echo "{\"scanner\":\"${scanner}\",\"status\":\"partial\"}" > "${status_json}"
      fi
    fi
  fi
done

# Aggregate status outputs.
printf '[' > "$status_file"
for idx in "${!scanner_names[@]}"; do
  scanner="${scanner_names[$idx]}"
  [[ $idx -gt 0 ]] && printf ',' >> "$status_file"
  if [[ -f "$results_dir/raw/${scanner}.status.json" ]]; then
    cat "$results_dir/raw/${scanner}.status.json" >> "$status_file"
  else
    printf '{"scanner":"%s","status":"unknown"}' "$scanner" >> "$status_file"
  fi
done
printf ']\n' >> "$status_file"

echo "Scanner orchestration complete. Status file: $status_file"
