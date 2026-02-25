#!/usr/bin/env bash
set -euo pipefail

strict_mode="${EGRESS_MODE:-${INPUT_EGRESS_MODE:-standard}}"
api_url="${CODEFENCE_API_URL:-${INPUT_CODEFENCE_API_URL:-https://api.codefence.io}}"

if [[ "$strict_mode" == "strict" ]]; then
  echo "Strict mode selected; full enforcement is handled by egress-strict.sh"
  exit 0
fi

check_url() {
  local url="$1"
  local label="$2"
  if curl -sfL --retry 2 --retry-delay 1 --connect-timeout 5 -A "codefence-egress-check/1.0" "$url" >/dev/null 2>&1; then
    echo "[ok] reachable: ${label} (${url})"
  else
    echo "::warning::[warn] unreachable: ${label} (${url})"
  fi
}

check_codefence_api() {
  local base="${api_url%/}"
  local health_url="${base}/health"
  local api_v1_url="${base}/api/v1"

  if curl -sfL --retry 2 --retry-delay 1 --connect-timeout 5 -A "codefence-egress-check/1.0" "$health_url" >/dev/null 2>&1; then
    echo "[ok] reachable: CodeFence API health (${health_url})"
    return 0
  fi

  if curl -sfL --retry 2 --retry-delay 1 --connect-timeout 5 -A "codefence-egress-check/1.0" "$api_v1_url" >/dev/null 2>&1; then
    echo "[ok] reachable: CodeFence API base (${api_v1_url})"
    return 0
  fi

  echo "::warning::[warn] unreachable: CodeFence API health/base (${health_url} | ${api_v1_url})"
}

check_url "https://api.github.com/meta" "GitHub meta API"
check_url "https://github.com" "GitHub"
check_codefence_api

echo "Egress validation (standard mode) complete"
