#!/usr/bin/env bash
set -euo pipefail

event_path="${GITHUB_EVENT_PATH:-}"
api_key="${CODEFENCE_API_KEY:-${INPUT_API_KEY:-}}"
fork_mode="${INPUT_FORK_MODE:-summary-only}"

is_fork="false"
strategy="summary-only"

if [[ -n "$event_path" && -f "$event_path" ]]; then
  head_repo_full_name="$(node -e "const fs=require('fs');const e=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));const v=e.pull_request?.head?.repo?.full_name||'';process.stdout.write(v);" "$event_path")"
  base_repo_full_name="${GITHUB_REPOSITORY:-}"
  head_is_fork="$(node -e "const fs=require('fs');const e=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));process.stdout.write(String(Boolean(e.pull_request?.head?.repo?.fork)));" "$event_path")"

  if [[ "$head_is_fork" == "true" ]] || [[ -n "$head_repo_full_name" && "$head_repo_full_name" != "$base_repo_full_name" ]]; then
    is_fork="true"
  fi
fi

if [[ "$is_fork" == "true" && -z "$api_key" ]]; then
  if [[ "$fork_mode" == "artifact-relay" ]]; then
    strategy="artifact-relay"
  else
    strategy="summary-only"
  fi
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "fork=${is_fork}"
    echo "strategy=${strategy}"
  } >> "$GITHUB_OUTPUT"
fi

echo "fork=${is_fork}"
echo "strategy=${strategy}"
