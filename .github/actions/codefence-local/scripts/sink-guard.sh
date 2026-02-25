#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: sink-guard.sh <input-json> <output-json>" >&2
  exit 2
fi

input_json="$1"
output_json="$2"
action_root="${GITHUB_ACTION_PATH:-$(cd "$(dirname "$0")/.." && pwd)}"

if [[ ! -f "$input_json" ]]; then
  echo "::error::Input JSON not found: $input_json" >&2
  exit 1
fi

if [[ -f "$action_root/dist/scripts/redact-secrets.js" ]]; then
  node "$action_root/dist/scripts/redact-secrets.js" --input="$input_json" --output="$output_json"
else
  npm ci --prefix "$action_root"
  npm run build --prefix "$action_root"
  node "$action_root/dist/scripts/redact-secrets.js" --input="$input_json" --output="$output_json"
fi

echo "Sink Guard redaction complete: $output_json"
