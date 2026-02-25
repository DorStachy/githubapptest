#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v semgrep &>/dev/null; then
  echo "ERROR: semgrep not found. Install: pip install semgrep==1.67.0"
  exit 1
fi

echo "==> Validating Semgrep rules..."
semgrep --validate --config configs/semgrep-rules.yml
echo "    Semgrep rules valid"
