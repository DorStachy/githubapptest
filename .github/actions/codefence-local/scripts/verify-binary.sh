#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: verify-binary.sh <binary-path> <artifact-name> [checksums-file]" >&2
  exit 2
fi

binary_path="$1"
artifact_name="$2"
checksums_file="${3:-$(dirname "$0")/../configs/checksums.sha256}"

if [[ ! -f "$binary_path" ]]; then
  echo "::error::Binary not found: $binary_path" >&2
  exit 1
fi

if [[ ! -f "$checksums_file" ]]; then
  echo "::error::Checksums file not found: $checksums_file" >&2
  exit 1
fi

expected_line="$(grep -E "[[:space:]]${artifact_name}$" "$checksums_file" || true)"
if [[ -z "$expected_line" ]]; then
  echo "::error::No checksum entry found for $artifact_name" >&2
  exit 1
fi

expected_hash="$(echo "$expected_line" | awk '{print $1}')"
actual_hash="$(sha256sum "$binary_path" | awk '{print $1}')"

if [[ "$expected_hash" != "$actual_hash" ]]; then
  echo "::error::Checksum mismatch for $artifact_name" >&2
  echo "expected=$expected_hash actual=$actual_hash" >&2
  exit 1
fi

echo "Checksum OK for $artifact_name"
