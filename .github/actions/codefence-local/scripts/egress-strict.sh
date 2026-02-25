#!/usr/bin/env bash
set -euo pipefail

strict_mode="${EGRESS_MODE:-${INPUT_EGRESS_MODE:-standard}}"
if [[ "$strict_mode" != "strict" ]]; then
  exit 0
fi

action_root="${GITHUB_ACTION_PATH:-$(cd "$(dirname "$0")/.." && pwd)}"
resolver_script="$action_root/dist/scripts/github-meta-resolver.js"

fatal() {
  echo "::error::FATAL: $1" >&2
  exit 1
}

log() {
  echo "[strict-egress] $1"
}

# 1) Linux only
[[ "$(uname -s)" == "Linux" ]] || fatal "Strict egress requires Linux"

# 2) Self-hosted only
if [[ "${RUNNER_ENVIRONMENT:-}" == "github-hosted" ]] || [[ -f /etc/github-hosted ]]; then
  fatal "Strict egress requires self-hosted runner"
fi

# 3) nftables required
command -v nft >/dev/null 2>&1 || fatal "nftables required for strict egress (iptables-only not accepted)"

# 4) nft inet family required
nft list tables inet >/dev/null 2>&1 || fatal "nft inet family not available"

# 5) CAP_NET_ADMIN check
if ! nft list ruleset >/dev/null 2>&1; then
  fatal "CAP_NET_ADMIN required"
fi

# 6) Resolver validation (private ranges only unless explicitly overridden)
allowed_resolvers=""
if [[ -n "${STRICT_DNS_RESOLVERS:-${INPUT_STRICT_DNS_RESOLVERS:-}}" ]]; then
  allowed_resolvers="$(echo "${STRICT_DNS_RESOLVERS:-${INPUT_STRICT_DNS_RESOLVERS:-}}" | tr ',' ' ')"
else
  while IFS= read -r line; do
    if [[ "$line" =~ ^nameserver[[:space:]]+(.+)$ ]]; then
      resolver="${BASH_REMATCH[1]}"
      if [[ "$resolver" =~ ^10\. ]] || [[ "$resolver" =~ ^192\.168\. ]] || [[ "$resolver" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] || [[ "$resolver" =~ ^127\. ]] || [[ "$resolver" =~ ^::1$ ]] || [[ "$resolver" =~ ^fd[0-9a-fA-F]{2}: ]] || [[ "$resolver" =~ ^fe80: ]]; then
        allowed_resolvers+=" ${resolver}"
      else
        fatal "Resolver not in private/VPC range: ${resolver}. Configure STRICT_DNS_RESOLVERS."
      fi
    fi
  done < /etc/resolv.conf
fi

allowed_resolvers="$(echo "$allowed_resolvers" | xargs || true)"
[[ -n "$allowed_resolvers" ]] || fatal "No valid DNS resolvers found for strict mode"

# 7) Fetch GitHub meta CIDRs fail-closed
if [[ ! -f "$resolver_script" ]]; then
  npm ci --prefix "$action_root"
  npm run build --prefix "$action_root"
fi

meta_json="$($resolver_script --format=json)" || fatal "Cannot fetch GitHub meta API (fail-closed)"
actions_count="$(echo "$meta_json" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); process.stdout.write(String((d.actions||[]).length));")"
[[ "$actions_count" != "0" ]] || fatal "GitHub meta API returned empty actions CIDR list"

api_url="${CODEFENCE_API_URL:-${INPUT_CODEFENCE_API_URL:-https://api.codefence.io}}"
api_host="$(echo "$api_url" | sed -E 's#^https?://##' | cut -d/ -f1)"
api_ips="$(getent ahosts "$api_host" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')"
[[ -n "$api_ips" ]] || fatal "Unable to resolve CodeFence API host: ${api_host}"

# Build nft ruleset.
table_name="codefence_egress"
nft delete table inet "$table_name" >/dev/null 2>&1 || true

rules_file="$(mktemp)"
{
  echo "table inet ${table_name} {"
  echo "  chain output {"
  echo "    type filter hook output priority 0; policy drop;"
  echo "    ct state established,related accept"
  echo "    oif \"lo\" accept"

  for resolver in $allowed_resolvers; do
    if [[ "$resolver" == *:* ]]; then
      echo "    ip6 daddr $resolver meta l4proto { udp, tcp } th dport 53 accept"
    else
      echo "    ip daddr $resolver meta l4proto { udp, tcp } th dport 53 accept"
    fi
  done

  echo "$meta_json" | node -e '
const fs=require("fs");
const meta=JSON.parse(fs.readFileSync(0,"utf8"));
for (const key of ["api","git","actions"]) {
  for (const cidr of (meta[key]||[])) {
    if (cidr.includes(":")) {
      console.log(`    ip6 daddr ${cidr} tcp dport 443 accept`);
    } else {
      console.log(`    ip daddr ${cidr} tcp dport 443 accept`);
    }
  }
}
'

  for ip in $api_ips; do
    if [[ "$ip" == *:* ]]; then
      echo "    ip6 daddr $ip tcp dport 443 accept"
    else
      echo "    ip daddr $ip tcp dport 443 accept"
    fi
  done

  echo "  }"
  echo "}"
} > "$rules_file"

nft -f "$rules_file" || fatal "Failed to apply strict nftables rules"

# Post-apply verification
curl -sf --connect-timeout 4 https://api.github.com >/dev/null || fatal "Allowed endpoint api.github.com unreachable"
curl -sf --connect-timeout 4 "$api_url" >/dev/null || fatal "Allowed endpoint CodeFence API unreachable"

if curl -sf --connect-timeout 4 https://pypi.org >/dev/null 2>&1; then
  fatal "Post-apply verification failed: pypi.org still reachable over IPv4"
fi
if curl -6 -sf --connect-timeout 4 https://pypi.org >/dev/null 2>&1; then
  fatal "Post-apply verification failed: pypi.org still reachable over IPv6"
fi

if dig @8.8.8.8 example.com +short >/dev/null 2>&1; then
  fatal "Public resolver 8.8.8.8 should be blocked (UDP)"
fi
if dig +tcp @8.8.8.8 example.com +short >/dev/null 2>&1; then
  fatal "Public resolver 8.8.8.8 should be blocked (TCP)"
fi

first_resolver="$(echo "$allowed_resolvers" | awk '{print $1}')"
dig @"$first_resolver" api.github.com +short >/dev/null 2>&1 || fatal "Allowed resolver check failed"

log "Strict egress policy applied with nft inet dual-stack + DNS restriction"
