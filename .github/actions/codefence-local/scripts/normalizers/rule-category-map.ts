const EXACT_RULE_MAP: Record<string, string> = {
  // SAST
  'codeql:js/sql-injection': 'sql-injection',
  'codeql:python/sql-injection': 'sql-injection',
  'semgrep:javascript.lang.security.audit.sql-injection': 'sql-injection',
  'semgrep:python.lang.security.audit.sql-injection': 'sql-injection',
  'semgrep:javascript.lang.security.audit.xss': 'xss',
  'semgrep:codefence.javascript.sql-injection.concat': 'sql-injection',
  'semgrep:codefence.javascript.sql-injection.template-literal': 'sql-injection',
  'semgrep:codefence.javascript.logging.password-exposure': 'sensitive-data-exposure',
  'semgrep:codefence.javascript.unsafe-jwt-decode': 'broken-authentication',
  'semgrep:codefence.javascript.idor.direct-object-reference': 'idor',
  'semgrep:codefence.javascript.missing-admin-authorization': 'broken-access-control',
  'semgrep:codefence.javascript.unrestricted-file-upload': 'unrestricted-file-upload',
  'semgrep:codefence.javascript.open-redirect': 'open-redirect',
  'semgrep:codefence.javascript.prototype-pollution-merge': 'prototype-pollution',
  'semgrep:codefence.javascript.ssrf.user-controlled-url': 'ssrf',
  'semgrep:codefence.javascript.ssrf.untrusted-url-argument': 'ssrf',
  'semgrep:codefence.javascript.insecure-random-token': 'weak-randomness',
  'semgrep:codefence.javascript.predictable-tempfile': 'insecure-temp-file',
  'semgrep:codefence.javascript.dynamic-function-execution': 'code-injection',
  'bandit:B602': 'command-injection',
  'bandit:B607': 'command-injection',

  // Secrets
  'gitleaks:generic-api-key': 'hardcoded-secret',
  'gitleaks:aws-access-key-id': 'hardcoded-secret',

  // Actions
  'actionlint:unpinned-action': 'unpinned-action',
  'zizmor:unpinned-action': 'unpinned-action',
  'zizmor:dangerous-trigger': 'dangerous-trigger',

  // CI Agent Guardrails
  'ci-agent-guardrails:ci-guardrails/untrusted-input-in-run': 'untrusted-input-injection',
  'ci-agent-guardrails:ci-guardrails/untrusted-input-in-agent-prompt': 'prompt-injection',
  'ci-agent-guardrails:ci-guardrails/expression-in-run-step': 'untrusted-input-injection',
  'ci-agent-guardrails:ci-guardrails/secrets-in-low-trust-trigger': 'secrets-segmentation',
  'ci-agent-guardrails:ci-guardrails/publish-secret-without-environment': 'secrets-segmentation',
  'ci-agent-guardrails:ci-guardrails/broad-permissions-with-secrets': 'excessive-permissions',
  'ci-agent-guardrails:ci-guardrails/cache-poisoning-risk': 'cache-artifact-isolation',
  'ci-agent-guardrails:ci-guardrails/artifact-injection-risk': 'cache-artifact-isolation',
  'ci-agent-guardrails:ci-guardrails/writable-cache-from-pr': 'cache-artifact-isolation',

  // SCA
  'osv-scanner:CVE': 'known-cve',
  'pip-audit:CVE': 'known-cve',

  // IaC / Container
  'checkov:CKV_K8S_': 'privileged-container',
  'checkov:CKV_DOCKER_': 'dockerfile-weakness',
  'trivy:VULN': 'known-cve',
};

function fuzzyCategoryByRuleId(toolName: string, ruleId: string): string {
  const normalizedTool = toolName.toLowerCase();
  const normalizedRule = ruleId.toLowerCase();

  if (normalizedRule.includes('sql') || normalizedRule.includes('sqli')) {
    return 'sql-injection';
  }
  if (normalizedRule.includes('xss')) {
    return 'xss';
  }
  if (normalizedRule.includes('idor')) {
    return 'idor';
  }
  if (normalizedRule.includes('authz') || normalizedRule.includes('authorization')) {
    return 'broken-access-control';
  }
  if (normalizedRule.includes('jwt') || normalizedRule.includes('authentication')) {
    return 'broken-authentication';
  }
  if (normalizedRule.includes('ssrf')) {
    return 'ssrf';
  }
  if (normalizedRule.includes('redirect')) {
    return 'open-redirect';
  }
  if (normalizedRule.includes('prototype')) {
    return 'prototype-pollution';
  }
  if (normalizedRule.includes('upload')) {
    return 'unrestricted-file-upload';
  }
  if (normalizedRule.includes('password') || normalizedRule.includes('sensitive')) {
    return 'sensitive-data-exposure';
  }
  if (normalizedRule.includes('random') || normalizedRule.includes('token')) {
    return 'weak-randomness';
  }
  if (normalizedRule.includes('temp') || normalizedRule.includes('/tmp')) {
    return 'insecure-temp-file';
  }
  if (normalizedRule.includes('function') || normalizedRule.includes('eval')) {
    return 'code-injection';
  }
  if (normalizedRule.includes('command') || normalizedRule.includes('shell')) {
    return 'command-injection';
  }
  if (normalizedRule.includes('secret') || normalizedRule.includes('token')) {
    return 'hardcoded-secret';
  }
  if (normalizedRule.includes('cve-') || normalizedRule.startsWith('cve')) {
    return 'known-cve';
  }
  if (normalizedRule.includes('action') && normalizedRule.includes('unpinned')) {
    return 'unpinned-action';
  }
  if (normalizedRule.includes('terraform') || normalizedRule.startsWith('ckv_')) {
    return 'iac-misconfiguration';
  }
  if (normalizedRule.includes('docker') || normalizedRule.includes('container')) {
    return 'privileged-container';
  }

  if (normalizedTool === 'gitleaks') {
    return 'hardcoded-secret';
  }
  if (normalizedTool === 'osv-scanner' || normalizedTool === 'pip-audit') {
    return 'known-cve';
  }

  return 'security-issue';
}

export function resolveNormalizedRuleCategory(toolName: string, ruleId: string): string {
  const key = `${toolName.toLowerCase()}:${ruleId}`;
  if (EXACT_RULE_MAP[key]) {
    return EXACT_RULE_MAP[key];
  }

  const prefixedKey = Object.keys(EXACT_RULE_MAP).find((candidate) =>
    key.startsWith(candidate.toLowerCase()),
  );
  if (prefixedKey) {
    return EXACT_RULE_MAP[prefixedKey];
  }

  return fuzzyCategoryByRuleId(toolName, ruleId);
}

export function registerRuleCategory(key: string, category: string): void {
  EXACT_RULE_MAP[key.toLowerCase()] = category;
}

export function getRuleCategoryMap(): Record<string, string> {
  return { ...EXACT_RULE_MAP };
}
