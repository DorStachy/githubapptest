import * as fs from 'fs';
import * as path from 'path';
import {
  FindingCategory,
  FindingConfidence,
  FindingSeverity,
  NormalizedFinding,
  fingerprintForPrimary,
  fingerprintForTool,
} from './types';
import { parseKeyValueArgs, safeNumber } from './utils';
import { resolveNormalizedRuleCategory } from './normalizers/rule-category-map';
import { stripWorkspacePrefix } from './path-utils';

interface NormalizeOptions {
  toolName: string;
  toolVersion?: string;
  repoRoot?: string;
}

function normalizeSeverity(value: unknown): FindingSeverity {
  const normalized = String(value || '').toUpperCase();
  if (normalized.includes('CRITICAL')) return 'CRITICAL';
  if (normalized.includes('HIGH')) return 'HIGH';
  if (normalized.includes('MEDIUM')) return 'MEDIUM';
  if (normalized.includes('LOW')) return 'LOW';
  if (normalized.includes('INFO')) return 'INFO';
  if (normalized.includes('ERROR')) return 'HIGH';
  if (normalized.includes('WARNING')) return 'MEDIUM';
  return 'MEDIUM';
}

function normalizeConfidence(value: unknown): FindingConfidence {
  const normalized = String(value || '').toUpperCase();
  if (normalized.includes('HIGH')) return 'HIGH';
  if (normalized.includes('LOW')) return 'LOW';
  return 'MEDIUM';
}

function inferCategory(toolName: string): FindingCategory {
  const normalized = toolName.toLowerCase();
  if (normalized.includes('gitleaks')) return 'SECRETS';
  if (normalized.includes('actionlint') || normalized.includes('zizmor') || normalized.includes('ci-agent-guardrails')) return 'ACTIONS';
  if (normalized.includes('checkov')) return 'IAC';
  if (normalized.includes('trivy')) return 'CONTAINER';
  if (normalized.includes('scorecard')) return 'POSTURE';
  if (normalized.includes('osv') || normalized.includes('pip-audit')) return 'SCA';
  return 'SAST';
}

function baseFinding(input: {
  toolName: string;
  toolVersion?: string;
  category: FindingCategory;
  ruleId: string;
  filePath: string;
  startLine: number;
  endLine: number;
  title: string;
  description?: string | null;
  severity: FindingSeverity;
  confidence?: FindingConfidence;
  snippet?: string | null;
  remediationSummary?: string | null;
  patchSuggestion?: string | null;
  ideFixPrompt?: string | null;
  references?: string[];
  repoRoot?: string;
}): NormalizedFinding {
  const cleanPath = stripWorkspacePrefix(input.filePath, input.repoRoot);
  const normalizedRuleCategory = resolveNormalizedRuleCategory(input.toolName, input.ruleId);
  const primaryFingerprint = fingerprintForPrimary(
    input.category,
    normalizedRuleCategory,
    cleanPath,
    input.startLine,
    input.endLine,
  );
  const toolFingerprint = fingerprintForTool(
    input.toolName,
    input.ruleId,
    cleanPath,
    input.startLine,
    input.endLine,
  );

  return {
    fingerprint: primaryFingerprint,
    primaryFingerprint,
    toolFingerprint,
    category: input.category,
    severity: input.severity,
    confidence: input.confidence || 'MEDIUM',
    title: input.title.slice(0, 256),
    description: input.description?.slice(0, 2000) || null,
    filePath: cleanPath,
    startLine: input.startLine,
    endLine: input.endLine,
    snippet: input.snippet || null,
    diffContext: null,
    remediationSummary: input.remediationSummary?.slice(0, 2000) || null,
    patchSuggestion: input.patchSuggestion?.slice(0, 3000) || null,
    ideFixPrompt: input.ideFixPrompt?.slice(0, 500) || null,
    references: (input.references || []).slice(0, 100),
    toolName: input.toolName,
    toolVersion: input.toolVersion || null,
    ruleId: input.ruleId.slice(0, 128),
    normalizedRuleCategory: normalizedRuleCategory.slice(0, 128),
  };
}

function normalizeGitleaks(payload: unknown, options: NormalizeOptions): NormalizedFinding[] {
  if (!Array.isArray(payload)) {
    return [];
  }

  return payload.map((entry: any) =>
    baseFinding({
      toolName: options.toolName,
      toolVersion: options.toolVersion,
      category: 'SECRETS',
      ruleId: entry.RuleID || 'gitleaks-rule',
      filePath: entry.File || 'unknown',
      startLine: safeNumber(entry.StartLine, 1),
      endLine: safeNumber(entry.EndLine, safeNumber(entry.StartLine, 1)),
      title: entry.Description || entry.RuleID || 'Secret detected',
      description: entry.Description || entry.Match || null,
      severity: 'CRITICAL',
      confidence: 'HIGH',
      snippet: entry.Match || null,
      remediationSummary: 'Remove hardcoded secret and rotate compromised credentials.',
      references: [],
      repoRoot: options.repoRoot,
    }),
  );
}

function normalizeBandit(payload: any, options: NormalizeOptions): NormalizedFinding[] {
  const results = Array.isArray(payload?.results) ? payload.results : [];
  return results.map((entry: any) => {
    const line = safeNumber(entry.line_number, 1);
    return baseFinding({
      toolName: options.toolName,
      toolVersion: options.toolVersion,
      category: 'SAST',
      ruleId: entry.test_id || 'bandit-rule',
      filePath: entry.filename || 'unknown',
      startLine: line,
      endLine: line,
      title: entry.test_name || entry.test_id || 'Bandit finding',
      description: entry.issue_text || null,
      severity: normalizeSeverity(entry.issue_severity),
      confidence: normalizeConfidence(entry.issue_confidence),
      snippet: entry.code || null,
      remediationSummary: 'Review this Python pattern and replace unsafe calls with validated alternatives.',
      references: [entry.more_info].filter(Boolean),
      repoRoot: options.repoRoot,
    });
  });
}

function normalizeOsv(payload: any, options: NormalizeOptions): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];
  const results = Array.isArray(payload?.results) ? payload.results : [];

  for (const result of results) {
    const packages = Array.isArray(result?.packages) ? result.packages : [];
    for (const pkgEntry of packages) {
      const pkg = pkgEntry.package || {};
      const vulns = Array.isArray(pkgEntry.vulnerabilities)
        ? pkgEntry.vulnerabilities
        : Array.isArray(pkgEntry.vulns)
          ? pkgEntry.vulns
          : [];
      for (const vuln of vulns) {
        const cve = vuln.id || vuln.alias || 'CVE';
        findings.push(
          baseFinding({
            toolName: options.toolName,
            toolVersion: options.toolVersion,
            category: 'SCA',
            ruleId: cve,
            filePath: result.source?.path || pkg?.path || 'dependency',
            startLine: 1,
            endLine: 1,
            title: `${pkg.name || 'dependency'} vulnerable (${cve})`,
            description: vuln.summary || vuln.details || null,
            severity: normalizeSeverity(vuln.severity || 'HIGH'),
            confidence: 'HIGH',
            remediationSummary:
              vuln.fixed_version || vuln.fixedVersion
                ? `Upgrade to ${vuln.fixed_version || vuln.fixedVersion}.`
                : 'Upgrade dependency to a patched version.',
            references: [vuln.database_specific?.url, vuln.reference].filter(Boolean),
            repoRoot: options.repoRoot,
          }),
        );
      }
    }
  }

  return findings;
}

function normalizePipAudit(payload: any, options: NormalizeOptions): NormalizedFinding[] {
  const dependencies = Array.isArray(payload?.dependencies) ? payload.dependencies : [];
  const findings: NormalizedFinding[] = [];

  for (const dep of dependencies) {
    const vulns = Array.isArray(dep?.vulns) ? dep.vulns : [];
    for (const vuln of vulns) {
      findings.push(
        baseFinding({
          toolName: options.toolName,
          toolVersion: options.toolVersion,
          category: 'SCA',
          ruleId: vuln.id || 'CVE',
          filePath: dep.path || 'requirements.txt',
          startLine: 1,
          endLine: 1,
          title: `${dep.name}@${dep.version} vulnerable (${vuln.id || 'CVE'})`,
          description: vuln.description || vuln.fix_versions?.join(', ') || null,
          severity: normalizeSeverity(vuln.severity || 'HIGH'),
          confidence: 'HIGH',
          remediationSummary:
            Array.isArray(vuln.fix_versions) && vuln.fix_versions.length > 0
              ? `Upgrade to one of: ${vuln.fix_versions.join(', ')}`
              : 'Upgrade dependency to a non-vulnerable version.',
          references: [vuln.link].filter(Boolean),
          repoRoot: options.repoRoot,
        }),
      );
    }
  }

  return findings;
}

function normalizeTrivy(payload: any, options: NormalizeOptions): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];
  const results = Array.isArray(payload?.Results) ? payload.Results : [];

  for (const result of results) {
    const target = result.Target || 'container';

    for (const vuln of Array.isArray(result.Vulnerabilities) ? result.Vulnerabilities : []) {
      findings.push(
        baseFinding({
          toolName: options.toolName,
          toolVersion: options.toolVersion,
          category: 'CONTAINER',
          ruleId: vuln.VulnerabilityID || 'TRIVY-VULN',
          filePath: target,
          startLine: 1,
          endLine: 1,
          title: vuln.Title || `${vuln.PkgName} vulnerable dependency`,
          description: vuln.Description || null,
          severity: normalizeSeverity(vuln.Severity),
          confidence: 'HIGH',
          remediationSummary:
            vuln.FixedVersion
              ? `Upgrade ${vuln.PkgName} to ${vuln.FixedVersion}.`
              : 'Apply vendor patch or update base image.',
          references: [vuln.PrimaryURL].filter(Boolean),
          repoRoot: options.repoRoot,
        }),
      );
    }

    for (const misconfig of Array.isArray(result.Misconfigurations)
      ? result.Misconfigurations
      : []) {
      findings.push(
        baseFinding({
          toolName: options.toolName,
          toolVersion: options.toolVersion,
          category: 'IAC',
          ruleId: misconfig.ID || 'TRIVY-MISCONFIG',
          filePath: misconfig.CauseMetadata?.Filename || target,
          startLine: safeNumber(misconfig.CauseMetadata?.StartLine, 1),
          endLine: safeNumber(
            misconfig.CauseMetadata?.EndLine,
            safeNumber(misconfig.CauseMetadata?.StartLine, 1),
          ),
          title: misconfig.Title || misconfig.ID || 'Infrastructure misconfiguration',
          description: misconfig.Description || null,
          severity: normalizeSeverity(misconfig.Severity),
          confidence: 'MEDIUM',
          remediationSummary: misconfig.Resolution || 'Apply secure infrastructure settings.',
          references: [misconfig.PrimaryURL].filter(Boolean),
          repoRoot: options.repoRoot,
        }),
      );
    }
  }

  return findings;
}

// ── Actionlint top-rule fix templates ──────────────────────────────
const ACTIONLINT_FIX_TEMPLATES: Record<string, { patchSuggestion: string; ideFixPrompt: string }> = {
  'expression': {
    patchSuggestion: '-  run: echo ${{ github.event.pull_request.title }}\n+  run: echo "$TITLE"\n+  env:\n+    TITLE: ${{ github.event.pull_request.title }}',
    ideFixPrompt: 'Move the expression into an env block to avoid script injection.',
  },
  'shellcheck': {
    patchSuggestion: '-  run: echo $MY_VAR\n+  run: echo "$MY_VAR"',
    ideFixPrompt: 'Quote shell variables to prevent word-splitting and globbing.',
  },
  'deprecated-commands': {
    patchSuggestion: '-  run: echo "::set-output name=result::$val"\n+  run: echo "result=$val" >> "$GITHUB_OUTPUT"',
    ideFixPrompt: 'Replace deprecated set-output with GITHUB_OUTPUT.',
  },
  'permissions': {
    patchSuggestion: '+permissions:\n+  contents: read',
    ideFixPrompt: 'Add explicit least-privilege permissions at workflow or job level.',
  },
  'events': {
    patchSuggestion: '',
    ideFixPrompt: 'Fix the event trigger configuration per actionlint documentation.',
  },
  'syntax-check': {
    patchSuggestion: '',
    ideFixPrompt: 'Fix YAML syntax errors in the workflow file.',
  },
  'glob': {
    patchSuggestion: '',
    ideFixPrompt: 'Fix glob pattern syntax in paths/paths-ignore filters.',
  },
  'runner-label': {
    patchSuggestion: "-  runs-on: ubuntu-18.04\n+  runs-on: ubuntu-latest",
    ideFixPrompt: 'Use a valid/supported runner label (e.g. ubuntu-latest, windows-latest).',
  },
  'action': {
    patchSuggestion: '',
    ideFixPrompt: 'Check action input names and required fields match the action definition.',
  },
  'credentials': {
    patchSuggestion: '-  password: my-token\n+  password: ${{ secrets.GHCR_TOKEN }}',
    ideFixPrompt: 'Use secrets instead of hardcoded credentials in container registry auth.',
  },
};

function getActionlintFixGuidance(
  ruleId: string,
  message?: string,
): { patchSuggestion: string | null; ideFixPrompt: string | null } {
  // Try exact match first, then keyword match
  const rule = ruleId.replace('actionlint-', '').replace('actionlint/', '');
  if (ACTIONLINT_FIX_TEMPLATES[rule]) {
    const t = ACTIONLINT_FIX_TEMPLATES[rule];
    return { patchSuggestion: t.patchSuggestion || null, ideFixPrompt: t.ideFixPrompt };
  }
  // Fallback: check if message contains known keywords
  const msg = (message || '').toLowerCase();
  if (msg.includes('shellcheck')) return getActionlintFixGuidance('shellcheck');
  if (msg.includes('deprecated')) return getActionlintFixGuidance('deprecated-commands');
  if (msg.includes('permission')) return getActionlintFixGuidance('permissions');
  if (msg.includes('expression')) return getActionlintFixGuidance('expression');
  return { patchSuggestion: null, ideFixPrompt: null };
}

// ── Zizmor top-rule fix templates ──────────────────────────────────
const ZIZMOR_FIX_TEMPLATES: Record<string, { patchSuggestion: string; ideFixPrompt: string }> = {
  'unpinned-uses': {
    patchSuggestion: '-  uses: actions/checkout@v4\n+  uses: actions/checkout@<full-sha>   # pin to commit SHA',
    ideFixPrompt: 'Pin action references to full commit SHAs instead of mutable tags.',
  },
  'template-injection': {
    patchSuggestion: '-  run: echo ${{ github.event.pull_request.title }}\n+  run: echo "$TITLE"\n+  env:\n+    TITLE: ${{ github.event.pull_request.title }}',
    ideFixPrompt: 'Move untrusted expressions into env vars to prevent template injection.',
  },
  'excessive-permissions': {
    patchSuggestion: '-permissions: write-all\n+permissions:\n+  contents: read',
    ideFixPrompt: 'Reduce permissions to least-privilege using explicit read-only scopes.',
  },
  'dangerous-triggers': {
    patchSuggestion: '-on: pull_request_target\n+on: pull_request',
    ideFixPrompt: 'Replace dangerous triggers (pull_request_target) with safer alternatives.',
  },
  'artipacked': {
    patchSuggestion: '+  - uses: actions/checkout@v4\n+    with:\n+      persist-credentials: false',
    ideFixPrompt: 'Set persist-credentials: false to avoid leaking tokens in uploaded artifacts.',
  },
  'known-vulnerability': {
    patchSuggestion: '-  uses: actions/example@vulnerable-version\n+  uses: actions/example@fixed-version',
    ideFixPrompt: 'Update the action to a version that patches the known vulnerability.',
  },
  'ref-confusion': {
    patchSuggestion: '-  uses: owner/repo@main\n+  uses: owner/repo@<full-sha>',
    ideFixPrompt: 'Pin to full SHA to avoid ref confusion between branches and tags.',
  },
  'self-hosted-runner': {
    patchSuggestion: '',
    ideFixPrompt: 'Review self-hosted runner security: restrict to private repos, rotate credentials.',
  },
  'github-env': {
    patchSuggestion: '-  run: echo "PATH=$HOME/bin:$PATH" >> $GITHUB_ENV\n+  # Avoid writing attacker-controlled data to GITHUB_ENV',
    ideFixPrompt: 'Avoid writing untrusted input to GITHUB_ENV which can alter the runner environment.',
  },
  'bot-conditions': {
    patchSuggestion: "+    if: github.actor != 'dependabot[bot]'",
    ideFixPrompt: 'Add actor-check conditions before granting elevated permissions to bot-triggered runs.',
  },
};

function getZizmorFixGuidance(
  ruleId: string,
): { patchSuggestion: string | null; ideFixPrompt: string | null } {
  const rule = ruleId.replace('zizmor/', '').replace('zizmor-', '');
  const t = ZIZMOR_FIX_TEMPLATES[rule];
  if (t) {
    return { patchSuggestion: t.patchSuggestion || null, ideFixPrompt: t.ideFixPrompt };
  }
  return { patchSuggestion: null, ideFixPrompt: null };
}

function normalizeActionlint(payload: any, options: NormalizeOptions): NormalizedFinding[] {
  const entries = Array.isArray(payload) ? payload : Array.isArray(payload?.findings) ? payload.findings : [];

  return entries.map((entry: any) => {
    const line = safeNumber(entry.line || entry.lineNumber, 1);
    const ruleId = entry.ruleId || entry.rule || 'actionlint-rule';
    const { patchSuggestion, ideFixPrompt } = getActionlintFixGuidance(ruleId, entry.message);
    return baseFinding({
      toolName: options.toolName,
      toolVersion: options.toolVersion,
      category: 'ACTIONS',
      ruleId,
      filePath: entry.filepath || entry.file || '.github/workflows/workflow.yml',
      startLine: line,
      endLine: line,
      title: entry.message || 'GitHub Actions issue',
      description: entry.message || null,
      severity: normalizeSeverity(entry.severity || 'MEDIUM'),
      confidence: 'HIGH',
      remediationSummary: 'Update workflow configuration according to actionlint recommendation.',
      patchSuggestion,
      ideFixPrompt,
      references: [],
      repoRoot: options.repoRoot,
    });
  });
}

function normalizeZizmor(payload: any, options: NormalizeOptions): NormalizedFinding[] {
  const entries = Array.isArray(payload?.findings)
    ? payload.findings
    : Array.isArray(payload)
      ? payload
      : [];

  return entries.map((entry: any) => {
    const line = safeNumber(entry.start_line || entry.line || 1, 1);
    const ruleId = entry.rule_id || entry.rule || 'zizmor-rule';
    const { patchSuggestion, ideFixPrompt } = getZizmorFixGuidance(ruleId);
    return baseFinding({
      toolName: options.toolName,
      toolVersion: options.toolVersion,
      category: 'ACTIONS',
      ruleId,
      filePath: entry.path || entry.file || '.github/workflows/workflow.yml',
      startLine: line,
      endLine: safeNumber(entry.end_line || line, line),
      title: entry.message || entry.title || 'GitHub Actions security issue',
      description: entry.description || null,
      severity: normalizeSeverity(entry.severity || 'MEDIUM'),
      confidence: normalizeConfidence(entry.confidence || 'HIGH'),
      remediationSummary: 'Apply secure workflow patterns and least-privilege permissions.',
      patchSuggestion,
      ideFixPrompt,
      references: [entry.url].filter(Boolean),
      repoRoot: options.repoRoot,
    });
  });
}

function normalizeScorecard(payload: any, options: NormalizeOptions): NormalizedFinding[] {
  const checks = Array.isArray(payload?.checks) ? payload.checks : [];
  const findings: NormalizedFinding[] = [];

  for (const check of checks) {
    const score = Number(check.score ?? 10);
    if (!Number.isFinite(score) || score >= 7) {
      continue;
    }

    findings.push(
      baseFinding({
        toolName: options.toolName,
        toolVersion: options.toolVersion,
        category: 'POSTURE',
        ruleId: `scorecard:${check.name || 'check'}`,
        filePath: 'repository',
        startLine: 1,
        endLine: 1,
        title: `${check.name || 'Scorecard check'} score is below threshold`,
        description: check.reason || check.details || null,
        severity: score <= 3 ? 'HIGH' : 'MEDIUM',
        confidence: 'MEDIUM',
        remediationSummary: 'Harden repository security controls to improve scorecard posture.',
        references: [],
        repoRoot: options.repoRoot,
      }),
    );
  }

  return findings;
}

/**
 * @deprecated Checkov output is normalized via SARIF (normalize-sarif.ts).
 * This JSON fallback is retained for potential future use but is currently unreachable.
 * TODO: Remove if not needed by Phase 5.
 */
function normalizeCheckov(payload: any, options: NormalizeOptions): NormalizedFinding[] {
  const failedChecks = Array.isArray(payload?.results?.failed_checks)
    ? payload.results.failed_checks
    : [];

  return failedChecks.map((entry: any) => {
    const line = safeNumber(entry.file_line_range?.[0], 1);
    return baseFinding({
      toolName: options.toolName,
      toolVersion: options.toolVersion,
      category: 'IAC',
      ruleId: entry.check_id || 'checkov-rule',
      filePath: entry.file_path || 'iac',
      startLine: line,
      endLine: safeNumber(entry.file_line_range?.[1], line),
      title: entry.check_name || entry.check_id || 'Checkov finding',
      description: entry.description || null,
      severity: normalizeSeverity(entry.severity || 'MEDIUM'),
      confidence: 'MEDIUM',
      snippet: typeof entry.code_block === 'string' ? entry.code_block : null,
      remediationSummary: entry.guideline || 'Apply secure IaC configuration.',
      references: [entry.guideline].filter(Boolean),
      repoRoot: options.repoRoot,
    });
  });
}

function normalizeCiAgentGuardrails(payload: any, options: NormalizeOptions): NormalizedFinding[] {
  const entries = Array.isArray(payload) ? payload : [];

  return entries.map((entry: any) => {
    const line = safeNumber(entry.startLine, 1);
    return baseFinding({
      toolName: options.toolName,
      toolVersion: options.toolVersion,
      category: 'ACTIONS',
      ruleId: entry.ruleId || 'ci-guardrails-rule',
      filePath: entry.filePath || '.github/workflows/workflow.yml',
      startLine: line,
      endLine: safeNumber(entry.endLine, line),
      title: entry.title || 'CI Agent Guardrails finding',
      description: entry.description || null,
      severity: normalizeSeverity(entry.severity || 'HIGH'),
      confidence: normalizeConfidence(entry.confidence || 'HIGH'),
      snippet: entry.snippet || null,
      remediationSummary: entry.remediationSummary || 'Review and sanitize untrusted input in workflow.',
      patchSuggestion: entry.patchSuggestion || null,
      ideFixPrompt: entry.ideFixPrompt || null,
      references: [],
      repoRoot: options.repoRoot,
    });
  });
}

export function normalizeJsonPayload(payload: unknown, options: NormalizeOptions): NormalizedFinding[] {
  const toolName = options.toolName.toLowerCase();

  if (toolName === 'gitleaks') return normalizeGitleaks(payload, options);
  if (toolName === 'bandit') return normalizeBandit(payload, options);
  if (toolName === 'osv-scanner' || toolName === 'osv') return normalizeOsv(payload, options);
  if (toolName === 'pip-audit') return normalizePipAudit(payload, options);
  if (toolName === 'trivy') return normalizeTrivy(payload, options);
  if (toolName === 'actionlint') return normalizeActionlint(payload, options);
  if (toolName === 'zizmor') return normalizeZizmor(payload, options);
  if (toolName === 'scorecard') return normalizeScorecard(payload, options);
  if (toolName === 'checkov') return normalizeCheckov(payload, options);
  if (toolName === 'ci-agent-guardrails') return normalizeCiAgentGuardrails(payload, options);

  const fallbackCategory = inferCategory(options.toolName);
  if (Array.isArray(payload)) {
    return payload.map((entry: any, index) =>
      baseFinding({
        toolName: options.toolName,
        toolVersion: options.toolVersion,
        category: fallbackCategory,
        ruleId: String(entry.ruleId || entry.id || `rule-${index}`),
        filePath: String(entry.filePath || entry.file || 'unknown'),
        startLine: safeNumber(entry.startLine || entry.line || 1),
        endLine: safeNumber(entry.endLine || entry.line || entry.startLine || 1),
        title: String(entry.title || entry.message || 'Security finding'),
        description: entry.description || entry.message || null,
        severity: normalizeSeverity(entry.severity || 'MEDIUM'),
        confidence: normalizeConfidence(entry.confidence || 'MEDIUM'),
        snippet: entry.snippet || null,
        remediationSummary: entry.remediationSummary || null,
        references: Array.isArray(entry.references) ? entry.references : [],
        repoRoot: options.repoRoot,
      }),
    );
  }

  return [];
}

export function normalizeJsonFile(filePath: string, options: NormalizeOptions): NormalizedFinding[] {
  const raw = fs.readFileSync(filePath, 'utf8').trim();
  if (raw.length === 0) {
    process.stderr.write(
      `[warn] Skipping empty JSON file from ${options.toolName}: ${filePath}\n`,
    );
    return [];
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    process.stderr.write(
      `[warn] Invalid JSON from ${options.toolName} (${filePath}): ${
        err instanceof Error ? err.message : String(err)
      }\n`,
    );
    return [];
  }
  return normalizeJsonPayload(parsed, options);
}

function runCli(): void {
  const args = parseKeyValueArgs(process.argv.slice(2));
  const input = args.input;
  const output = args.output;
  const tool = args.tool;

  if (!input || !output || !tool) {
    throw new Error(
      'Usage: normalize-json.ts --tool=<tool> --input=<file1,file2> --output=<out-file> [--tool-version=<version>]',
    );
  }

  const files = input
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => path.resolve(item));

  const findings = files.flatMap((filePath) =>
    normalizeJsonFile(filePath, {
      toolName: tool,
      toolVersion: args['tool-version'],
    }),
  );

  fs.writeFileSync(output, `${JSON.stringify(findings, null, 2)}\n`, 'utf8');
}

if (require.main === module) {
  runCli();
}
