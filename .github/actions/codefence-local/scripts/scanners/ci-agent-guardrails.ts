/**
 * CI Agent Guardrails Scanner — Phase A, Steps 6-8
 *
 * Detects GitHub Actions workflows that:
 * - Feed untrusted content into agent prompts or run: steps (Step 6)
 * - Expose secrets in low-trust triggers without environment gating (Step 7)
 * - Use risky cross-workflow cache/artifact sharing patterns (Step 8)
 *
 * Detection rules:
 *  1. ci-guardrails/untrusted-input-in-run               HIGH     HIGH
 *  2. ci-guardrails/untrusted-input-in-agent-prompt       CRITICAL HIGH
 *  3. ci-guardrails/expression-in-run-step                MEDIUM   MEDIUM
 *  4. ci-guardrails/secrets-in-low-trust-trigger           HIGH     HIGH
 *  5. ci-guardrails/publish-secret-without-environment     MEDIUM   MEDIUM
 *  6. ci-guardrails/broad-permissions-with-secrets         HIGH     MEDIUM
 *  7. ci-guardrails/cache-poisoning-risk                   HIGH     MEDIUM
 *  8. ci-guardrails/artifact-injection-risk                HIGH     MEDIUM
 *  9. ci-guardrails/writable-cache-from-pr                 MEDIUM   MEDIUM
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

// ── Types ────────────────────────────────────────────────────────────────────

export interface GuardrailFinding {
  ruleId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  filePath: string;
  startLine: number;
  endLine: number;
  title: string;
  description: string;
  snippet: string;
  remediationSummary: string;
  /** Minimal diff showing the safe pattern (Step 9). */
  patchSuggestion: string | null;
  /** IDE-friendly one-liner fix instruction (Step 9). */
  ideFixPrompt: string | null;
}

// ── Constants ────────────────────────────────────────────────────────────────

/**
 * GitHub context paths that contain user-controllable data.
 * Any `${{ }}` expression referencing these should be treated as untrusted.
 */
export const UNTRUSTED_CONTEXTS: readonly string[] = [
  'github.event.issue.title',
  'github.event.issue.body',
  'github.event.pull_request.title',
  'github.event.pull_request.body',
  'github.event.comment.body',
  'github.event.review.body',
  'github.event.review_comment.body',
  'github.event.pages.*.page_name',
  'github.event.head_commit.message',
  'github.event.head_commit.author.email',
  'github.event.head_commit.author.name',
  'github.event.commits.*.message',
  'github.event.commits.*.author.email',
  'github.event.commits.*.author.name',
  'github.event.discussion.title',
  'github.event.discussion.body',
  'github.head_ref',
  'github.event.workflow_run.head_branch',
  'github.event.workflow_run.head_commit.message',
  'github.event.pull_request.head.ref',
  'github.event.pull_request.head.label',
];

/**
 * Compiled regex fragments from UNTRUSTED_CONTEXTS.
 * Wildcards (.*) are converted to regex (.+).
 */
const UNTRUSTED_PATTERNS: RegExp[] = UNTRUSTED_CONTEXTS.map((ctx) => {
  const escaped = ctx.replace(/\./g, '\\.').replace(/\\\.\\\*/g, '\\..+');
  return new RegExp(escaped, 'i');
});

/**
 * Known AI agent actions whose `with:` inputs may accept untrusted content
 * as prompts.
 */
export const KNOWN_AGENT_ACTIONS: readonly string[] = [
  'github/copilot-swe-agent',
  'anthropics/claude-code-action',
  'aider-ai/aider-action',
  'jamsocket/aicmd-action',
  'coderabbitai/ai-pr-reviewer',
  'codiumai/pr-agent',
  'gptlint/gptlint-action',
  'sweep-ai/sweep-action',
  'sourcery-ai/action',
];

// ── Secrets segmentation constants (Step 7) ─────────────────────────────────

/**
 * Trigger events considered low-trust because they can be initiated by
 * external contributors or forked repositories.
 */
export const LOW_TRUST_TRIGGERS: ReadonlySet<string> = new Set([
  'pull_request_target',
  'issue_comment',
  'workflow_run',
  'issues',
  'discussion_comment',
  'fork',
]);

/**
 * Secret name patterns that reference publish/deploy credentials.
 * Matched case-insensitively against the secret name portion of
 * `secrets.<NAME>`.
 */
export const PUBLISH_SECRET_PATTERNS: readonly RegExp[] = [
  /^npm[_-]?token$/i,
  /^pypi[_-]?token$/i,
  /^nuget[_-]?(?:api[_-]?)?key$/i,
  /^rubygems[_-]?(?:api[_-]?)?key$/i,
  /^cargo[_-]?(?:registry[_-]?)?token$/i,
  /deploy/i,
  /publish/i,
  /release/i,
  /^aws[_-]/i,
  /^gcp[_-]/i,
  /^azure[_-]/i,
  /^docker[_-]?(?:hub[_-]?)?(?:password|token|username)/i,
];

/**
 * Permissions considered "broad" when combined with secret access.
 */
const BROAD_PERMISSIONS: ReadonlySet<string> = new Set([
  'write-all',
  'write',
]);

// ── Cache/Artifact isolation constants (Step 8) ─────────────────────────────

/**
 * Triggers considered low-trust for cache/artifact isolation analysis.
 * Re-uses the same set from secrets segmentation plus PR triggers.
 */
const CACHE_LOW_TRUST_TRIGGERS: ReadonlySet<string> = new Set([
  'pull_request',
  'pull_request_target',
  'issue_comment',
  'workflow_run',
  'issues',
  'discussion_comment',
  'fork',
]);

/**
 * Triggers considered high-trust for cache read-side analysis.
 */
const CACHE_HIGH_TRUST_TRIGGERS: ReadonlySet<string> = new Set([
  'push',
  'schedule',
  'workflow_dispatch',
  'release',
]);

// ── Cache/Artifact isolation types (Step 8) ──────────────────────────────────

export interface CacheKeyUsage {
  /** The literal cache key string (may contain `${{ }}` expressions). */
  key: string;
  /** Additional restore-keys (read-only fallbacks). */
  restoreKeys: string[];
  jobName: string;
  filePath: string;
  lineNum: number;
  triggers: string[];
  isLowTrust: boolean;
}

export interface ArtifactUsage {
  /** The artifact name. */
  name: string;
  type: 'upload' | 'download';
  jobName: string;
  filePath: string;
  lineNum: number;
  triggers: string[];
  isLowTrust: boolean;
}

// ── Expression extraction ────────────────────────────────────────────────────

/**
 * Extract all `${{ ... }}` expressions from a string value.
 * Returns the inner expression bodies (trimmed).
 */
export function extractExpressions(value: string): string[] {
  const matches: string[] = [];
  const regex = /\$\{\{\s*(.*?)\s*\}\}/g;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(value)) !== null) {
    matches.push(m[1].trim());
  }
  return matches;
}

/**
 * Check whether an expression body references any untrusted context.
 */
export function isUntrustedExpression(expr: string): boolean {
  return UNTRUSTED_PATTERNS.some((pattern) => pattern.test(expr));
}

/**
 * Check whether an expression body references *any* user-controllable GitHub
 * context (broader check used for the MEDIUM-severity rule).
 */
export function isUserControllableExpression(expr: string): boolean {
  // Matches anything under github.event.* that isn't a well-known safe field
  const safeFields = new Set([
    'github.event.action',
    'github.event.number',
    'github.event.repository',
    'github.event.sender',
    'github.event.installation',
    'github.event.organization',
  ]);
  if (safeFields.has(expr.toLowerCase())) return false;

  // If it explicitly matches untrusted, yes
  if (isUntrustedExpression(expr)) return true;

  // Broad heuristic: any github.event path that looks like it carries
  // user-authored text
  return /github\.event\.[a-z_]+\.(body|title|message|label|name|text|description)/i.test(expr);
}

// ── YAML workflow parsing ────────────────────────────────────────────────────

interface WorkflowStep {
  run?: string;
  uses?: string;
  with?: Record<string, string>;
  env?: Record<string, string>;
  name?: string;
}

interface WorkflowJob {
  'runs-on'?: string;
  steps?: WorkflowStep[];
  environment?: string | { name: string };
  permissions?: unknown;
}

interface WorkflowFile {
  on?: unknown;
  jobs?: Record<string, WorkflowJob>;
}

/**
 * Parse a YAML workflow file safely. Returns null on parse failure.
 */
export function parseWorkflow(content: string): WorkflowFile | null {
  try {
    const doc = yaml.load(content);
    if (doc && typeof doc === 'object') {
      return doc as WorkflowFile;
    }
    return null;
  } catch {
    return null;
  }
}

// ── Line number resolution ───────────────────────────────────────────────────

/**
 * Find the 1-based line number of a substring in the raw file content.
 */
function findLineNumber(content: string, needle: string, startFrom = 0): number {
  const idx = content.indexOf(needle, startFrom);
  if (idx === -1) return 1;
  return content.slice(0, idx).split('\n').length;
}

// ── Rule implementations ─────────────────────────────────────────────────────

/**
 * Rule 1: ci-guardrails/untrusted-input-in-run
 *
 * Detects `${{ github.event.* }}` untrusted context used directly in
 * `run:` steps (shell injection risk).
 */
function detectUntrustedInputInRun(
  workflow: WorkflowFile,
  rawContent: string,
  filePath: string,
): GuardrailFinding[] {
  const findings: GuardrailFinding[] = [];

  for (const [, job] of Object.entries(workflow.jobs || {})) {
    for (const step of job.steps || []) {
      if (!step.run) continue;
      const exprs = extractExpressions(step.run);
      for (const expr of exprs) {
        if (isUntrustedExpression(expr)) {
          const lineNum = findLineNumber(rawContent, expr);
          const envVarName = expr.split('.').pop()?.toUpperCase().replace(/[^A-Z0-9_]/g, '_') || 'INPUT';
          findings.push({
            ruleId: 'ci-guardrails/untrusted-input-in-run',
            severity: 'HIGH',
            confidence: 'HIGH',
            filePath,
            startLine: lineNum,
            endLine: lineNum,
            title: `Untrusted input \${{ ${expr} }} used in run: step`,
            description:
              `The expression \${{ ${expr} }} injects user-controllable content ` +
              `directly into a shell command. An attacker who controls this value ` +
              `(e.g., via a crafted PR title or issue body) can execute arbitrary ` +
              `commands in the runner.`,
            snippet: step.run.slice(0, 200),
            remediationSummary:
              'Pass untrusted input via an environment variable instead of inline expression. ' +
              'Example: add `env: TITLE: ${{ github.event.pull_request.title }}` to the step ' +
              'and reference `$TITLE` in the shell script.',
            patchSuggestion:
              `--- a/${filePath}\n+++ b/${filePath}\n` +
              `@@ step @@\n` +
              `-      run: echo \${{ ${expr} }}\n` +
              `+      env:\n` +
              `+        ${envVarName}: \${{ ${expr} }}\n` +
              `+      run: echo "$${envVarName}"`,
            ideFixPrompt:
              `Extract \${{ ${expr} }} into an env: variable named ${envVarName} and reference it as $${envVarName} in the run: script.`,
          });
        }
      }
    }
  }

  return findings;
}

/**
 * Rule 2: ci-guardrails/untrusted-input-in-agent-prompt
 *
 * Detects untrusted event context used as input to known AI agent actions.
 */
function detectUntrustedInputInAgentPrompt(
  workflow: WorkflowFile,
  rawContent: string,
  filePath: string,
): GuardrailFinding[] {
  const findings: GuardrailFinding[] = [];

  for (const [, job] of Object.entries(workflow.jobs || {})) {
    for (const step of job.steps || []) {
      if (!step.uses) continue;
      // Normalize action name: strip version/tag suffix (e.g., @v1, @main)
      const actionName = step.uses.replace(/@[^@]+$/, '').toLowerCase();
      const isAgentAction = KNOWN_AGENT_ACTIONS.some(
        (a) => actionName === a.toLowerCase() || actionName.startsWith(a.toLowerCase() + '/'),
      );
      if (!isAgentAction) continue;

      // Check all `with:` inputs for untrusted expressions
      for (const [inputKey, inputValue] of Object.entries(step.with || {})) {
        const strValue = String(inputValue);
        const exprs = extractExpressions(strValue);
        for (const expr of exprs) {
          if (isUntrustedExpression(expr)) {
            const lineNum = findLineNumber(rawContent, expr);
            findings.push({
              ruleId: 'ci-guardrails/untrusted-input-in-agent-prompt',
              severity: 'CRITICAL',
              confidence: 'HIGH',
              filePath,
              startLine: lineNum,
              endLine: lineNum,
              title: `Untrusted input \${{ ${expr} }} passed to AI agent action ${step.uses}`,
              description:
                `The expression \${{ ${expr} }} passes user-controllable content ` +
                `to the '${inputKey}' input of agent action '${step.uses}'. ` +
                `An attacker can craft a malicious PR/issue to inject instructions ` +
                `into the agent's prompt, potentially exfiltrating secrets or ` +
                `manipulating repository content.`,
              snippet: `${inputKey}: ${strValue}`.slice(0, 200),
              remediationSummary:
                'Never pass untrusted user input directly to AI agent action inputs. ' +
                'Use a sanitization step that strips special characters and validates ' +
                'content against an allowlist, or restrict the trigger to trusted events only.',
              patchSuggestion:
                `--- a/${filePath}\n+++ b/${filePath}\n` +
                `@@ step @@\n` +
                `-      ${inputKey}: \${{ ${expr} }}\n` +
                `+      # SECURITY: Do not pass untrusted input directly to agent prompts.\n` +
                `+      # Option 1: Restrict trigger to trusted events (e.g., workflow_dispatch)\n` +
                `+      # Option 2: Add a sanitization step before this action`,
              ideFixPrompt:
                `Remove \${{ ${expr} }} from the '${inputKey}' input of ${step.uses}. Restrict the workflow trigger to trusted events or add an input sanitization step.`,
            });
          }
        }
      }
    }
  }

  return findings;
}

/**
 * Rule 3: ci-guardrails/expression-in-run-step
 *
 * Broader, lower-confidence rule: flags `${{ ... }}` expressions in `run:`
 * blocks that reference user-controllable GitHub event context (wider net
 * than Rule 1).
 */
function detectExpressionInRunStep(
  workflow: WorkflowFile,
  rawContent: string,
  filePath: string,
  alreadyFlagged: Set<string>,
): GuardrailFinding[] {
  const findings: GuardrailFinding[] = [];

  for (const [, job] of Object.entries(workflow.jobs || {})) {
    for (const step of job.steps || []) {
      if (!step.run) continue;
      const exprs = extractExpressions(step.run);
      for (const expr of exprs) {
        // Skip expressions already caught by Rule 1 (higher severity)
        if (alreadyFlagged.has(expr)) continue;
        if (isUserControllableExpression(expr)) {
          const lineNum = findLineNumber(rawContent, expr);
          const safeVarName = expr.split('.').pop()?.toUpperCase().replace(/[^A-Z0-9_]/g, '_') || 'CTX';
          findings.push({
            ruleId: 'ci-guardrails/expression-in-run-step',
            severity: 'MEDIUM',
            confidence: 'MEDIUM',
            filePath,
            startLine: lineNum,
            endLine: lineNum,
            title: `User-controllable expression \${{ ${expr} }} in run: step`,
            description:
              `The expression \${{ ${expr} }} references GitHub event context that ` +
              `may be influenced by external users. While not all such expressions ` +
              `are exploitable, using them in shell commands increases the attack surface.`,
            snippet: step.run.slice(0, 200),
            remediationSummary:
              'Prefer passing GitHub context through environment variables rather than ' +
              'inline expressions. This prevents shell metacharacter injection.',
            patchSuggestion:
              `--- a/${filePath}\n+++ b/${filePath}\n` +
              `@@ step @@\n` +
              `+      env:\n` +
              `+        ${safeVarName}: \${{ ${expr} }}\n` +
              `       run: |\n` +
              `-        ... \${{ ${expr} }} ...\n` +
              `+        ... "$${safeVarName}" ...`,
            ideFixPrompt:
              `Move \${{ ${expr} }} into an env: block and reference it as $${safeVarName} in the shell script.`,
          });
        }
      }
    }
  }

  return findings;
}

// ── Secrets segmentation helpers (Step 7) ────────────────────────────────────

/**
 * Extract the trigger event names from the `on:` field of a workflow.
 */
export function extractTriggers(on: unknown): string[] {
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.map(String);
  if (on && typeof on === 'object') return Object.keys(on);
  return [];
}

/**
 * Check whether any of the workflow triggers are low-trust.
 */
export function hasLowTrustTrigger(triggers: string[]): boolean {
  return triggers.some((t) => LOW_TRUST_TRIGGERS.has(t));
}

/**
 * Extract all `secrets.*` references from a string.
 * Returns the secret names (e.g., ['NPM_TOKEN', 'GITHUB_TOKEN']).
 */
export function extractSecretReferences(value: string): string[] {
  const refs: string[] = [];
  const regex = /\$\{\{\s*secrets\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}/g;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(value)) !== null) {
    refs.push(m[1]);
  }
  return refs;
}

/**
 * Collect all secret names referenced anywhere in a job's steps
 * (run:, env:, with: values).
 */
export function collectJobSecrets(job: WorkflowJob): string[] {
  const secrets: string[] = [];
  for (const step of job.steps || []) {
    const sources: string[] = [];
    if (step.run) sources.push(step.run);
    for (const v of Object.values(step.env || {})) sources.push(String(v));
    for (const v of Object.values(step.with || {})) sources.push(String(v));
    for (const src of sources) {
      secrets.push(...extractSecretReferences(src));
    }
  }
  return [...new Set(secrets)];
}

/**
 * Check whether a job has an `environment:` block (protects secret access).
 */
export function jobHasEnvironment(job: WorkflowJob): boolean {
  return job.environment != null;
}

/**
 * Check whether a secret name matches known publish/deploy patterns.
 */
export function isPublishSecret(name: string): boolean {
  // GITHUB_TOKEN is not a publish secret
  if (name.toUpperCase() === 'GITHUB_TOKEN') return false;
  return PUBLISH_SECRET_PATTERNS.some((p) => p.test(name));
}

/**
 * Determine whether a job has broad permissions.
 * Handles both string ("write-all") and object ({ contents: write }) forms.
 */
export function jobHasBroadPermissions(job: WorkflowJob): boolean {
  const perms = job.permissions;
  if (typeof perms === 'string') {
    return BROAD_PERMISSIONS.has(perms.toLowerCase());
  }
  if (perms && typeof perms === 'object') {
    // Count write-level scopes; 3+ is considered broad
    const writeScopes = Object.values(perms as Record<string, string>).filter(
      (v) => typeof v === 'string' && v.toLowerCase() === 'write',
    );
    return writeScopes.length >= 3;
  }
  return false;
}

// ── Cache/Artifact isolation helpers (Step 8) ───────────────────────────────

/**
 * Check whether an action `uses:` string matches a given action owner/repo.
 * Handles version tags (e.g., `actions/cache@v3`).
 */
function usesAction(uses: string | undefined, actionName: string): boolean {
  if (!uses) return false;
  const normalized = uses.replace(/@[^@]+$/, '').toLowerCase();
  return normalized === actionName.toLowerCase();
}

/**
 * Extract cache key usages from a parsed workflow.
 * Looks for `actions/cache` steps and extracts `key` and `restore-keys`.
 */
export function extractCacheUsages(
  workflow: WorkflowFile,
  rawContent: string,
  filePath: string,
): CacheKeyUsage[] {
  const triggers = extractTriggers(workflow.on);
  const isLowTrust = triggers.some((t) => CACHE_LOW_TRUST_TRIGGERS.has(t));
  const usages: CacheKeyUsage[] = [];

  for (const [jobName, job] of Object.entries(workflow.jobs || {})) {
    for (const step of job.steps || []) {
      if (!usesAction(step.uses, 'actions/cache')) continue;

      const key = String(step.with?.key || '').trim();
      if (!key) continue;

      const restoreKeysRaw = String(step.with?.['restore-keys'] || '').trim();
      const restoreKeys = restoreKeysRaw
        ? restoreKeysRaw.split('\n').map((k) => k.trim()).filter(Boolean)
        : [];

      const lineNum = findLineNumber(rawContent, key);
      usages.push({ key, restoreKeys, jobName, filePath, lineNum, triggers, isLowTrust });
    }
  }

  return usages;
}

/**
 * Extract artifact upload/download usages from a parsed workflow.
 * Looks for `actions/upload-artifact` and `actions/download-artifact` steps.
 */
export function extractArtifactUsages(
  workflow: WorkflowFile,
  rawContent: string,
  filePath: string,
): ArtifactUsage[] {
  const triggers = extractTriggers(workflow.on);
  const isLowTrust = triggers.some((t) => CACHE_LOW_TRUST_TRIGGERS.has(t));
  const usages: ArtifactUsage[] = [];

  for (const [jobName, job] of Object.entries(workflow.jobs || {})) {
    for (const step of job.steps || []) {
      if (usesAction(step.uses, 'actions/upload-artifact')) {
        const name = String(step.with?.name || 'artifact').trim();
        const lineNum = findLineNumber(rawContent, 'upload-artifact');
        usages.push({ name, type: 'upload', jobName, filePath, lineNum, triggers, isLowTrust });
      } else if (usesAction(step.uses, 'actions/download-artifact')) {
        const name = String(step.with?.name || 'artifact').trim();
        const lineNum = findLineNumber(rawContent, 'download-artifact');
        usages.push({ name, type: 'download', jobName, filePath, lineNum, triggers, isLowTrust });
      }
    }
  }

  return usages;
}

/**
 * Determine whether two cache keys overlap.
 * Overlap = exact match, or one is a prefix of the other (before `${{ }}`
 * expression boundaries), which would cause a restore-key hit.
 *
 * Special case: keys containing `github.event_name` are inherently scoped
 * per trigger type and should NOT be considered overlapping across workflows.
 */
export function cacheKeysOverlap(key1: string, key2: string): boolean {
  // Keys that include event_name scoping resolve to different values at
  // runtime across different trigger types, so they do NOT overlap.
  const eventScopingExpr = /\$\{\{\s*github\.event_name\s*\}\}/;
  if (eventScopingExpr.test(key1) || eventScopingExpr.test(key2)) {
    return false;
  }

  if (key1 === key2) return true;

  // Strip `${{ ... }}` expression parts for static prefix comparison
  const stripExprs = (k: string) => k.replace(/\$\{\{.*?\}\}/g, '').trim();
  const static1 = stripExprs(key1);
  const static2 = stripExprs(key2);

  // If the static portions are empty, they can't meaningfully overlap
  if (!static1 || !static2) return false;

  // Check if one static prefix starts with the other
  return static1.startsWith(static2) || static2.startsWith(static1);
}

/**
 * Check whether a workflow_run downloading workflow has any artifact
 * integrity verification (hash check, cosign, etc.).
 */
function hasArtifactIntegrityCheck(workflow: WorkflowFile): boolean {
  const integrityPatterns = [
    /sha256/i, /checksum/i, /cosign/i, /verify/i,
    /sigstore/i, /attestation/i, /digest/i,
  ];

  for (const [, job] of Object.entries(workflow.jobs || {})) {
    for (const step of job.steps || []) {
      const sources = [step.run || '', step.name || ''];
      for (const src of sources) {
        if (integrityPatterns.some((p) => p.test(src))) return true;
      }
    }
  }
  return false;
}

// ── Cache/Artifact isolation rule implementations (Step 8) ───────────────────

/**
 * Rule 7: ci-guardrails/cache-poisoning-risk
 *
 * Detects `actions/cache` used with shared key patterns across workflows
 * where one workflow has low-trust triggers and another has high-trust
 * triggers.
 */
function detectCachePoisoningRisk(
  allCacheUsages: CacheKeyUsage[],
): GuardrailFinding[] {
  const findings: GuardrailFinding[] = [];

  const lowTrustUsages = allCacheUsages.filter((u) => u.isLowTrust);
  const highTrustUsages = allCacheUsages.filter((u) => !u.isLowTrust);

  for (const lowUsage of lowTrustUsages) {
    for (const highUsage of highTrustUsages) {
      // Skip if same file (single-workflow analysis handled elsewhere)
      if (lowUsage.filePath === highUsage.filePath) continue;

      if (cacheKeysOverlap(lowUsage.key, highUsage.key)) {
        findings.push({
          ruleId: 'ci-guardrails/cache-poisoning-risk',
          severity: 'HIGH',
          confidence: 'MEDIUM',
          filePath: lowUsage.filePath,
          startLine: lowUsage.lineNum,
          endLine: lowUsage.lineNum,
          title: `Cache key shared between low-trust and high-trust workflows (job: ${lowUsage.jobName})`,
          description:
            `Workflow '${lowUsage.filePath}' (triggers: ${lowUsage.triggers.join(', ')}) ` +
            `uses cache key '${lowUsage.key}' that overlaps with key '${highUsage.key}' ` +
            `in '${highUsage.filePath}' (triggers: ${highUsage.triggers.join(', ')}). ` +
            `A malicious PR or issue could poison the cache, injecting tainted content into ` +
            `the trusted workflow's build.`,
          snippet: `key: ${lowUsage.key}`,
          remediationSummary:
            'Use unique cache keys per trigger type by including `${{ github.event_name }}` ' +
            'in the cache key. This prevents cross-workflow cache poisoning. ' +
            'Example: `key: ${{ github.event_name }}-deps-${{ hashFiles("**/lockfile") }}`.',
          patchSuggestion:
            `--- a/${lowUsage.filePath}\n+++ b/${lowUsage.filePath}\n` +
            `@@ cache step @@\n` +
            `-        key: ${lowUsage.key}\n` +
            `+        key: \${{ github.event_name }}-${lowUsage.key}`,
          ideFixPrompt:
            `Prefix the cache key with \${{ github.event_name }} to scope it per trigger type and prevent cross-workflow cache poisoning.`,
        });
      }

      // Also check if the high-trust workflow's restore-keys could match
      for (const rk of highUsage.restoreKeys) {
        if (cacheKeysOverlap(lowUsage.key, rk)) {
          findings.push({
            ruleId: 'ci-guardrails/cache-poisoning-risk',
            severity: 'HIGH',
            confidence: 'MEDIUM',
            filePath: lowUsage.filePath,
            startLine: lowUsage.lineNum,
            endLine: lowUsage.lineNum,
            title: `Cache key matches restore-key in high-trust workflow (job: ${lowUsage.jobName})`,
            description:
              `Workflow '${lowUsage.filePath}' writes cache key '${lowUsage.key}' that ` +
              `matches restore-key '${rk}' in '${highUsage.filePath}'. ` +
              `The trusted workflow may restore a cache entry poisoned by the untrusted workflow.`,
            snippet: `key: ${lowUsage.key} -> restore-keys: ${rk}`,
            remediationSummary:
              'Scope cache keys and restore-keys by event type. Avoid broad restore-key prefixes ' +
              'that could match cache entries written by untrusted workflows.',
            patchSuggestion:
              `--- a/${highUsage.filePath}\n+++ b/${highUsage.filePath}\n` +
              `@@ cache step @@\n` +
              `-        restore-keys: ${rk}\n` +
              `+        restore-keys: \${{ github.event_name }}-${rk}`,
            ideFixPrompt:
              `Scope the restore-keys in '${highUsage.filePath}' with \${{ github.event_name }} to prevent matching cache entries from untrusted workflows.`,
          });
        }
      }
    }
  }

  return findings;
}

/**
 * Rule 8: ci-guardrails/artifact-injection-risk
 *
 * Detects `actions/upload-artifact` + `actions/download-artifact` used
 * across workflow_run boundaries without integrity verification.
 */
function detectArtifactInjectionRisk(
  allArtifactUsages: ArtifactUsage[],
  workflowMap: Map<string, WorkflowFile>,
): GuardrailFinding[] {
  const findings: GuardrailFinding[] = [];

  const uploads = allArtifactUsages.filter((u) => u.type === 'upload');
  const downloads = allArtifactUsages.filter((u) => u.type === 'download');

  for (const upload of uploads) {
    for (const download of downloads) {
      // Only flag cross-workflow sharing
      if (upload.filePath === download.filePath) continue;

      // Check if artifact names match
      if (upload.name !== download.name) continue;

      // Check if the download side is a workflow_run trigger (cross-boundary)
      const isWorkflowRunBoundary = download.triggers.includes('workflow_run');
      if (!isWorkflowRunBoundary) continue;

      // Check if the downloading workflow has integrity verification
      const downloadWorkflow = workflowMap.get(download.filePath);
      if (downloadWorkflow && hasArtifactIntegrityCheck(downloadWorkflow)) continue;

      findings.push({
        ruleId: 'ci-guardrails/artifact-injection-risk',
        severity: 'HIGH',
        confidence: 'MEDIUM',
        filePath: download.filePath,
        startLine: download.lineNum,
        endLine: download.lineNum,
        title: `Artifact '${download.name}' downloaded across workflow_run boundary without integrity check (job: ${download.jobName})`,
        description:
          `Workflow '${download.filePath}' (workflow_run trigger) downloads artifact ` +
          `'${download.name}' that is uploaded by '${upload.filePath}'. ` +
          `Without integrity verification (e.g., checksum or signature), a compromised ` +
          `or malicious PR workflow could inject tainted artifacts into the trusted workflow.`,
        snippet: `download-artifact: ${download.name}`,
        remediationSummary:
          'Add integrity verification for downloaded artifacts. Compute and verify a SHA-256 ' +
          'checksum of the artifact contents, or use sigstore/cosign to sign and verify artifacts. ' +
          'Example: upload a `sha256sum.txt` alongside the artifact and verify it after download.',
        patchSuggestion:
          `--- a/${download.filePath}\n+++ b/${download.filePath}\n` +
          `@@ download step @@\n` +
          `       - uses: actions/download-artifact@v4\n` +
          `         with:\n` +
          `           name: ${download.name}\n` +
          `+      - name: Verify artifact integrity\n` +
          `+        run: sha256sum -c sha256sum.txt`,
        ideFixPrompt:
          `Add a checksum verification step after downloading artifact '${download.name}'. Upload sha256sum.txt with the artifact and verify it after download.`,
      });
    }
  }

  return findings;
}

/**
 * Rule 9: ci-guardrails/writable-cache-from-pr
 *
 * Detects `pull_request` or `pull_request_target` workflows that write to
 * cache keys which `push`/`schedule` workflows read.
 */
function detectWritableCacheFromPR(
  allCacheUsages: CacheKeyUsage[],
): GuardrailFinding[] {
  const findings: GuardrailFinding[] = [];

  const prTriggers = new Set(['pull_request', 'pull_request_target']);

  const prUsages = allCacheUsages.filter((u) =>
    u.triggers.some((t) => prTriggers.has(t)),
  );
  const trustedUsages = allCacheUsages.filter((u) =>
    u.triggers.some((t) => CACHE_HIGH_TRUST_TRIGGERS.has(t)),
  );

  for (const prUsage of prUsages) {
    for (const trustedUsage of trustedUsages) {
      if (prUsage.filePath === trustedUsage.filePath) continue;

      // Check primary key overlap
      if (cacheKeysOverlap(prUsage.key, trustedUsage.key)) {
        findings.push({
          ruleId: 'ci-guardrails/writable-cache-from-pr',
          severity: 'MEDIUM',
          confidence: 'MEDIUM',
          filePath: prUsage.filePath,
          startLine: prUsage.lineNum,
          endLine: prUsage.lineNum,
          title: `PR workflow writes cache key readable by trusted workflow (job: ${prUsage.jobName})`,
          description:
            `Workflow '${prUsage.filePath}' (triggers: ${prUsage.triggers.join(', ')}) ` +
            `writes cache key '${prUsage.key}' that overlaps with key '${trustedUsage.key}' ` +
            `read by '${trustedUsage.filePath}' (triggers: ${trustedUsage.triggers.join(', ')}). ` +
            `A malicious PR could poison the cache to inject code into the push/schedule build.`,
          snippet: `key: ${prUsage.key}`,
          remediationSummary:
            'Separate cache keys for PR and push/schedule workflows. Include `${{ github.event_name }}` ' +
            'in the cache key to prevent cross-trigger sharing. Alternatively, use read-only cache ' +
            'in PR workflows with `actions/cache/restore`.',
          patchSuggestion:
            `--- a/${prUsage.filePath}\n+++ b/${prUsage.filePath}\n` +
            `@@ cache step @@\n` +
            `-      - uses: actions/cache@v4\n` +
            `+      - uses: actions/cache/restore@v4  # read-only in PR workflows\n` +
            `         with:\n` +
            `           key: ${prUsage.key}`,
          ideFixPrompt:
            `Replace actions/cache with actions/cache/restore in the PR workflow to make it read-only, preventing cache poisoning.`,
        });
      }

      // Check if trusted workflow's restore-keys match PR cache key
      for (const rk of trustedUsage.restoreKeys) {
        if (cacheKeysOverlap(prUsage.key, rk)) {
          // Avoid duplicate if already flagged via primary key
          const alreadyFlagged = findings.some(
            (f) =>
              f.ruleId === 'ci-guardrails/writable-cache-from-pr' &&
              f.filePath === prUsage.filePath &&
              f.startLine === prUsage.lineNum &&
              f.description.includes(trustedUsage.filePath),
          );
          if (alreadyFlagged) continue;

          findings.push({
            ruleId: 'ci-guardrails/writable-cache-from-pr',
            severity: 'MEDIUM',
            confidence: 'MEDIUM',
            filePath: prUsage.filePath,
            startLine: prUsage.lineNum,
            endLine: prUsage.lineNum,
            title: `PR workflow cache key matches trusted restore-key (job: ${prUsage.jobName})`,
            description:
              `Workflow '${prUsage.filePath}' writes cache key '${prUsage.key}' that matches ` +
              `restore-key '${rk}' of '${trustedUsage.filePath}' (triggers: ${trustedUsage.triggers.join(', ')}). ` +
              `The trusted workflow may fall back to a cache entry poisoned by a malicious PR.`,
            snippet: `key: ${prUsage.key} -> restore-keys: ${rk}`,
            remediationSummary:
              'Scope cache keys and restore-keys by trigger type. Use `actions/cache/restore` (read-only) ' +
              'in PR workflows instead of the full `actions/cache` action.',
            patchSuggestion:
              `--- a/${prUsage.filePath}\n+++ b/${prUsage.filePath}\n` +
              `@@ cache step @@\n` +
              `-      - uses: actions/cache@v4\n` +
              `+      - uses: actions/cache/restore@v4  # read-only in PR workflows`,
            ideFixPrompt:
              `Use actions/cache/restore instead of actions/cache in the PR workflow to prevent writing poisoned cache entries.`,
          });
        }
      }
    }
  }

  return findings;
}

// ── Secrets segmentation rule implementations (Step 7) ──────────────────────

/**
 * Rule 4: ci-guardrails/secrets-in-low-trust-trigger
 *
 * Flags workflows triggered by low-trust events that access secrets
 * without an `environment:` block.
 */
function detectSecretsInLowTrustTrigger(
  workflow: WorkflowFile,
  rawContent: string,
  filePath: string,
): GuardrailFinding[] {
  const triggers = extractTriggers(workflow.on);
  if (!hasLowTrustTrigger(triggers)) return [];

  const findings: GuardrailFinding[] = [];

  for (const [jobName, job] of Object.entries(workflow.jobs || {})) {
    if (jobHasEnvironment(job)) continue;

    const secrets = collectJobSecrets(job);
    // Exclude GITHUB_TOKEN — it's always available and not a deploy credential
    const nonTrivial = secrets.filter((s) => s.toUpperCase() !== 'GITHUB_TOKEN');
    if (nonTrivial.length === 0) continue;

    const lineNum = findLineNumber(rawContent, jobName);
    findings.push({
      ruleId: 'ci-guardrails/secrets-in-low-trust-trigger',
      severity: 'HIGH',
      confidence: 'HIGH',
      filePath,
      startLine: lineNum,
      endLine: lineNum,
      title: `Secrets used in low-trust trigger without environment gating (job: ${jobName})`,
      description:
        `Job '${jobName}' is triggered by ${triggers.filter((t) => LOW_TRUST_TRIGGERS.has(t)).join(', ')} ` +
        `and accesses secrets (${nonTrivial.join(', ')}) without an \`environment:\` block. ` +
        `External contributors or forked repos may be able to exfiltrate these secrets.`,
      snippet: `secrets: ${nonTrivial.join(', ')}`,
      remediationSummary:
        'Gate secret access behind an `environment:` block with required reviewers. ' +
        'Example: add `environment: production` to the job to require approval before secrets are exposed.',
      patchSuggestion:
        `--- a/${filePath}\n+++ b/${filePath}\n` +
        `@@ jobs.${jobName} @@\n` +
        ` ${jobName}:\n` +
        `   runs-on: ubuntu-latest\n` +
        `+  environment: production\n` +
        `   steps:`,
      ideFixPrompt:
        `Add \`environment: production\` (or another protected environment) to job '${jobName}' to gate secret access behind required reviewers.`,
    });
  }

  return findings;
}

/**
 * Rule 5: ci-guardrails/publish-secret-without-environment
 *
 * Flags jobs that reference publish/deploy secrets without environment gating,
 * regardless of trigger type.
 */
function detectPublishSecretWithoutEnvironment(
  workflow: WorkflowFile,
  rawContent: string,
  filePath: string,
): GuardrailFinding[] {
  const findings: GuardrailFinding[] = [];

  for (const [jobName, job] of Object.entries(workflow.jobs || {})) {
    if (jobHasEnvironment(job)) continue;

    const secrets = collectJobSecrets(job);
    const publishSecrets = secrets.filter(isPublishSecret);
    if (publishSecrets.length === 0) continue;

    const lineNum = findLineNumber(rawContent, jobName);
    findings.push({
      ruleId: 'ci-guardrails/publish-secret-without-environment',
      severity: 'MEDIUM',
      confidence: 'MEDIUM',
      filePath,
      startLine: lineNum,
      endLine: lineNum,
      title: `Publish/deploy secrets used without environment gating (job: ${jobName})`,
      description:
        `Job '${jobName}' accesses publish/deploy secrets (${publishSecrets.join(', ')}) ` +
        `without an \`environment:\` block. This allows any workflow trigger to access ` +
        `these high-value credentials without approval.`,
      snippet: `secrets: ${publishSecrets.join(', ')}`,
      remediationSummary:
        'Add an `environment:` block with required reviewers to jobs that access publish or deploy secrets. ' +
        'This ensures credentials are only available after approval. ' +
        'Example: `environment: release`.',
      patchSuggestion:
        `--- a/${filePath}\n+++ b/${filePath}\n` +
        `@@ jobs.${jobName} @@\n` +
        ` ${jobName}:\n` +
        `   runs-on: ubuntu-latest\n` +
        `+  environment: release\n` +
        `   steps:`,
      ideFixPrompt:
        `Add \`environment: release\` to job '${jobName}' to protect publish/deploy secrets behind environment approval.`,
    });
  }

  return findings;
}

/**
 * Rule 6: ci-guardrails/broad-permissions-with-secrets
 *
 * Flags jobs that have both broad permissions AND access secrets.
 */
function detectBroadPermissionsWithSecrets(
  workflow: WorkflowFile,
  rawContent: string,
  filePath: string,
): GuardrailFinding[] {
  const findings: GuardrailFinding[] = [];

  for (const [jobName, job] of Object.entries(workflow.jobs || {})) {
    if (!jobHasBroadPermissions(job)) continue;

    const secrets = collectJobSecrets(job);
    if (secrets.length === 0) continue;

    const lineNum = findLineNumber(rawContent, jobName);
    findings.push({
      ruleId: 'ci-guardrails/broad-permissions-with-secrets',
      severity: 'HIGH',
      confidence: 'MEDIUM',
      filePath,
      startLine: lineNum,
      endLine: lineNum,
      title: `Broad permissions combined with secret access (job: ${jobName})`,
      description:
        `Job '${jobName}' has broad permissions and accesses secrets (${secrets.join(', ')}). ` +
        `This violates the principle of least privilege. If the job is compromised, ` +
        `the attacker gains both write access to repository resources and secrets.`,
      snippet: `permissions: ${JSON.stringify(job.permissions)}, secrets: ${secrets.join(', ')}`,
      remediationSummary:
        'Apply least-privilege permissions: only grant the specific scopes needed. ' +
        'Example: `permissions: { contents: read, packages: write }` instead of `write-all`. ' +
        'Split jobs so that the job accessing secrets has minimal permissions.',
      patchSuggestion:
        `--- a/${filePath}\n+++ b/${filePath}\n` +
        `@@ jobs.${jobName} @@\n` +
        `-  permissions: write-all\n` +
        `+  permissions:\n` +
        `+    contents: read\n` +
        `+    packages: write  # adjust to only needed scopes`,
      ideFixPrompt:
        `Replace broad permissions in job '${jobName}' with least-privilege scopes (e.g., contents: read, packages: write).`,
    });
  }

  return findings;
}

// ── Main scanner entry point ─────────────────────────────────────────────────

/**
 * Scan a workspace directory for CI Agent Guardrails issues.
 * Returns an array of findings in the scanner's internal format.
 *
 * Two-pass analysis:
 *  1. Per-file: rules 1-6 (inline expression / secrets / permissions)
 *  2. Cross-workflow: rules 7-9 (cache/artifact isolation)
 */
export function scanWorkspace(workspacePath: string): GuardrailFinding[] {
  const workflowDir = path.join(workspacePath, '.github', 'workflows');
  if (!fs.existsSync(workflowDir)) {
    return [];
  }

  const files = fs
    .readdirSync(workflowDir)
    .filter((f) => /\.ya?ml$/i.test(f))
    .map((f) => path.join(workflowDir, f));

  const allFindings: GuardrailFinding[] = [];

  // ── Cross-workflow accumulators (Step 8) ──────────────────────────────────
  const allCacheUsages: CacheKeyUsage[] = [];
  const allArtifactUsages: ArtifactUsage[] = [];
  const workflowMap = new Map<string, WorkflowFile>();

  for (const file of files) {
    let rawContent: string;
    try {
      rawContent = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }

    const workflow = parseWorkflow(rawContent);
    if (!workflow) continue;

    const relPath = path.relative(workspacePath, file).replace(/\\/g, '/');

    // Store for cross-workflow analysis
    workflowMap.set(relPath, workflow);

    // ── Pass 1: per-file rules (1-6) ────────────────────────────────────────

    // Rule 1: untrusted-input-in-run
    const rule1 = detectUntrustedInputInRun(workflow, rawContent, relPath);
    allFindings.push(...rule1);

    // Collect expressions already flagged by Rule 1 to avoid duplicates in Rule 3
    const flaggedExprs = new Set(
      rule1.flatMap((f) => {
        const m = f.title.match(/\$\{\{\s*(.*?)\s*\}\}/);
        return m ? [m[1].trim()] : [];
      }),
    );

    // Rule 2: untrusted-input-in-agent-prompt
    allFindings.push(...detectUntrustedInputInAgentPrompt(workflow, rawContent, relPath));

    // Rule 3: expression-in-run-step (broader, lower confidence)
    allFindings.push(...detectExpressionInRunStep(workflow, rawContent, relPath, flaggedExprs));

    // Rule 4: secrets-in-low-trust-trigger (Step 7)
    allFindings.push(...detectSecretsInLowTrustTrigger(workflow, rawContent, relPath));

    // Rule 5: publish-secret-without-environment (Step 7)
    allFindings.push(...detectPublishSecretWithoutEnvironment(workflow, rawContent, relPath));

    // Rule 6: broad-permissions-with-secrets (Step 7)
    allFindings.push(...detectBroadPermissionsWithSecrets(workflow, rawContent, relPath));

    // ── Collect cross-workflow metadata (Step 8) ────────────────────────────
    allCacheUsages.push(...extractCacheUsages(workflow, rawContent, relPath));
    allArtifactUsages.push(...extractArtifactUsages(workflow, rawContent, relPath));
  }

  // ── Pass 2: cross-workflow rules (7-9) ──────────────────────────────────

  // Rule 7: cache-poisoning-risk (Step 8)
  allFindings.push(...detectCachePoisoningRisk(allCacheUsages));

  // Rule 8: artifact-injection-risk (Step 8)
  allFindings.push(...detectArtifactInjectionRisk(allArtifactUsages, workflowMap));

  // Rule 9: writable-cache-from-pr (Step 8)
  allFindings.push(...detectWritableCacheFromPR(allCacheUsages));

  return allFindings;
}

// ── CLI entry point ──────────────────────────────────────────────────────────

function main(): void {
  const workspace = process.argv[2] || process.env.GITHUB_WORKSPACE || process.cwd();
  const outputFile = process.argv[3] || path.join(
    process.env.CODEFENCE_RESULTS_DIR || '/tmp/codefence-results',
    'raw',
    'ci-agent-guardrails.json',
  );

  const findings = scanWorkspace(workspace);

  const outputDir = path.dirname(outputFile);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  fs.writeFileSync(outputFile, JSON.stringify(findings, null, 2) + '\n', 'utf8');
  console.log(`[ci-agent-guardrails] ${findings.length} finding(s) written to ${outputFile}`);
}

if (require.main === module) {
  main();
}
