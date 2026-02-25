import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  scanWorkspace,
  extractExpressions,
  isUntrustedExpression,
  isUserControllableExpression,
  parseWorkflow,
  extractTriggers,
  hasLowTrustTrigger,
  extractSecretReferences,
  collectJobSecrets,
  jobHasEnvironment,
  isPublishSecret,
  jobHasBroadPermissions,
  extractCacheUsages,
  extractArtifactUsages,
  cacheKeysOverlap,
  GuardrailFinding,
  CacheKeyUsage,
  ArtifactUsage,
} from '../scripts/scanners/ci-agent-guardrails';
import { normalizeJsonPayload } from '../scripts/normalize-json';

const FIXTURES_DIR = path.join(__dirname, 'fixtures', 'workflows');

// ── Helper ──────────────────────────────────────────────────────────────────

function setupWorkspace(workflowFiles: Record<string, string>): string {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardrails-test-'));
  const workflowDir = path.join(tmpDir, '.github', 'workflows');
  fs.mkdirSync(workflowDir, { recursive: true });

  for (const [name, content] of Object.entries(workflowFiles)) {
    fs.writeFileSync(path.join(workflowDir, name), content, 'utf8');
  }

  return tmpDir;
}

function loadFixture(name: string): string {
  return fs.readFileSync(path.join(FIXTURES_DIR, name), 'utf8');
}

// ── Expression extraction tests ─────────────────────────────────────────────

describe('extractExpressions', () => {
  it('extracts single expression', () => {
    const result = extractExpressions('echo ${{ github.sha }}');
    expect(result).toEqual(['github.sha']);
  });

  it('extracts multiple expressions', () => {
    const result = extractExpressions('${{ github.event.pull_request.title }} and ${{ github.sha }}');
    expect(result).toEqual(['github.event.pull_request.title', 'github.sha']);
  });

  it('returns empty for no expressions', () => {
    const result = extractExpressions('echo "hello world"');
    expect(result).toEqual([]);
  });

  it('handles whitespace in expressions', () => {
    const result = extractExpressions('${{  github.event.issue.body  }}');
    expect(result).toEqual(['github.event.issue.body']);
  });
});

// ── Untrusted expression detection ──────────────────────────────────────────

describe('isUntrustedExpression', () => {
  it('flags PR title', () => {
    expect(isUntrustedExpression('github.event.pull_request.title')).toBe(true);
  });

  it('flags PR body', () => {
    expect(isUntrustedExpression('github.event.pull_request.body')).toBe(true);
  });

  it('flags issue body', () => {
    expect(isUntrustedExpression('github.event.issue.body')).toBe(true);
  });

  it('flags comment body', () => {
    expect(isUntrustedExpression('github.event.comment.body')).toBe(true);
  });

  it('flags review body', () => {
    expect(isUntrustedExpression('github.event.review.body')).toBe(true);
  });

  it('flags head_commit message', () => {
    expect(isUntrustedExpression('github.event.head_commit.message')).toBe(true);
  });

  it('flags head_ref', () => {
    expect(isUntrustedExpression('github.head_ref')).toBe(true);
  });

  it('does NOT flag github.sha', () => {
    expect(isUntrustedExpression('github.sha')).toBe(false);
  });

  it('does NOT flag github.ref', () => {
    expect(isUntrustedExpression('github.ref')).toBe(false);
  });

  it('does NOT flag secrets', () => {
    expect(isUntrustedExpression('secrets.GITHUB_TOKEN')).toBe(false);
  });
});

// ── User-controllable expression detection ──────────────────────────────────

describe('isUserControllableExpression', () => {
  it('flags broader patterns like discussion.body', () => {
    expect(isUserControllableExpression('github.event.discussion.body')).toBe(true);
  });

  it('does NOT flag github.sha', () => {
    expect(isUserControllableExpression('github.sha')).toBe(false);
  });

  it('does NOT flag safe event fields', () => {
    expect(isUserControllableExpression('github.event.action')).toBe(false);
  });
});

// ── YAML parsing ────────────────────────────────────────────────────────────

describe('parseWorkflow', () => {
  it('parses valid workflow YAML', () => {
    const result = parseWorkflow('name: Test\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n');
    expect(result).toBeTruthy();
    expect(result!.jobs).toBeDefined();
    expect(result!.jobs!.build).toBeDefined();
  });

  it('returns null for invalid YAML', () => {
    const result = parseWorkflow('{{{{invalid');
    expect(result).toBeNull();
  });

  it('returns null for non-object YAML', () => {
    const result = parseWorkflow('hello');
    expect(result).toBeNull();
  });
});

// ── Full scanner integration with fixtures ──────────────────────────────────

describe('scanWorkspace', () => {
  describe('Rule 1: untrusted-input-in-run', () => {
    it('detects untrusted input in run: steps', () => {
      const workspace = setupWorkspace({
        'unsafe-run.yml': loadFixture('unsafe-run-injection.yml'),
      });

      const findings = scanWorkspace(workspace);
      const rule1 = findings.filter((f) => f.ruleId === 'ci-guardrails/untrusted-input-in-run');

      expect(rule1.length).toBeGreaterThanOrEqual(2);
      expect(rule1[0].severity).toBe('HIGH');
      expect(rule1[0].confidence).toBe('HIGH');
      expect(rule1[0].title).toContain('github.event.pull_request.title');

      fs.rmSync(workspace, { recursive: true, force: true });
    });
  });

  describe('Rule 2: untrusted-input-in-agent-prompt', () => {
    it('detects untrusted input passed to agent actions', () => {
      const workspace = setupWorkspace({
        'unsafe-agent.yml': loadFixture('unsafe-agent-prompt.yml'),
      });

      const findings = scanWorkspace(workspace);
      const rule2 = findings.filter((f) => f.ruleId === 'ci-guardrails/untrusted-input-in-agent-prompt');

      expect(rule2.length).toBeGreaterThanOrEqual(2);
      expect(rule2[0].severity).toBe('CRITICAL');
      expect(rule2[0].confidence).toBe('HIGH');
      expect(rule2.some((f) => f.title.includes('copilot-swe-agent'))).toBe(true);
      expect(rule2.some((f) => f.title.includes('claude-code-action'))).toBe(true);

      fs.rmSync(workspace, { recursive: true, force: true });
    });
  });

  describe('Rule 3: expression-in-run-step', () => {
    it('detects broader user-controllable expressions in run blocks', () => {
      const workspace = setupWorkspace({
        'unsafe-expr.yml': loadFixture('unsafe-expression-in-run.yml'),
      });

      const findings = scanWorkspace(workspace);
      // Rule 1 should catch head_commit.message and head_ref (they're in UNTRUSTED_CONTEXTS)
      const rule1 = findings.filter((f) => f.ruleId === 'ci-guardrails/untrusted-input-in-run');
      expect(rule1.length).toBeGreaterThanOrEqual(2);

      // Safe expressions (github.sha, github.ref) should NOT be flagged
      const allFindingsText = findings.map((f) => f.title).join(' ');
      expect(allFindingsText).not.toContain('github.sha');
      expect(allFindingsText).not.toContain('github.ref');

      fs.rmSync(workspace, { recursive: true, force: true });
    });
  });

  describe('safe workflows', () => {
    it('produces zero findings for safe workflow', () => {
      const workspace = setupWorkspace({
        'safe.yml': loadFixture('safe-workflow.yml'),
      });

      const findings = scanWorkspace(workspace);
      expect(findings).toHaveLength(0);

      fs.rmSync(workspace, { recursive: true, force: true });
    });
  });

  it('returns empty for workspace with no workflow directory', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardrails-empty-'));
    const findings = scanWorkspace(tmpDir);
    expect(findings).toHaveLength(0);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});

// ── Normalizer integration ──────────────────────────────────────────────────

describe('normalizeCiAgentGuardrails via normalizeJsonPayload', () => {
  it('normalizes scanner output to NormalizedFinding format', () => {
    const rawFindings: GuardrailFinding[] = [
      {
        ruleId: 'ci-guardrails/untrusted-input-in-run',
        severity: 'HIGH',
        confidence: 'HIGH',
        filePath: '.github/workflows/deploy.yml',
        startLine: 15,
        endLine: 15,
        title: 'Untrusted input ${{ github.event.pull_request.title }} used in run: step',
        description: 'The expression injects user-controllable content.',
        snippet: 'echo "${{ github.event.pull_request.title }}"',
        remediationSummary: 'Pass untrusted input via environment variable.',
        patchSuggestion: null,
        ideFixPrompt: null,
      },
    ];

    const normalized = normalizeJsonPayload(rawFindings, {
      toolName: 'ci-agent-guardrails',
      toolVersion: '1.0.0',
    });

    expect(normalized).toHaveLength(1);
    expect(normalized[0]).toMatchObject({
      category: 'ACTIONS',
      severity: 'HIGH',
      confidence: 'HIGH',
      toolName: 'ci-agent-guardrails',
      ruleId: 'ci-guardrails/untrusted-input-in-run',
      filePath: '.github/workflows/deploy.yml',
      startLine: 15,
    });
    expect(normalized[0].fingerprint).toBeTruthy();
    expect(normalized[0].primaryFingerprint).toBeTruthy();
    expect(normalized[0].toolFingerprint).toBeTruthy();
    expect(normalized[0].remediationSummary).toContain('environment variable');
  });

  it('handles empty array', () => {
    const normalized = normalizeJsonPayload([], { toolName: 'ci-agent-guardrails' });
    expect(normalized).toHaveLength(0);
  });

  it('normalizes CRITICAL agent prompt findings', () => {
    const rawFindings: GuardrailFinding[] = [
      {
        ruleId: 'ci-guardrails/untrusted-input-in-agent-prompt',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        filePath: '.github/workflows/ai-review.yml',
        startLine: 20,
        endLine: 20,
        title: 'Untrusted input passed to AI agent',
        description: 'Agent prompt injection risk.',
        snippet: 'prompt: ${{ github.event.comment.body }}',
        remediationSummary: 'Never pass untrusted user input to AI agents.',
        patchSuggestion: null,
        ideFixPrompt: null,
      },
    ];

    const normalized = normalizeJsonPayload(rawFindings, {
      toolName: 'ci-agent-guardrails',
    });

    expect(normalized).toHaveLength(1);
    expect(normalized[0].severity).toBe('CRITICAL');
    expect(normalized[0].category).toBe('ACTIONS');
    expect(normalized[0].normalizedRuleCategory).toBe('prompt-injection');
  });
});

// ── Step 7: Secrets segmentation helper tests ───────────────────────────────

describe('extractTriggers', () => {
  it('handles string trigger', () => {
    expect(extractTriggers('push')).toEqual(['push']);
  });

  it('handles array trigger', () => {
    expect(extractTriggers(['push', 'pull_request'])).toEqual(['push', 'pull_request']);
  });

  it('handles object trigger', () => {
    expect(extractTriggers({ push: { branches: ['main'] }, pull_request_target: {} })).toEqual([
      'push',
      'pull_request_target',
    ]);
  });

  it('handles null/undefined', () => {
    expect(extractTriggers(null)).toEqual([]);
    expect(extractTriggers(undefined)).toEqual([]);
  });
});

describe('hasLowTrustTrigger', () => {
  it('detects pull_request_target', () => {
    expect(hasLowTrustTrigger(['pull_request_target'])).toBe(true);
  });

  it('detects issue_comment', () => {
    expect(hasLowTrustTrigger(['issue_comment', 'push'])).toBe(true);
  });

  it('detects workflow_run', () => {
    expect(hasLowTrustTrigger(['workflow_run'])).toBe(true);
  });

  it('returns false for trusted triggers', () => {
    expect(hasLowTrustTrigger(['push', 'pull_request', 'schedule'])).toBe(false);
  });
});

describe('extractSecretReferences', () => {
  it('extracts secret names from expressions', () => {
    const result = extractSecretReferences('${{ secrets.NPM_TOKEN }} and ${{ secrets.AWS_KEY }}');
    expect(result).toEqual(['NPM_TOKEN', 'AWS_KEY']);
  });

  it('returns empty for no secrets', () => {
    expect(extractSecretReferences('echo hello')).toEqual([]);
  });

  it('extracts from env block value', () => {
    const result = extractSecretReferences('${{ secrets.DEPLOY_TOKEN }}');
    expect(result).toEqual(['DEPLOY_TOKEN']);
  });
});

describe('isPublishSecret', () => {
  it('flags NPM_TOKEN', () => {
    expect(isPublishSecret('NPM_TOKEN')).toBe(true);
  });

  it('flags PYPI_TOKEN', () => {
    expect(isPublishSecret('PYPI_TOKEN')).toBe(true);
  });

  it('flags deploy keys', () => {
    expect(isPublishSecret('AWS_DEPLOY_KEY')).toBe(true);
    expect(isPublishSecret('DEPLOY_TOKEN')).toBe(true);
  });

  it('flags publish keys', () => {
    expect(isPublishSecret('PUBLISH_KEY')).toBe(true);
  });

  it('does NOT flag GITHUB_TOKEN', () => {
    expect(isPublishSecret('GITHUB_TOKEN')).toBe(false);
  });

  it('does NOT flag generic non-deploy secrets', () => {
    expect(isPublishSecret('SLACK_WEBHOOK')).toBe(false);
  });
});

describe('jobHasBroadPermissions', () => {
  it('detects write-all string', () => {
    expect(jobHasBroadPermissions({ permissions: 'write-all' } as any)).toBe(true);
  });

  it('detects 3+ write scopes', () => {
    expect(
      jobHasBroadPermissions({
        permissions: { contents: 'write', packages: 'write', issues: 'write' },
      } as any),
    ).toBe(true);
  });

  it('does NOT flag minimal permissions', () => {
    expect(
      jobHasBroadPermissions({
        permissions: { contents: 'read', packages: 'write' },
      } as any),
    ).toBe(false);
  });

  it('does NOT flag undefined permissions', () => {
    expect(jobHasBroadPermissions({} as any)).toBe(false);
  });
});

// ── Step 7: Full scanner integration with fixtures ──────────────────────────

describe('scanWorkspace — secrets segmentation (Step 7)', () => {
  describe('Rule 4: secrets-in-low-trust-trigger', () => {
    it('detects secrets in low-trust trigger without environment', () => {
      const workspace = setupWorkspace({
        'unsafe.yml': loadFixture('unsafe-secrets-low-trust.yml'),
      });

      const findings = scanWorkspace(workspace);
      const rule4 = findings.filter(
        (f) => f.ruleId === 'ci-guardrails/secrets-in-low-trust-trigger',
      );

      expect(rule4.length).toBeGreaterThanOrEqual(1);
      expect(rule4[0].severity).toBe('HIGH');
      expect(rule4[0].confidence).toBe('HIGH');
      expect(rule4[0].description).toContain('pull_request_target');
      expect(rule4[0].remediationSummary).toContain('environment');

      fs.rmSync(workspace, { recursive: true, force: true });
    });
  });

  describe('Rule 5: publish-secret-without-environment', () => {
    it('detects publish secrets without environment gating', () => {
      const workspace = setupWorkspace({
        'unsafe.yml': loadFixture('unsafe-publish-no-env.yml'),
      });

      const findings = scanWorkspace(workspace);
      const rule5 = findings.filter(
        (f) => f.ruleId === 'ci-guardrails/publish-secret-without-environment',
      );

      // 3 jobs, all without environment, all with publish secrets
      expect(rule5.length).toBe(3);
      expect(rule5[0].severity).toBe('MEDIUM');
      expect(rule5[0].confidence).toBe('MEDIUM');
      expect(rule5[0].remediationSummary).toContain('environment');

      fs.rmSync(workspace, { recursive: true, force: true });
    });
  });

  describe('Rule 6: broad-permissions-with-secrets', () => {
    it('detects broad permissions combined with secret access', () => {
      const workspace = setupWorkspace({
        'unsafe.yml': loadFixture('unsafe-broad-permissions.yml'),
      });

      const findings = scanWorkspace(workspace);
      const rule6 = findings.filter(
        (f) => f.ruleId === 'ci-guardrails/broad-permissions-with-secrets',
      );

      expect(rule6.length).toBeGreaterThanOrEqual(2);
      expect(rule6[0].severity).toBe('HIGH');
      expect(rule6[0].confidence).toBe('MEDIUM');
      expect(rule6[0].remediationSummary).toContain('least-privilege');

      fs.rmSync(workspace, { recursive: true, force: true });
    });
  });

  describe('safe workflows (Step 7)', () => {
    it('produces zero secrets findings for properly gated workflow', () => {
      const workspace = setupWorkspace({
        'safe.yml': loadFixture('safe-secrets-with-environment.yml'),
      });

      const findings = scanWorkspace(workspace);
      const secretFindings = findings.filter((f) =>
        ['ci-guardrails/secrets-in-low-trust-trigger',
         'ci-guardrails/publish-secret-without-environment',
         'ci-guardrails/broad-permissions-with-secrets'].includes(f.ruleId),
      );

      expect(secretFindings).toHaveLength(0);

      fs.rmSync(workspace, { recursive: true, force: true });
    });
  });
});

// ── Step 7: Normalizer integration ──────────────────────────────────────────

describe('normalizeCiAgentGuardrails — secrets rules', () => {
  it('normalizes secrets-in-low-trust-trigger finding', () => {
    const finding: GuardrailFinding = {
      ruleId: 'ci-guardrails/secrets-in-low-trust-trigger',
      severity: 'HIGH',
      confidence: 'HIGH',
      filePath: '.github/workflows/pr-handler.yml',
      startLine: 10,
      endLine: 10,
      title: 'Secrets in low-trust trigger',
      description: 'Job accesses secrets without environment.',
      snippet: 'secrets: AWS_KEY',
      remediationSummary: 'Add environment block.',
      patchSuggestion: null,
      ideFixPrompt: null,
    };

    const normalized = normalizeJsonPayload([finding], {
      toolName: 'ci-agent-guardrails',
    });

    expect(normalized).toHaveLength(1);
    expect(normalized[0]).toMatchObject({
      category: 'ACTIONS',
      severity: 'HIGH',
      ruleId: 'ci-guardrails/secrets-in-low-trust-trigger',
      normalizedRuleCategory: 'secrets-segmentation',
    });
  });

  it('normalizes broad-permissions-with-secrets finding', () => {
    const finding: GuardrailFinding = {
      ruleId: 'ci-guardrails/broad-permissions-with-secrets',
      severity: 'HIGH',
      confidence: 'MEDIUM',
      filePath: '.github/workflows/deploy.yml',
      startLine: 5,
      endLine: 5,
      title: 'Broad permissions with secrets',
      description: 'Overprivileged job.',
      snippet: 'permissions: write-all',
      remediationSummary: 'Apply least-privilege.',
      patchSuggestion: null,
      ideFixPrompt: null,
    };

    const normalized = normalizeJsonPayload([finding], {
      toolName: 'ci-agent-guardrails',
    });

    expect(normalized).toHaveLength(1);
    expect(normalized[0].normalizedRuleCategory).toBe('excessive-permissions');
  });
});

// ── Step 8: Cache/Artifact isolation helper tests ───────────────────────────

describe('cacheKeysOverlap', () => {
  it('detects exact match', () => {
    expect(cacheKeysOverlap('deps-abc', 'deps-abc')).toBe(true);
  });

  it('detects prefix overlap', () => {
    expect(cacheKeysOverlap('deps-', 'deps-abc')).toBe(true);
  });

  it('detects overlap with expression stripped', () => {
    const key1 = 'deps-${{ hashFiles("**/lock") }}';
    const key2 = 'deps-${{ hashFiles("**/lock") }}';
    expect(cacheKeysOverlap(key1, key2)).toBe(true);
  });

  it('detects static prefix overlap across expressions', () => {
    const key1 = 'deps-${{ hashFiles("a") }}';
    const key2 = 'deps-${{ hashFiles("b") }}';
    // Static prefixes are both "deps-" which overlap
    expect(cacheKeysOverlap(key1, key2)).toBe(true);
  });

  it('returns false for event-scoped keys (github.event_name)', () => {
    const key1 = '${{ github.event_name }}-deps-${{ hashFiles("a") }}';
    const key2 = '${{ github.event_name }}-deps-${{ hashFiles("b") }}';
    // event_name resolves differently per trigger → no overlap
    expect(cacheKeysOverlap(key1, key2)).toBe(false);
  });

  it('returns false for non-overlapping keys', () => {
    expect(cacheKeysOverlap('pr-deps-abc', 'push-deps-abc')).toBe(false);
  });

  it('returns false when static portions are empty', () => {
    expect(cacheKeysOverlap('${{ github.sha }}', '${{ github.ref }}')).toBe(false);
  });
});

describe('extractCacheUsages', () => {
  it('extracts cache key from actions/cache step', () => {
    const content = `
name: Build
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v3
        with:
          path: node_modules
          key: deps-abc
          restore-keys: |
            deps-
`;
    const workflow = parseWorkflow(content)!;
    const usages = extractCacheUsages(workflow, content, '.github/workflows/build.yml');

    expect(usages).toHaveLength(1);
    expect(usages[0].key).toBe('deps-abc');
    expect(usages[0].restoreKeys).toEqual(['deps-']);
    expect(usages[0].jobName).toBe('build');
    expect(usages[0].isLowTrust).toBe(false);
  });

  it('marks PR workflows as low-trust', () => {
    const content = `
name: PR Build
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v3
        with:
          path: node_modules
          key: deps-lock
`;
    const workflow = parseWorkflow(content)!;
    const usages = extractCacheUsages(workflow, content, '.github/workflows/pr.yml');

    expect(usages).toHaveLength(1);
    expect(usages[0].isLowTrust).toBe(true);
  });

  it('returns empty for workflows without cache steps', () => {
    const content = `
name: Simple
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`;
    const workflow = parseWorkflow(content)!;
    const usages = extractCacheUsages(workflow, content, '.github/workflows/simple.yml');
    expect(usages).toHaveLength(0);
  });
});

describe('extractArtifactUsages', () => {
  it('extracts upload-artifact usage', () => {
    const content = `
name: Build
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v4
        with:
          name: build-output
          path: dist/
`;
    const workflow = parseWorkflow(content)!;
    const usages = extractArtifactUsages(workflow, content, '.github/workflows/build.yml');

    expect(usages).toHaveLength(1);
    expect(usages[0].name).toBe('build-output');
    expect(usages[0].type).toBe('upload');
    expect(usages[0].isLowTrust).toBe(true);
  });

  it('extracts download-artifact usage', () => {
    const content = `
name: Deploy
on:
  workflow_run:
    workflows: ["Build"]
    types: [completed]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: build-output
          path: dist/
`;
    const workflow = parseWorkflow(content)!;
    const usages = extractArtifactUsages(workflow, content, '.github/workflows/deploy.yml');

    expect(usages).toHaveLength(1);
    expect(usages[0].name).toBe('build-output');
    expect(usages[0].type).toBe('download');
    expect(usages[0].triggers).toContain('workflow_run');
  });

  it('returns empty for workflows without artifact steps', () => {
    const content = `
name: Simple
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`;
    const workflow = parseWorkflow(content)!;
    const usages = extractArtifactUsages(workflow, content, '.github/workflows/simple.yml');
    expect(usages).toHaveLength(0);
  });
});

// ── Step 8: Cross-workflow scanner integration tests ────────────────────────

describe('scanWorkspace — cache/artifact isolation (Step 8)', () => {
  describe('Rule 7: cache-poisoning-risk', () => {
    it('detects shared cache keys between low-trust and high-trust workflows', () => {
      const workspace = setupWorkspace({
        'pr-build.yml': loadFixture('unsafe-cache-pr-writer.yml'),
        'push-deploy.yml': loadFixture('unsafe-cache-push-reader.yml'),
      });

      const findings = scanWorkspace(workspace);
      const rule7 = findings.filter(
        (f) => f.ruleId === 'ci-guardrails/cache-poisoning-risk',
      );

      expect(rule7.length).toBeGreaterThanOrEqual(1);
      expect(rule7[0].severity).toBe('HIGH');
      expect(rule7[0].confidence).toBe('MEDIUM');
      expect(rule7[0].description).toContain('pull_request');
      expect(rule7[0].description).toContain('push');
      expect(rule7[0].remediationSummary).toContain('github.event_name');

      fs.rmSync(workspace, { recursive: true, force: true });
    });

    it('does NOT flag when cache keys are event-scoped', () => {
      const workspace = setupWorkspace({
        'pr-build.yml': loadFixture('safe-cache-scoped.yml'),
        'push-deploy.yml': loadFixture('safe-cache-push-scoped.yml'),
      });

      const findings = scanWorkspace(workspace);
      const rule7 = findings.filter(
        (f) => f.ruleId === 'ci-guardrails/cache-poisoning-risk',
      );

      expect(rule7).toHaveLength(0);

      fs.rmSync(workspace, { recursive: true, force: true });
    });

    it('does NOT flag single-workflow cache usage', () => {
      const workspace = setupWorkspace({
        'pr-build.yml': loadFixture('unsafe-cache-pr-writer.yml'),
      });

      const findings = scanWorkspace(workspace);
      const rule7 = findings.filter(
        (f) => f.ruleId === 'ci-guardrails/cache-poisoning-risk',
      );

      expect(rule7).toHaveLength(0);

      fs.rmSync(workspace, { recursive: true, force: true });
    });
  });

  describe('Rule 8: artifact-injection-risk', () => {
    it('detects cross-boundary artifact sharing without integrity check', () => {
      const workspace = setupWorkspace({
        'pr-build.yml': loadFixture('unsafe-artifact-uploader.yml'),
        'deploy.yml': loadFixture('unsafe-artifact-downloader.yml'),
      });

      const findings = scanWorkspace(workspace);
      const rule8 = findings.filter(
        (f) => f.ruleId === 'ci-guardrails/artifact-injection-risk',
      );

      expect(rule8.length).toBeGreaterThanOrEqual(1);
      expect(rule8[0].severity).toBe('HIGH');
      expect(rule8[0].confidence).toBe('MEDIUM');
      expect(rule8[0].title).toContain('build-output');
      expect(rule8[0].description).toContain('workflow_run');
      expect(rule8[0].remediationSummary).toContain('SHA-256');

      fs.rmSync(workspace, { recursive: true, force: true });
    });

    it('does NOT flag artifact download with integrity verification', () => {
      const workspace = setupWorkspace({
        'pr-build.yml': loadFixture('unsafe-artifact-uploader.yml'),
        'deploy.yml': loadFixture('safe-artifact-with-integrity.yml'),
      });

      const findings = scanWorkspace(workspace);
      const rule8 = findings.filter(
        (f) => f.ruleId === 'ci-guardrails/artifact-injection-risk',
      );

      expect(rule8).toHaveLength(0);

      fs.rmSync(workspace, { recursive: true, force: true });
    });

    it('does NOT flag non-workflow_run artifact downloads', () => {
      // If both workflows are push-triggered, no workflow_run boundary
      const workspace = setupWorkspace({
        'build.yml': loadFixture('unsafe-artifact-uploader.yml'),
      });

      const findings = scanWorkspace(workspace);
      const rule8 = findings.filter(
        (f) => f.ruleId === 'ci-guardrails/artifact-injection-risk',
      );

      expect(rule8).toHaveLength(0);

      fs.rmSync(workspace, { recursive: true, force: true });
    });
  });

  describe('Rule 9: writable-cache-from-pr', () => {
    it('detects PR workflow cache keys readable by push workflow', () => {
      const workspace = setupWorkspace({
        'pr-build.yml': loadFixture('unsafe-cache-pr-writer.yml'),
        'push-deploy.yml': loadFixture('unsafe-cache-push-reader.yml'),
      });

      const findings = scanWorkspace(workspace);
      const rule9 = findings.filter(
        (f) => f.ruleId === 'ci-guardrails/writable-cache-from-pr',
      );

      expect(rule9.length).toBeGreaterThanOrEqual(1);
      expect(rule9[0].severity).toBe('MEDIUM');
      expect(rule9[0].confidence).toBe('MEDIUM');
      expect(rule9[0].filePath).toContain('pr-build');
      expect(rule9[0].remediationSummary).toContain('actions/cache/restore');

      fs.rmSync(workspace, { recursive: true, force: true });
    });

    it('does NOT flag when cache keys are event-scoped', () => {
      const workspace = setupWorkspace({
        'pr-build.yml': loadFixture('safe-cache-scoped.yml'),
        'push-deploy.yml': loadFixture('safe-cache-push-scoped.yml'),
      });

      const findings = scanWorkspace(workspace);
      const rule9 = findings.filter(
        (f) => f.ruleId === 'ci-guardrails/writable-cache-from-pr',
      );

      expect(rule9).toHaveLength(0);

      fs.rmSync(workspace, { recursive: true, force: true });
    });
  });

  describe('mixed patterns', () => {
    it('detects both cache and artifact issues in a combined workspace', () => {
      const workspace = setupWorkspace({
        'pr-build.yml': loadFixture('unsafe-cache-pr-writer.yml'),
        'push-deploy.yml': loadFixture('unsafe-cache-push-reader.yml'),
        'pr-artifact.yml': loadFixture('unsafe-artifact-uploader.yml'),
        'artifact-deploy.yml': loadFixture('unsafe-artifact-downloader.yml'),
      });

      const findings = scanWorkspace(workspace);
      const cacheFindings = findings.filter(
        (f) => f.ruleId === 'ci-guardrails/cache-poisoning-risk' ||
               f.ruleId === 'ci-guardrails/writable-cache-from-pr',
      );
      const artifactFindings = findings.filter(
        (f) => f.ruleId === 'ci-guardrails/artifact-injection-risk',
      );

      expect(cacheFindings.length).toBeGreaterThanOrEqual(1);
      expect(artifactFindings.length).toBeGreaterThanOrEqual(1);

      fs.rmSync(workspace, { recursive: true, force: true });
    });
  });

  describe('safe workflows (Step 8)', () => {
    it('produces zero cache/artifact findings for safe workflows', () => {
      const workspace = setupWorkspace({
        'safe.yml': loadFixture('safe-workflow.yml'),
      });

      const findings = scanWorkspace(workspace);
      const step8Findings = findings.filter((f) =>
        ['ci-guardrails/cache-poisoning-risk',
         'ci-guardrails/artifact-injection-risk',
         'ci-guardrails/writable-cache-from-pr'].includes(f.ruleId),
      );

      expect(step8Findings).toHaveLength(0);

      fs.rmSync(workspace, { recursive: true, force: true });
    });
  });
});

// ── Step 8: Normalizer integration ──────────────────────────────────────────

describe('normalizeCiAgentGuardrails — cache/artifact rules', () => {
  it('normalizes cache-poisoning-risk finding', () => {
    const finding: GuardrailFinding = {
      ruleId: 'ci-guardrails/cache-poisoning-risk',
      severity: 'HIGH',
      confidence: 'MEDIUM',
      filePath: '.github/workflows/pr-build.yml',
      startLine: 12,
      endLine: 12,
      title: 'Cache key shared between low-trust and high-trust workflows',
      description: 'Shared cache key enables poisoning.',
      snippet: 'key: deps-abc',
      remediationSummary: 'Scope cache keys by event type.',
      patchSuggestion: '-  key: deps-${{ hashFiles(...) }}\n+  key: pr-deps-${{ hashFiles(...) }}',
      ideFixPrompt: 'Add event-type prefix to cache key.',
    };

    const normalized = normalizeJsonPayload([finding], {
      toolName: 'ci-agent-guardrails',
    });

    expect(normalized).toHaveLength(1);
    expect(normalized[0]).toMatchObject({
      category: 'ACTIONS',
      severity: 'HIGH',
      ruleId: 'ci-guardrails/cache-poisoning-risk',
      normalizedRuleCategory: 'cache-artifact-isolation',
      patchSuggestion: expect.any(String),
      ideFixPrompt: expect.any(String),
    });
  });

  it('normalizes artifact-injection-risk finding', () => {
    const finding: GuardrailFinding = {
      ruleId: 'ci-guardrails/artifact-injection-risk',
      severity: 'HIGH',
      confidence: 'MEDIUM',
      filePath: '.github/workflows/deploy.yml',
      startLine: 10,
      endLine: 10,
      title: 'Artifact downloaded across workflow_run boundary',
      description: 'No integrity check.',
      snippet: 'download-artifact: build-output',
      remediationSummary: 'Add SHA-256 verification.',
      patchSuggestion: '+  - name: Verify artifact\n+    run: sha256sum --check artifact.sha256',
      ideFixPrompt: 'Add SHA-256 verification step after download-artifact.',
    };

    const normalized = normalizeJsonPayload([finding], {
      toolName: 'ci-agent-guardrails',
    });

    expect(normalized).toHaveLength(1);
    expect(normalized[0].normalizedRuleCategory).toBe('cache-artifact-isolation');
  });

  it('normalizes writable-cache-from-pr finding', () => {
    const finding: GuardrailFinding = {
      ruleId: 'ci-guardrails/writable-cache-from-pr',
      severity: 'MEDIUM',
      confidence: 'MEDIUM',
      filePath: '.github/workflows/pr.yml',
      startLine: 15,
      endLine: 15,
      title: 'PR workflow writes cache key readable by push workflow',
      description: 'Cache poisoning vector.',
      snippet: 'key: deps-lock',
      remediationSummary: 'Scope cache keys.',
      patchSuggestion: '-  key: deps-lock\n+  key: pr-deps-lock',
      ideFixPrompt: 'Add event-specific prefix to cache key to isolate PR cache writes.',
    };

    const normalized = normalizeJsonPayload([finding], {
      toolName: 'ci-agent-guardrails',
    });

    expect(normalized).toHaveLength(1);
    expect(normalized[0].normalizedRuleCategory).toBe('cache-artifact-isolation');
  });
});

// ── Step 9: Fix-diff guidance ───────────────────────────────────────────────

describe('scanWorkspace — patchSuggestion & ideFixPrompt', () => {
  it('emits patchSuggestion and ideFixPrompt for every finding', () => {
    const workspace = setupWorkspace({
      'inject.yml': `
name: inject
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo \${{ github.event.pull_request.title }}
`,
    });

    const findings = scanWorkspace(workspace);
    expect(findings.length).toBeGreaterThan(0);

    for (const f of findings) {
      expect(f.patchSuggestion).not.toBeNull();
      expect(typeof f.patchSuggestion).toBe('string');
      expect(f.ideFixPrompt).not.toBeNull();
      expect(typeof f.ideFixPrompt).toBe('string');
      expect(f.ideFixPrompt!.length).toBeGreaterThan(5);
    }

    fs.rmSync(workspace, { recursive: true, force: true });
  });

  it('normalizer passes through patchSuggestion and ideFixPrompt', () => {
    const finding: GuardrailFinding = {
      ruleId: 'ci-guardrails/untrusted-input-in-run',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      filePath: '.github/workflows/ci.yml',
      startLine: 5,
      endLine: 5,
      title: 'Untrusted expression in run step',
      description: 'Expression injected directly into shell.',
      snippet: 'run: echo ${{ github.event.pull_request.title }}',
      remediationSummary: 'Use env var.',
      patchSuggestion: '-  run: echo ${{ github.event.pull_request.title }}\n+  env:\n+    TITLE: ${{ github.event.pull_request.title }}\n+  run: echo "$TITLE"',
      ideFixPrompt: 'Extract the expression into an env block and reference $TITLE in the run step.',
    };

    const normalized = normalizeJsonPayload([finding], {
      toolName: 'ci-agent-guardrails',
    });

    expect(normalized).toHaveLength(1);
    expect(normalized[0].patchSuggestion).toBe(finding.patchSuggestion);
    expect(normalized[0].ideFixPrompt).toBe(finding.ideFixPrompt);
  });
});
