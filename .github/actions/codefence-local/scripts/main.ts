import * as fs from 'fs';
import * as path from 'path';
import { execFileSync } from 'child_process';
import {
  EvidenceMode,
  ForkDetectionResult,
  LlmMode,
  NormalizedFinding,
  Verdict,
} from './types';
import {
  ensureDir,
  getBooleanInput,
  getInput,
  normalizeEvidenceMode,
  parseScannerList,
  safeNumber,
  severityToVerdict,
  writeJsonFile,
} from './utils';
import { normalizeSarifFile } from './normalize-sarif';
import { normalizeJsonFile } from './normalize-json';
import { applyEvidenceMode } from './apply-evidence-mode';
import { redactFindings } from './redact-secrets';
import { runSupplyChainHeuristics } from './supply-chain-heuristics';
import { writeForkSummary } from './fork-summary';
import { buildForkRelayArtifact } from './fork-artifact-emitter';
import { uploadResults } from './upload-results';
import { SignedClientConfig } from './http-client';

interface GithubEvent {
  installation?: { id?: number };
  pull_request?: {
    number?: number;
    base?: { sha?: string; ref?: string; repo?: { full_name?: string } };
    head?: { sha?: string; ref?: string; repo?: { full_name?: string; fork?: boolean } };
  };
}

const SCANNER_SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

const CVE_PATTERN = /CVE-\d{4}-\d+/gi;

function normalizeLlmMode(value: string | undefined): LlmMode {
  const normalized = (value || 'codefence').trim().toUpperCase();
  if (normalized === 'CODEFENCE') {
    return 'CODEFENCE';
  }
  if (normalized === 'BYO') {
    return 'BYO';
  }
  return 'OFF';
}

function normalizeLlmConfidenceGate(
  value: string | undefined,
): 'strict' | 'balanced' | 'off' {
  const normalized = (value || 'strict').trim().toLowerCase();
  if (normalized === 'balanced') {
    return 'balanced';
  }
  if (normalized === 'off') {
    return 'off';
  }
  return 'strict';
}

function loadGithubEvent(): GithubEvent {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath || !fs.existsSync(eventPath)) {
    return {};
  }

  return JSON.parse(fs.readFileSync(eventPath, 'utf8')) as GithubEvent;
}

function detectFork(event: GithubEvent, apiKey: string): ForkDetectionResult {
  const eventFork = Boolean(event.pull_request?.head?.repo?.fork);
  const headRepo = event.pull_request?.head?.repo?.full_name;
  const baseRepo = process.env.GITHUB_REPOSITORY;
  const repoMismatch = Boolean(headRepo && baseRepo && headRepo !== baseRepo);
  const fork = eventFork || repoMismatch;

  if (fork && !apiKey) {
    const strategy = getInput('fork-mode', 'summary-only') === 'artifact-relay'
      ? 'artifact-relay'
      : 'summary-only';
    return { fork, strategy };
  }

  return { fork, strategy: 'summary-only' };
}

function listResultFiles(resultsRawDir: string, ext: string): string[] {
  if (!fs.existsSync(resultsRawDir)) {
    return [];
  }

  return fs
    .readdirSync(resultsRawDir)
    .filter((name) => name.endsWith(ext))
    .map((name) => path.join(resultsRawDir, name));
}

function inferToolNameFromFileName(filePath: string): string {
  const fileName = path.basename(filePath).toLowerCase();
  const known = [
    'codeql',
    'semgrep',
    'bandit',
    'gitleaks',
    'osv-scanner',
    'pip-audit',
    'actionlint',
    'zizmor',
    'checkov',
    'trivy',
    'scorecard',
  ];

  for (const tool of known) {
    if (fileName.includes(tool)) {
      return tool;
    }
  }

  return fileName.replace(path.extname(fileName), '');
}

function extractCveIds(finding: NormalizedFinding): string[] {
  const ids = new Set<string>();
  const candidates = [finding.ruleId, ...(finding.references || [])];

  for (const candidate of candidates) {
    const text = String(candidate || '');
    const matches = text.match(CVE_PATTERN) || [];
    for (const match of matches) {
      ids.add(match.toUpperCase());
    }
  }

  return Array.from(ids);
}

function remediationRichness(finding: NormalizedFinding): number {
  const remediation = finding.remediationSummary || '';
  const description = finding.description || '';
  return remediation.length * 4 + description.length;
}

function mergeReferences(a: string[], b: string[]): string[] {
  return Array.from(new Set([...(a || []), ...(b || [])])).slice(0, 100);
}

function choosePreferredScaFinding(a: NormalizedFinding, b: NormalizedFinding): NormalizedFinding {
  const aRichness = remediationRichness(a);
  const bRichness = remediationRichness(b);
  if (aRichness !== bRichness) {
    return aRichness > bRichness ? a : b;
  }

  const aSeverity = SCANNER_SEVERITY_RANK[a.severity] || 0;
  const bSeverity = SCANNER_SEVERITY_RANK[b.severity] || 0;
  if (aSeverity !== bSeverity) {
    return aSeverity >= bSeverity ? a : b;
  }

  if (a.toolName === 'pip-audit' && b.toolName !== 'pip-audit') {
    return a;
  }
  if (b.toolName === 'pip-audit' && a.toolName !== 'pip-audit') {
    return b;
  }

  return a;
}

export function dedupePipAuditAndOsv(findings: NormalizedFinding[]): NormalizedFinding[] {
  const deduped: NormalizedFinding[] = [];
  const keyToIndex = new Map<string, number>();

  for (const finding of findings) {
    const tool = finding.toolName.toLowerCase();
    const isTargetScanner = tool === 'pip-audit' || tool === 'osv-scanner' || tool === 'osv';
    const cveIds = extractCveIds(finding);

    if (finding.category !== 'SCA' || !isTargetScanner || cveIds.length === 0) {
      deduped.push(finding);
      continue;
    }

    // Dedup key intentionally uses the first sorted CVE to avoid false merges across partially
    // overlapping multi-CVE findings; overlapping findings with different primary CVEs stay separate.
    const key = `${cveIds.sort()[0]}|${finding.filePath}`;
    const existingIndex = keyToIndex.get(key);

    if (existingIndex === undefined) {
      keyToIndex.set(key, deduped.length);
      deduped.push(finding);
      continue;
    }

    const existing = deduped[existingIndex];
    const preferred = choosePreferredScaFinding(existing, finding);
    const other = preferred === existing ? finding : existing;
    const existingMergedFrom = Array.isArray(preferred.metadata?.mergedFrom)
      ? (preferred.metadata?.mergedFrom as string[])
      : [];

    deduped[existingIndex] = {
      ...preferred,
      references: mergeReferences(preferred.references, other.references),
      metadata: {
        ...(preferred.metadata || {}),
        mergedFrom: Array.from(
          new Set([preferred.toolName, other.toolName, ...existingMergedFrom]),
        ),
      },
    };
  }

  return deduped;
}

function collectNormalizedFindings(workspace: string, resultsDir: string): NormalizedFinding[] {
  const rawDir = path.join(resultsDir, 'raw');
  const findings: NormalizedFinding[] = [];
  const repoRoot = process.env.GITHUB_WORKSPACE || workspace;

  for (const sarifPath of listResultFiles(rawDir, '.sarif')) {
    const tool = inferToolNameFromFileName(sarifPath);
    findings.push(...normalizeSarifFile(sarifPath, { toolNameOverride: tool, repoRoot }));
  }

  for (const jsonPath of listResultFiles(rawDir, '.json')) {
    if (jsonPath.endsWith('.status.json')) {
      continue;
    }

    const tool = inferToolNameFromFileName(jsonPath);
    findings.push(...normalizeJsonFile(jsonPath, { toolName: tool, repoRoot }));
  }

  const packageJsonPath = path.join(workspace, 'package.json');
  if (fs.existsSync(packageJsonPath)) {
    const heuristics = runSupplyChainHeuristics({
      workspaceRoot: workspace,
      manifestPath: 'package.json',
      baseManifestPath: fs.existsSync(path.join(workspace, '.codefence-base.package.json'))
        ? '.codefence-base.package.json'
        : undefined,
      baseLockfilePath: fs.existsSync(path.join(workspace, '.codefence-base.package-lock.json'))
        ? '.codefence-base.package-lock.json'
        : undefined,
      headLockfilePath: fs.existsSync(path.join(workspace, 'package-lock.json'))
        ? 'package-lock.json'
        : undefined,
      popularPackagesPath: 'configs/popular-packages.json',
      evidenceMode: normalizeEvidenceMode(getInput('evidence-mode', 'minimal')),
    });
    findings.push(...heuristics);
  }

  return dedupePipAuditAndOsv(findings);
}

function shouldFailBuild(verdict: Verdict, failOn: string, forkMode: boolean): boolean {
  if (forkMode) {
    return false;
  }

  const normalized = (failOn || 'fail').toLowerCase();
  if (normalized === 'never') {
    return false;
  }
  if (normalized === 'warn') {
    return verdict === 'FAIL' || verdict === 'WARN';
  }

  return verdict === 'FAIL';
}

function runScript(scriptPath: string, env: NodeJS.ProcessEnv): void {
  execFileSync('bash', [scriptPath], {
    env,
    stdio: 'inherit',
  });
}

function resolveActionRoot(): string {
  const candidates = [
    path.resolve(__dirname, '..'),
    path.resolve(__dirname, '..', '..'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(path.join(candidate, 'scripts', 'run-scanners.sh'))) {
      return candidate;
    }
  }

  return candidates[0];
}

function resolveSigningSecret(apiKey: string): string {
  const dedicated =
    process.env.CODEFENCE_SIGNING_SECRET || process.env.CODEFENCE_RESULTS_SIGNING_SECRET || '';
  if (dedicated.trim().length > 0) {
    return dedicated;
  }

  process.stdout.write(
    '::warning::CODEFENCE_SIGNING_SECRET is not set; falling back to api-key for HMAC signing. Configure a dedicated signing secret.\n',
  );
  return apiKey;
}

async function main(): Promise<void> {
  const startedAt = Date.now();
  const actionRoot = resolveActionRoot();
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const resultsDir = process.env.CODEFENCE_RESULTS_DIR || '/tmp/codefence-results';
  const rawDir = path.join(resultsDir, 'raw');

  ensureDir(resultsDir);
  ensureDir(rawDir);

  const apiKey = getInput('api-key', process.env.CODEFENCE_API_KEY || '');
  const evidenceMode: EvidenceMode = normalizeEvidenceMode(getInput('evidence-mode', 'minimal'));
  const egressMode = getInput('egress-mode', 'standard').toLowerCase();
  const scanners = parseScannerList(getInput('scanners', 'all'));
  const failOn = getInput('fail-on', 'fail');
  const llmMode = normalizeLlmMode(getInput('llm-mode', 'codefence'));
  const llmConfidenceGate = normalizeLlmConfidenceGate(
    getInput('llm-confidence-gate', 'strict'),
  );
  const llmIncludeSnippets = getBooleanInput('llm-include-snippets', false);
  const llmProvider = getInput('llm-provider', '').trim();
  const llmEndpoint = getInput('llm-endpoint', '').trim();
  const llmModel = getInput('llm-model', '').trim();

  const event = loadGithubEvent();
  const forkInfo = detectFork(event, apiKey);

  const sharedEnv: NodeJS.ProcessEnv = {
    ...process.env,
    CODEFENCE_RESULTS_DIR: resultsDir,
    CODEFENCE_SCANNERS: scanners.join(','),
    CODEFENCE_API_KEY: apiKey,
    EGRESS_MODE: egressMode,
    INPUT_EGRESS_MODE: egressMode,
    INPUT_STRICT_DNS_RESOLVERS: getInput('strict-dns-resolvers', ''),
    INPUT_CODEFENCE_API_URL: getInput('codefence-api-url', 'https://api.codefence.io'),
  };

  if (egressMode === 'strict') {
    runScript(path.join(actionRoot, 'scripts', 'egress-strict.sh'), sharedEnv);
  } else {
    runScript(path.join(actionRoot, 'scripts', 'validate-egress.sh'), sharedEnv);
  }

  runScript(path.join(actionRoot, 'scripts', 'run-scanners.sh'), sharedEnv);

  const findings = collectNormalizedFindings(workspace, resultsDir);
  const afterEvidence = applyEvidenceMode(findings, evidenceMode);
  const redacted = redactFindings(afterEvidence);

  const outputFindingsPath = path.join(resultsDir, 'normalized-findings.json');
  writeJsonFile(outputFindingsPath, redacted);

  const verdict = severityToVerdict(redacted);
  const scannersRun = scanners;
  const scanDurationMs = Date.now() - startedAt;

  if (forkInfo.fork && !apiKey) {
    writeForkSummary(redacted, { uploaded: false });

    if (forkInfo.strategy === 'artifact-relay') {
      const artifact = buildForkRelayArtifact({
        findings: redacted,
        repoFullName: process.env.GITHUB_REPOSITORY || event.pull_request?.base?.repo?.full_name || '',
        forkRepoFullName:
          event.pull_request?.head?.repo?.full_name || process.env.GITHUB_REPOSITORY || '',
        headSha: process.env.GITHUB_SHA || event.pull_request?.head?.sha || '',
        baseSha: process.env.GITHUB_BASE_SHA || event.pull_request?.base?.sha || '',
        prNumber: Number(event.pull_request?.number || 0),
        runId: Number(process.env.GITHUB_RUN_ID || 0),
        scannersRun,
        scanDurationMs,
      });

      const artifactPath = '/tmp/codefence-relay-artifact.json';
      writeJsonFile(artifactPath, artifact);
      process.stdout.write(`Fork relay artifact generated at ${artifactPath}\n`);
    }

    process.exit(0);
  }

  if (!apiKey) {
    writeForkSummary(redacted, { uploaded: false });
    process.stdout.write(
      '::notice::api-key input is empty on a non-fork event; backend upload is being skipped.\n',
    );
    process.stdout.write('No CODEFENCE_API_KEY provided. Skipping backend upload.\n');
    process.exit(shouldFailBuild(verdict, failOn, false) ? 1 : 0);
  }

  const signingSecret = resolveSigningSecret(apiKey);
  const config: SignedClientConfig = {
    apiBaseUrl: getInput('codefence-api-url', process.env.CODEFENCE_API_URL || 'https://api.codefence.io'),
    apiKey,
    signingSecret,
    keyVersion: safeNumber(
      process.env.CODEFENCE_KEY_VERSION || process.env.CODEFENCE_SIGNING_KEY_VERSION || 1,
      1,
    ),
  };

  const installationId =
    safeNumber(process.env.CODEFENCE_INSTALLATION_ID, 0) || safeNumber(event.installation?.id, 0);

  if (!installationId) {
    throw new Error(
      'Missing installation id. Set CODEFENCE_INSTALLATION_ID or provide GitHub App installation payload context.',
    );
  }

  // Resolve PR metadata from the event payload for action-mode linking
  const prNumber = event.pull_request?.number ?? undefined;
  const headRef = event.pull_request?.head?.ref ?? process.env.GITHUB_HEAD_REF ?? undefined;
  const baseRef = event.pull_request?.base?.ref ?? process.env.GITHUB_BASE_REF ?? undefined;

  const upload = await uploadResults(config, {
    installationId,
    repositoryFullName:
      process.env.GITHUB_REPOSITORY || event.pull_request?.base?.repo?.full_name || '',
    headSha: process.env.GITHUB_SHA || event.pull_request?.head?.sha || '',
    baseSha: process.env.GITHUB_BASE_SHA || event.pull_request?.base?.sha || null,
    evidenceMode,
    llmMode,
    scannersRun,
    workflowRunId: safeNumber(process.env.GITHUB_RUN_ID, 0) || undefined,
    clientCorrelationId:
      process.env.CODEFENCE_CLIENT_CORRELATION_ID ||
      `${process.env.GITHUB_RUN_ID || 'run'}:${process.env.GITHUB_RUN_ATTEMPT || '1'}`,
    findings: redacted,
    prNumber,
    headRef,
    baseRef,
    metadata: {
      scanDurationMs,
      triggerType:
        process.env.GITHUB_EVENT_NAME === 'push'
          ? 'push'
          : process.env.GITHUB_EVENT_NAME === 'schedule'
            ? 'scheduled'
            : 'pull_request',
      actionVersion: process.env.GITHUB_ACTION_REF,
      llmConfidenceGate,
      llmIncludeSnippets,
      llmProvider: llmProvider.length > 0 ? llmProvider : undefined,
      llmEndpoint: llmEndpoint.length > 0 ? llmEndpoint : undefined,
      llmModel: llmModel.length > 0 ? llmModel : undefined,
    },
  });

  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `scan-run-id=${upload.scanRunId}\n`, 'utf8');
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `verdict=${verdict}\n`, 'utf8');
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `findings-count=${redacted.length}\n`, 'utf8');
  }

  process.stdout.write(
    `CodeFence scan complete. verdict=${verdict} findings=${redacted.length} scanRunId=${upload.scanRunId}\n`,
  );

  process.exit(shouldFailBuild(verdict, failOn, false) ? 1 : 0);
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  });
}
