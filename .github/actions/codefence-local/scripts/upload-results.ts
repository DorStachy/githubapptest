import * as fs from 'fs';
import {
  EvidenceMode,
  LlmMode,
  NormalizedFinding,
  RunnerMetadata,
  ScanRunRequest,
  SubmitResultsRequest,
} from './types';
import { getInput, normalizeEvidenceMode, parseKeyValueArgs, safeNumber, isGitSha } from './utils';
import { SignedClientConfig, signedJsonRequest } from './http-client';
import { uploadResultsInChunks } from './chunked-upload';

const CHUNK_TRIGGER_FINDINGS = 2000;
const CHUNK_TRIGGER_BYTES = 2 * 1024 * 1024;

function normalizeLlmMode(value: string | undefined): LlmMode {
  const normalized = (value || 'codefence').toUpperCase();
  if (normalized === 'CODEFENCE') return 'CODEFENCE';
  if (normalized === 'BYO') return 'BYO';
  return 'OFF';
}

function normalizeTriggerType(value: string | undefined): 'pull_request' | 'push' | 'scheduled' {
  if (value === 'push' || value === 'scheduled') {
    return value;
  }
  return 'pull_request';
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

export interface UploadInputs {
  installationId: number;
  repositoryFullName: string;
  headSha: string;
  baseSha?: string | null;
  evidenceMode: EvidenceMode;
  llmMode: LlmMode;
  scannersRun: string[];
  workflowRunId?: number;
  clientCorrelationId?: string;
  findings: NormalizedFinding[];
  metadata?: Partial<RunnerMetadata>;
  /** PR number from event payload (fallback to PR_NUMBER env var) */
  prNumber?: number;
  /** Head branch ref from event payload (fallback to GITHUB_HEAD_REF env var) */
  headRef?: string;
  /** Base branch ref from event payload (fallback to GITHUB_BASE_REF env var) */
  baseRef?: string;
}

export async function createScanRun(
  config: SignedClientConfig,
  input: UploadInputs,
): Promise<string> {
  const payload: ScanRunRequest = {
    clientCorrelationId: input.clientCorrelationId,
    installationId: input.installationId,
    repositoryFullName: input.repositoryFullName,
    triggerType: normalizeTriggerType(process.env.GITHUB_EVENT_NAME),
    headSha: input.headSha,
    baseSha: input.baseSha ?? null,
    evidenceMode: input.evidenceMode,
    llmMode: input.llmMode,
    scannersRun: input.scannersRun,
    workflowRunId: input.workflowRunId,
    prNumber: input.prNumber ?? (safeNumber(process.env.PR_NUMBER || process.env.GITHUB_PR_NUMBER, 0) || undefined),
    headRef: input.headRef ?? (process.env.GITHUB_HEAD_REF || undefined),
    baseRef: input.baseRef ?? (process.env.GITHUB_BASE_REF || undefined),
  };

  const response = await signedJsonRequest<ScanRunRequest, { scanRunId: string }>(
    config,
    'POST',
    '/api/v1/github/scan-runs',
    payload,
  );

  if (response.status < 200 || response.status >= 300) {
    throw new Error(`Create scan run failed (${response.status}): ${JSON.stringify(response.body)}`);
  }

  const body = response.body as { scanRunId?: string };
  if (!body.scanRunId) {
    throw new Error('Create scan run response missing scanRunId');
  }

  return body.scanRunId;
}

function shouldChunkUpload(scanRunId: string, findings: NormalizedFinding[]): boolean {
  if (findings.length > CHUNK_TRIGGER_FINDINGS) {
    return true;
  }

  const sample = JSON.stringify({ scanRunId, findings });
  return Buffer.byteLength(sample, 'utf8') > CHUNK_TRIGGER_BYTES;
}

export async function uploadResults(
  config: SignedClientConfig,
  input: UploadInputs,
): Promise<{ scanRunId: string; chunked: boolean }> {
  if (!isGitSha(input.headSha)) {
    throw new Error(`headSha must be a valid SHA, got '${input.headSha}'`);
  }

  const scanRunId = await createScanRun(config, input);

  if (shouldChunkUpload(scanRunId, input.findings)) {
    await uploadResultsInChunks(config, {
      installationId: input.installationId,
      repositoryFullName: input.repositoryFullName,
      scanRunId,
      findings: input.findings,
      metadata: input.metadata,
    });
    return { scanRunId, chunked: true };
  }

  const payload: SubmitResultsRequest = {
    scanRunId,
    clientCorrelationId: input.clientCorrelationId,
    installationId: input.installationId,
    repositoryFullName: input.repositoryFullName,
    headSha: input.headSha,
    baseSha: input.baseSha ?? null,
    evidenceMode: input.evidenceMode,
    llmMode: input.llmMode,
    findings: input.findings,
    metadata: {
      scannersRun: input.scannersRun,
      scanDurationMs: input.metadata?.scanDurationMs || 0,
      workflowRunId: input.workflowRunId,
      triggerType: input.metadata?.triggerType || normalizeTriggerType(process.env.GITHUB_EVENT_NAME),
      actionVersion: input.metadata?.actionVersion || process.env.GITHUB_ACTION_REF,
      defaultBranch: input.metadata?.defaultBranch || process.env.GITHUB_DEFAULT_BRANCH || null,
      llmConfidenceGate: input.metadata?.llmConfidenceGate,
      llmIncludeSnippets: input.metadata?.llmIncludeSnippets,
      llmProvider: input.metadata?.llmProvider,
      llmEndpoint: input.metadata?.llmEndpoint,
      llmModel: input.metadata?.llmModel,
    },
  };

  const response = await signedJsonRequest(config, 'POST', '/api/v1/github/results', payload);
  if (response.status === 413) {
    process.stdout.write(
      '::notice::Results payload too large for single upload; retrying with chunked upload.\n',
    );
    await uploadResultsInChunks(config, {
      installationId: input.installationId,
      repositoryFullName: input.repositoryFullName,
      scanRunId,
      findings: input.findings,
      metadata: input.metadata,
    });
    return { scanRunId, chunked: true };
  }
  if (response.status >= 400) {
    throw new Error(`Results upload failed (${response.status}): ${JSON.stringify(response.body)}`);
  }

  return { scanRunId, chunked: false };
}

function runCli(): void {
  const args = parseKeyValueArgs(process.argv.slice(2));
  const findingsPath = args.findings;

  if (!findingsPath) {
    throw new Error('Usage: upload-results.ts --findings=<normalized-findings.json>');
  }

  const apiKey = getInput('api-key', process.env.CODEFENCE_API_KEY || '');
  if (!apiKey) {
    throw new Error('Missing CODEFENCE_API_KEY (or action input api-key).');
  }

  const signingSecret = resolveSigningSecret(apiKey);
  const keyVersion = safeNumber(process.env.CODEFENCE_KEY_VERSION || process.env.CODEFENCE_SIGNING_KEY_VERSION || 1, 1);

  const config: SignedClientConfig = {
    apiBaseUrl: getInput('codefence-api-url', process.env.CODEFENCE_API_URL || 'https://api.cera.buzz'),
    apiKey,
    signingSecret,
    keyVersion,
    timeoutMs: safeNumber(process.env.CODEFENCE_UPLOAD_TIMEOUT_MS || 20000, 20000),
  };

  const findings = JSON.parse(fs.readFileSync(findingsPath, 'utf8')) as NormalizedFinding[];
  const startTime = Date.now();

  uploadResults(config, {
    installationId: safeNumber(process.env.CODEFENCE_INSTALLATION_ID, 0),
    repositoryFullName: process.env.GITHUB_REPOSITORY || '',
    headSha: process.env.GITHUB_SHA || '',
    baseSha: process.env.GITHUB_BASE_SHA || null,
    evidenceMode: normalizeEvidenceMode(getInput('evidence-mode', 'minimal')),
    llmMode: normalizeLlmMode(getInput('llm-mode', 'codefence')),
    scannersRun: (process.env.CODEFENCE_SCANNERS_RUN || '').split(',').filter(Boolean),
    workflowRunId: safeNumber(process.env.GITHUB_RUN_ID, 0) || undefined,
    clientCorrelationId:
      process.env.CODEFENCE_CLIENT_CORRELATION_ID ||
      `${process.env.GITHUB_RUN_ID || 'run'}:${process.env.GITHUB_RUN_ATTEMPT || '1'}`,
    findings,
    metadata: {
      scanDurationMs: Date.now() - startTime,
      actionVersion: process.env.GITHUB_ACTION_REF,
    },
  })
    .then((result) => {
      if (process.env.GITHUB_OUTPUT) {
        fs.appendFileSync(process.env.GITHUB_OUTPUT, `scan-run-id=${result.scanRunId}\n`, 'utf8');
      }
      process.stdout.write(
        `Uploaded ${findings.length} findings (scanRunId=${result.scanRunId}, chunked=${result.chunked})\n`,
      );
    })
    .catch((error) => {
      process.stderr.write(`Upload failed: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exit(1);
    });
}

if (require.main === module) {
  runCli();
}
