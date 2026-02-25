import {
  computePrimaryFingerprint,
  computeToolFingerprint,
} from '@cera/shared-schemas';

export type EvidenceMode = 'MINIMAL' | 'STANDARD' | 'RICH';
export type LlmMode = 'OFF' | 'CODEFENCE' | 'BYO';

export type FindingCategory =
  | 'SAST'
  | 'SCA'
  | 'SECRETS'
  | 'ACTIONS'
  | 'IAC'
  | 'CONTAINER'
  | 'POSTURE';

export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingConfidence = 'HIGH' | 'MEDIUM' | 'LOW';

export interface NormalizedFinding {
  id?: string;
  fingerprint: string;
  primaryFingerprint: string;
  toolFingerprint: string;
  category: FindingCategory;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  title: string;
  description?: string | null;
  filePath: string;
  pathHash?: string | null;
  startLine: number;
  endLine: number;
  snippet?: string | null;
  diffContext?: string | null;
  remediationSummary?: string | null;
  patchSuggestion?: string | null;
  ideFixPrompt?: string | null;
  references: string[];
  toolName: string;
  toolVersion?: string | null;
  ruleId: string;
  normalizedRuleCategory: string;
  cliVerdict?: Record<string, unknown> | null;
  metadata?: Record<string, unknown>;

  // Extra runner-only fields used for v2.2 stripping.
  sarifHelpText?: string | null;
  sarifCodeFlows?: unknown[] | null;
  sarifRelatedLocations?: unknown[] | null;
}

export interface RunnerMetadata {
  scannersRun: string[];
  scanDurationMs: number;
  workflowRunId?: number;
  triggerType?: 'pull_request' | 'push' | 'scheduled';
  actionVersion?: string;
  defaultBranch?: string | null;
  llmConfidenceGate?: 'strict' | 'balanced' | 'off';
  llmIncludeSnippets?: boolean;
  llmProvider?: string;
  llmEndpoint?: string;
  llmModel?: string;
}

export interface ScanRunRequest {
  clientCorrelationId?: string;
  installationId: number;
  repositoryFullName: string;
  triggerType: 'pull_request' | 'push' | 'scheduled';
  prNumber?: number | null;
  headSha: string;
  baseSha?: string | null;
  headRef?: string | null;
  baseRef?: string | null;
  evidenceMode: EvidenceMode;
  llmMode: LlmMode;
  scannersRun: string[];
  workflowRunId?: number;
}

export interface SubmitResultsRequest {
  scanRunId?: string;
  clientCorrelationId?: string;
  installationId: number;
  repositoryFullName: string;
  headSha: string;
  baseSha?: string | null;
  evidenceMode: EvidenceMode;
  llmMode?: LlmMode;
  findings: NormalizedFinding[];
  metadata: RunnerMetadata;
}

export interface SubmitChunkRequest {
  installationId?: number;
  repositoryFullName?: string;
  scanRunId: string;
  chunkIndex: number;
  totalChunks: number;
  idempotencyKey: string;
  findings: NormalizedFinding[];
}

export interface CompleteUploadRequest {
  installationId?: number;
  repositoryFullName?: string;
  scanRunId: string;
  totalChunks: number;
  metadata?: Pick<
    RunnerMetadata,
    | 'llmConfidenceGate'
    | 'llmIncludeSnippets'
    | 'llmProvider'
    | 'llmEndpoint'
    | 'llmModel'
  >;
}

export interface UploadResponse {
  status: 'accepted' | 'queued';
  scanRunId: string;
  findingsCount?: number;
}

export interface UploadAuthConfig {
  apiKey: string;
  signingSecret: string;
  keyVersion: number;
}

export interface UploadEndpointConfig {
  apiBaseUrl: string;
  timeoutMs?: number;
}

export type Verdict = 'PASS' | 'WARN' | 'FAIL';

export interface WorkspaceDescriptor {
  root: string;
  language: 'javascript' | 'python' | 'rust' | 'go';
  hasLockfile: boolean;
}

export interface ForkDetectionResult {
  fork: boolean;
  strategy: 'summary-only' | 'artifact-relay';
}

export interface ForkRelayArtifact {
  schemaVersion: 1;
  checksum: string;
  repoFullName: string;
  forkRepoFullName: string;
  headSha: string;
  baseSha: string;
  prNumber: number;
  runId: number;
  findings: NormalizedFinding[];
  verdict: Verdict;
  verdictReason: string;
  scannersRun: string[];
  scanDurationMs: number;
  evidenceMode: 'MINIMAL';
}

export const SEVERITY_RANK: Record<FindingSeverity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export function fingerprintForPrimary(
  category: FindingCategory,
  normalizedRuleCategory: string,
  filePath: string,
  startLine: number,
  endLine: number,
  contextHash = '',
): string {
  return computePrimaryFingerprint({
    category,
    normalizedRuleCategory,
    filePath,
    startLine,
    endLine,
    contextHash,
  });
}

export function fingerprintForTool(
  toolName: string,
  ruleId: string,
  filePath: string,
  startLine: number,
  endLine: number,
): string {
  return computeToolFingerprint({
    toolName,
    ruleId,
    filePath,
    startLine,
    endLine,
  });
}
