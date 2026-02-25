/**
 * Canonical contract types for the CodeFence scanner pipeline.
 *
 * These are the single source of truth for message shapes flowing between:
 *   Backend (dispatch) → Scanner Worker → Scan Processor
 *   Backend (results ingestion) → Scan Processor
 *
 * All consumers MUST import these types from @cera/shared-schemas.
 */
/** How the scan was triggered — server-side bot or customer-side action/workflow */
export type ScanRoute = 'BOT_SERVER' | 'CUSTOMER_LOCAL';
/** Compute lane the job runs in */
export type ScanLane = 'light' | 'heavy' | 'default' | 'codeql-heavy';
/** Source of a processor message */
export type ProcessorMessageSource = 'bot-scanner' | 'action-upload';
export type EvidenceMode = 'MINIMAL' | 'STANDARD' | 'RICH';
export type LlmMode = 'OFF' | 'CODEFENCE' | 'BYO';
export type ScanTriggerType = 'pull_request' | 'push' | 'check_suite' | 'scheduled';
export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingConfidence = 'HIGH' | 'MEDIUM' | 'LOW';
/** A single normalized security finding produced by any scanner tool. */
export interface NormalizedFinding {
    fingerprint: string;
    primaryFingerprint: string;
    toolFingerprint: string;
    category: string;
    severity: FindingSeverity;
    confidence: FindingConfidence;
    title: string;
    description?: string | null;
    filePath: string;
    startLine: number;
    endLine: number;
    snippet?: string | null;
    diffContext?: string | null;
    remediationSummary?: string | null;
    patchSuggestion?: string | null;
    ideFixPrompt?: string | null;
    references?: string[];
    toolName: string;
    toolVersion?: string | null;
    ruleId: string;
    normalizedRuleCategory: string;
    metadata?: Record<string, unknown>;
    isNew?: boolean;
    status?: string;
    suppressionId?: string | null;
    pathHash?: string | null;
    cliVerdict?: unknown;
}
/** Queue contract for bot dispatch → scanner worker. */
export interface ScannerJobMessage {
    scanRunId: string;
    installationId: number;
    orgId: string;
    repositoryFullName: string;
    triggerType: ScanTriggerType;
    prNumber: number | null;
    headSha: string;
    baseSha: string | null;
    headRef: string | null;
    baseRef: string | null;
    defaultBranch: string | null;
    evidenceMode: EvidenceMode;
    llmMode: LlmMode;
    metadata: Record<string, unknown>;
    queuedAt: string;
}
/** Queue contract for all messages arriving at the scan processor. */
export interface ScanProcessorMessage {
    scanRunId: string;
    installationId: number;
    orgId: string;
    repositoryFullName: string;
    headSha: string;
    baseSha?: string | null;
    evidenceMode: EvidenceMode;
    llmMode?: LlmMode;
    /** Discriminates how this message entered the pipeline */
    source?: ProcessorMessageSource;
    /** Which compute lane produced this message */
    lane?: ScanLane;
    metadata: Record<string, unknown>;
    rawFindings?: NormalizedFinding[];
    queuedAt: string;
}
