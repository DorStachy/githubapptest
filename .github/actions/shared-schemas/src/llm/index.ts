export const LLM_PAYLOAD_ALLOWLIST = Object.freeze({
  payloadFields: Object.freeze(['findings', 'repository', 'prNumber', 'mode']),
  findingFields: Object.freeze([
    'title',
    'severity',
    'confidence',
    'category',
    'ruleId',
    'normalizedRuleCategory',
    'filePath',
    'startLine',
    'endLine',
    'description',
    'remediationSummary',
    'references',
    'redactedSnippet',
    'diffContext',
    'patchSuggestion',
  ]),
});

export const SCAN_PROCESSOR_LLM_METADATA_KEYS = Object.freeze({
  confidenceGate: 'llmConfidenceGate',
  includeSnippets: 'llmIncludeSnippets',
  provider: 'llmProvider',
  endpoint: 'llmEndpoint',
  model: 'llmModel',
  apiKey: 'llmApiKey',
} as const);

export type ScanProcessorLlmMetadataKey =
  (typeof SCAN_PROCESSOR_LLM_METADATA_KEYS)[keyof typeof SCAN_PROCESSOR_LLM_METADATA_KEYS];
