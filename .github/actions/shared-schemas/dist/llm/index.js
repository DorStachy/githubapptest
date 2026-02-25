"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SCAN_PROCESSOR_LLM_METADATA_KEYS = exports.LLM_PAYLOAD_ALLOWLIST = void 0;
exports.LLM_PAYLOAD_ALLOWLIST = Object.freeze({
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
exports.SCAN_PROCESSOR_LLM_METADATA_KEYS = Object.freeze({
    confidenceGate: 'llmConfidenceGate',
    includeSnippets: 'llmIncludeSnippets',
    provider: 'llmProvider',
    endpoint: 'llmEndpoint',
    model: 'llmModel',
    apiKey: 'llmApiKey',
});
