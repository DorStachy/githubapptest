export declare const LLM_PAYLOAD_ALLOWLIST: Readonly<{
    payloadFields: readonly string[];
    findingFields: readonly string[];
}>;
export declare const SCAN_PROCESSOR_LLM_METADATA_KEYS: Readonly<{
    readonly confidenceGate: "llmConfidenceGate";
    readonly includeSnippets: "llmIncludeSnippets";
    readonly provider: "llmProvider";
    readonly endpoint: "llmEndpoint";
    readonly model: "llmModel";
    readonly apiKey: "llmApiKey";
}>;
export type ScanProcessorLlmMetadataKey = (typeof SCAN_PROCESSOR_LLM_METADATA_KEYS)[keyof typeof SCAN_PROCESSOR_LLM_METADATA_KEYS];
