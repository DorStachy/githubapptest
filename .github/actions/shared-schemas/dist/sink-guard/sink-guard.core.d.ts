/**
 * Result of a Sink Guard scan on a single text field.
 */
export interface SinkGuardResult {
    sanitized: string;
    hadSecrets: boolean;
    matchedPatterns: string[];
    redactionCount: number;
}
/**
 * Result of scanning an entire object (multiple fields).
 */
export interface SinkGuardObjectResult {
    sanitized: Record<string, unknown>;
    totalRedactions: number;
    allMatchedPatterns: string[];
}
/**
 * Sink Guard Service - core secret detection and redaction engine.
 */
export interface SinkGuardLogger {
    onSecretsRedacted?: (redactionCount: number, matchedPatterns: string[]) => void;
    onMaxDepthReached?: (maxDepth: number) => void;
}
export declare class SinkGuardCore {
    private readonly logger;
    private readonly patterns;
    /** Maximum recursion depth for scanObject to prevent stack overflow. */
    private static readonly MAX_DEPTH;
    constructor(logger?: SinkGuardLogger);
    /**
     * Scan a single string value for secrets and redact any matches.
     */
    scanAndRedact(text: string | null | undefined): SinkGuardResult;
    /**
     * Scan all fields in an object recursively and redact secrets.
     * Returns the sanitized copy (does not mutate the original).
     */
    scanObject<T extends Record<string, unknown>>(obj: T): SinkGuardObjectResult;
    /**
     * Scan an array of strings for secrets. Returns sanitized array.
     */
    scanArray(arr: string[]): string[];
    /**
     * Quick check: does this text contain any secrets? (No redaction, just boolean)
     */
    containsSecrets(text: string): boolean;
    /**
     * Detect high-entropy strings that look like secrets/tokens but don't match known patterns.
     * Scans both quoted values and common secret assignment formats.
     */
    private redactHighEntropyStrings;
    /**
     * Quick check for high-entropy strings (no redaction).
     */
    private containsHighEntropyStrings;
}
