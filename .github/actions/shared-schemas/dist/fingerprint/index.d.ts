export interface PrimaryFingerprintInput {
    category: string;
    normalizedRuleCategory: string;
    filePath: string;
    startLine: number;
    endLine: number;
    contextHash?: string | null;
}
export interface ToolFingerprintInput {
    toolName: string;
    ruleId: string;
    filePath: string;
    startLine: number;
    endLine: number;
}
export declare function computePrimaryFingerprint(input: PrimaryFingerprintInput): string;
export declare function computeToolFingerprint(input: ToolFingerprintInput): string;
