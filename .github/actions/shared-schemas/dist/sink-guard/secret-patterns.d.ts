/**
 * Frozen secret pattern registry for Sink Guard.
 * 40+ compiled regexes covering AWS, GitHub, Google, Azure, Slack, Stripe, generic tokens, etc.
 * Object.freeze() ensures immutability after load.
 *
 * Each pattern has:
 *   - name: Human-readable label for audit/redaction logs
 *   - pattern: Compiled RegExp (global flag for scanning entire text)
 *   - severity: How critical the leak would be
 */
export interface SecretPattern {
    name: string;
    pattern: RegExp;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}
/**
 * Frozen, immutable pattern registry.
 * Use `SECRET_PATTERNS` throughout the application — never modify.
 */
export declare const SECRET_PATTERNS: readonly SecretPattern[];
/**
 * Shannon entropy calculation for detecting high-entropy strings
 * that may be secrets not matched by specific patterns.
 * Threshold: 4.5 bits/char for strings ≥ 20 chars.
 */
export declare function calculateEntropy(str: string): number;
export declare const HIGH_ENTROPY_THRESHOLD = 4.5;
export declare const HIGH_ENTROPY_MIN_LENGTH = 20;
