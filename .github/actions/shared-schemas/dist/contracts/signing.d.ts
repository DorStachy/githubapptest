/**
 * HMAC-SHA256 message signing and verification for SQS pipeline messages.
 *
 * Used to ensure message integrity between:
 *   - Backend dispatch → Scanner Worker
 *   - Scanner Worker → Scan Processor
 *   - Backend ingestion → Scan Processor
 *
 * Compatible with the existing SigningKeyService approach in the backend.
 */
/** SQS message attribute names for signature transport */
export declare const SIGNATURE_ATTRIBUTE = "X-CodeFence-Signature";
export declare const SIGNATURE_VERSION_ATTRIBUTE = "X-CodeFence-Key-Version";
/**
 * Sign an SQS message body with HMAC-SHA256.
 *
 * @param body  - The serialized JSON message body
 * @param key   - The signing key (Buffer)
 * @param version - The key version number
 * @returns The hex signature and key version
 */
export declare function signMessage(body: string, key: Buffer, version: number): {
    signature: string;
    version: number;
};
/**
 * Verify an HMAC-SHA256 signature on an SQS message body.
 * Uses constant-time comparison to prevent timing attacks.
 *
 * @param body      - The serialized JSON message body
 * @param signature - The hex signature to verify
 * @param key       - The signing key (Buffer)
 * @returns true if the signature is valid
 */
export declare function verifyMessage(body: string, signature: string, key: Buffer): boolean;
